from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from datetime import datetime, timedelta
from typing import Optional, List
import jwt
from jwt.exceptions import PyJWTError
import bcrypt
import sqlite3
import logging
from contextlib import contextmanager
from datetime import timezone

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Initialize FastAPI app
app = FastAPI(title="Productivity Dashboard API")

# Configuration
SECRET_KEY = "secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

security = HTTPBearer()

# Database setup
DB_NAME = "productivity.db"

@contextmanager
def get_db():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        c = conn.cursor()
        # Users table
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        
        # Tasks table
        c.execute('''
            CREATE TABLE IF NOT EXISTS tasks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                priority TEXT CHECK(priority IN ('Low', 'Medium', 'High')),
                status TEXT CHECK(status IN ('Pending', 'In Progress', 'Completed')),
                deadline TIMESTAMP,
                tags TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        ''')
        conn.commit()
        logger.info("Database initialized successfully")

# Pydantic models
class UserRegister(BaseModel):
    email: EmailStr
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

class TaskCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "Medium"
    status: str = "Pending"
    deadline: Optional[datetime] = None
    tags: Optional[str] = None

    model_config = {
        "json_schema_extra": {
            "example": {
                "title": "Finish GDG assignment",
                "description": "Complete the FastAPI backend",
                "priority": "High",
                "status": "Pending",
                "deadline": "2026-02-20T10:00:00Z",
                "tags": "college,backend"
            }
        }
    }

class TaskUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[str] = None
    status: Optional[str] = None
    deadline: Optional[datetime] = None
    tags: Optional[str] = None

class TaskResponse(BaseModel):
    id: int
    user_id: int
    title: str
    description: Optional[str]
    priority: str
    status: str
    deadline: Optional[datetime]
    tags: Optional[str]
    is_overdue: bool
    created_at: datetime
    updated_at: datetime

# Helper functions
def create_access_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        token = credentials.credentials
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = payload.get("user_id")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Invalid token")
        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except PyJWTError:
        raise HTTPException(status_code=401, detail="Invalid token")


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def is_task_overdue(deadline: Optional[datetime], status: str) -> bool:
    if deadline and status != "Completed":
        return datetime.now(timezone.utc) > deadline
    return False


# API Endpoints

@app.on_event("startup")
async def startup():
    init_db()

@app.post("/api/register", response_model=Token, status_code=status.HTTP_201_CREATED)
async def register(user: UserRegister):
    try:
        with get_db() as conn:
            c = conn.cursor()
            password_hash = hash_password(user.password)
            c.execute("INSERT INTO users (email, password_hash) VALUES (?, ?)", 
                     (user.email, password_hash))
            conn.commit()
            user_id = c.lastrowid
            
            token = create_access_token({"user_id": user_id})
            logger.info(f"User registered: {user.email}")
            return {"access_token": token, "token_type": "bearer"}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Email already registered")

@app.post("/api/login", response_model=Token)
async def login(user: UserLogin):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT id, password_hash FROM users WHERE email = ?", (user.email,))
        result = c.fetchone()
        
        if not result or not verify_password(user.password, result['password_hash']):
            raise HTTPException(status_code=401, detail="Invalid credentials")
        
        token = create_access_token({"user_id": result['id']})
        logger.info(f"User logged in: {user.email}")
        return {"access_token": token, "token_type": "bearer"}

@app.post("/api/tasks", response_model=TaskResponse, status_code=status.HTTP_201_CREATED)
async def create_task(task: TaskCreate, user_id: int = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute('''
            INSERT INTO tasks (user_id, title, description, priority, status, deadline, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (user_id, task.title, task.description, task.priority, task.status, task.deadline, task.tags))
        conn.commit()
        task_id = c.lastrowid
        
        c.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        result = dict(c.fetchone())
        result['is_overdue'] = is_task_overdue(
            datetime.fromisoformat(result['deadline'].replace(" ", "T")) if result['deadline'] else None,
            result['status']
        )
        logger.info(f"Task created: {task_id} by user {user_id}")
        return result

@app.get("/api/tasks", response_model=List[TaskResponse])
async def get_tasks(
    status_filter: Optional[str] = None,
    priority: Optional[str] = None,
    search: Optional[str] = None,
    user_id: int = Depends(verify_token)
):
    with get_db() as conn:
        c = conn.cursor()
        query = "SELECT * FROM tasks WHERE user_id = ?"
        params = [user_id]
        
        if status_filter:
            query += " AND status = ?"
            params.append(status_filter)
        if priority:
            query += " AND priority = ?"
            params.append(priority)
        if search:
            query += " AND (title LIKE ? OR description LIKE ?)"
            params.extend([f"%{search}%", f"%{search}%"])
        
        c.execute(query, params)
        tasks = []
        for row in c.fetchall():
            task = dict(row)
            task['is_overdue'] = is_task_overdue(
                datetime.fromisoformat(task['deadline'].replace(" ", "T")) if task['deadline'] else None,
                task['status']
            )
            tasks.append(task)
        return tasks

@app.get("/api/tasks/{task_id}", response_model=TaskResponse)
async def get_task(task_id: int, user_id: int = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
        result = c.fetchone()
        
        if not result:
            raise HTTPException(status_code=404, detail="Task not found")
        
        task = dict(result)
        task['is_overdue'] = is_task_overdue(
            datetime.fromisoformat(task['deadline'].replace(" ", "T")) if task['deadline'] else None,
            task['status']
        )
        return task

@app.put("/api/tasks/{task_id}", response_model=TaskResponse)
async def update_task(task_id: int, task: TaskUpdate, user_id: int = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("SELECT * FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
        if not c.fetchone():
            raise HTTPException(status_code=404, detail="Task not found")
        
        updates = []
        params = []
        for field, value in task.dict(exclude_unset=True).items():
            updates.append(f"{field} = ?")
            params.append(value)
        
        if updates:
            params.extend([task_id, user_id])
            c.execute(f"UPDATE tasks SET {', '.join(updates)}, updated_at = CURRENT_TIMESTAMP WHERE id = ? AND user_id = ?", params)
            conn.commit()
            logger.info(f"Task updated: {task_id}")
        
        c.execute("SELECT * FROM tasks WHERE id = ?", (task_id,))
        result = dict(c.fetchone())
        result['is_overdue'] = is_task_overdue(
            datetime.fromisoformat(result['deadline'].replace(" ", "T")) if result['deadline'] else None,
            result['status']
        )
        return result

@app.delete("/api/tasks/{task_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_task(task_id: int, user_id: int = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        c.execute("DELETE FROM tasks WHERE id = ? AND user_id = ?", (task_id, user_id))
        if c.rowcount == 0:
            raise HTTPException(status_code=404, detail="Task not found")
        conn.commit()
        logger.info(f"Task deleted: {task_id}")

@app.get("/api/dashboard/stats")
async def get_dashboard_stats(user_id: int = Depends(verify_token)):
    with get_db() as conn:
        c = conn.cursor()
        
        # Total tasks
        c.execute("SELECT COUNT(*) as total FROM tasks WHERE user_id = ?", (user_id,))
        total_tasks = c.fetchone()['total']
        
        # Completed tasks
        c.execute("SELECT COUNT(*) as completed FROM tasks WHERE user_id = ? AND status = 'Completed'", (user_id,))
        completed_tasks = c.fetchone()['completed']
        
        # Overdue tasks
        c.execute("""
            SELECT COUNT(*) as overdue FROM tasks 
            WHERE user_id = ? AND status != 'Completed' AND deadline < datetime('now')
        """, (user_id,))
        overdue_tasks = c.fetchone()['overdue']
        
        # Tasks by status
        c.execute("SELECT status, COUNT(*) as count FROM tasks WHERE user_id = ? GROUP BY status", (user_id,))
        tasks_by_status = {row['status']: row['count'] for row in c.fetchall()}
        
        # Completion rate
        completion_rate = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            "total_tasks": total_tasks,
            "completed_tasks": completed_tasks,
            "overdue_tasks": overdue_tasks,
            "tasks_by_status": tasks_by_status,
            "completion_rate": round(completion_rate, 2)
        }

@app.get("/")
async def root():
    return {"message": "Productivity Dashboard API is running!"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
