import os
import secrets
import time
from datetime import datetime, timedelta

import jwt
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Depends, Request, Response
from fastapi.openapi.docs import get_swagger_ui_html
from fastapi.openapi.utils import get_openapi
from fastapi.responses import JSONResponse
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from passlib.context import CryptContext
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from models import User, UserInDB, UserBase, TodoCreate, TodoUpdate
from database import get_db_connection, create_tables

load_dotenv()

MODE = os.getenv("MODE", "DEV")
DOCS_USER = os.getenv("DOCS_USER", "admin")
DOCS_PASSWORD = os.getenv("DOCS_PASSWORD", "secret")
JWT_SECRET = "jwt-super-secret-key"
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_MINUTES = 30

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBasic()
limiter = Limiter(key_func=get_remote_address)

# In-memory user DB для заданий 6.x/7.1
fake_users_db: dict[str, UserInDB] = {}

# Создаём таблицы SQLite при старте
create_tables()


# ==================== Настройка приложения (задание 6.3) ====================

if MODE == "PROD":
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
else:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

app.state.limiter = limiter


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(status_code=429, content={"detail": "Too many requests"})


def verify_docs_credentials(credentials: HTTPBasicCredentials = Depends(security)):
    correct_user = secrets.compare_digest(credentials.username, DOCS_USER)
    correct_pass = secrets.compare_digest(credentials.password, DOCS_PASSWORD)
    if not (correct_user and correct_pass):
        raise HTTPException(
            status_code=401,
            detail="Unauthorized",
            headers={"WWW-Authenticate": "Basic"},
        )


if MODE == "DEV":
    @app.get("/docs", include_in_schema=False)
    def custom_docs(credentials: HTTPBasicCredentials = Depends(security)):
        verify_docs_credentials(credentials)
        return get_swagger_ui_html(openapi_url="/openapi.json", title="API Docs")

    @app.get("/openapi.json", include_in_schema=False)
    def custom_openapi(credentials: HTTPBasicCredentials = Depends(security)):
        verify_docs_credentials(credentials)
        return get_openapi(title="KR3 API", version="1.0.0", routes=app.routes)


# ==================== Задание 6.1 + 6.2 — Basic Auth ====================

def auth_user(credentials: HTTPBasicCredentials = Depends(security)) -> UserInDB:
    user = fake_users_db.get(credentials.username)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not secrets.compare_digest(credentials.username, user.username):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not pwd_context.verify(credentials.password, user.hashed_password):
        raise HTTPException(
            status_code=401,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return user


@app.post("/register")
@limiter.limit("1/minute")
def register(request: Request, user: User):
    if user.username in fake_users_db:
        raise HTTPException(status_code=409, detail="User already exists")
    hashed = pwd_context.hash(user.password)
    fake_users_db[user.username] = UserInDB(
        username=user.username,
        hashed_password=hashed,
        role=getattr(user, "role", "user"),
    )
    return JSONResponse(status_code=201, content={"message": "New user created"})


@app.get("/login")
def login(user: UserInDB = Depends(auth_user)):
    return {"message": f"You got my secret, welcome"}


# ==================== Задание 6.4 + 6.5 — JWT ====================

def create_jwt_token(username: str) -> str:
    payload = {
        "sub": username,
        "exp": datetime.utcnow() + timedelta(minutes=JWT_EXPIRATION_MINUTES),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)


def get_current_user_jwt(request: Request) -> dict:
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Token missing")
    token = auth_header.split(" ", 1)[1]
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Invalid token")
    username = payload.get("sub")
    if not username or username not in fake_users_db:
        raise HTTPException(status_code=401, detail="Invalid token")
    return fake_users_db[username]


@app.post("/login_jwt")
@limiter.limit("5/minute")
def login_jwt(request: Request, user: User):
    db_user = fake_users_db.get(user.username)
    if not db_user:
        raise HTTPException(status_code=404, detail="User not found")
    if not secrets.compare_digest(user.username, db_user.username):
        raise HTTPException(status_code=401, detail="Authorization failed")
    if not pwd_context.verify(user.password, db_user.hashed_password):
        raise HTTPException(status_code=401, detail="Authorization failed")
    token = create_jwt_token(user.username)
    return {"access_token": token, "token_type": "bearer"}


@app.get("/protected_resource")
def protected_resource(user: UserInDB = Depends(get_current_user_jwt)):
    return {"message": "Access granted"}


# ==================== Задание 7.1 — RBAC ====================

ROLE_PERMISSIONS = {
    "admin": ["create", "read", "update", "delete"],
    "user": ["read", "update"],
    "guest": ["read"],
}


def require_role(*allowed_roles):
    def dependency(user: UserInDB = Depends(get_current_user_jwt)):
        if user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Forbidden: insufficient permissions")
        return user
    return dependency


@app.post("/register_with_role")
def register_with_role(username: str, password: str, role: str = "user"):
    if username in fake_users_db:
        raise HTTPException(status_code=409, detail="User already exists")
    if role not in ROLE_PERMISSIONS:
        raise HTTPException(status_code=400, detail=f"Invalid role. Choose from: {list(ROLE_PERMISSIONS.keys())}")
    hashed = pwd_context.hash(password)
    fake_users_db[username] = UserInDB(username=username, hashed_password=hashed, role=role)
    return JSONResponse(status_code=201, content={"message": f"User created with role '{role}'"})


@app.post("/admin/resource")
def admin_create_resource(
    title: str,
    user: UserInDB = Depends(require_role("admin")),
):
    return {"message": f"Resource '{title}' created by admin {user.username}"}


@app.get("/user/resource")
def user_read_resource(user: UserInDB = Depends(require_role("admin", "user"))):
    return {"message": f"Resource data for {user.username}", "data": ["item1", "item2"]}


@app.put("/user/resource")
def user_update_resource(
    title: str,
    user: UserInDB = Depends(require_role("admin", "user")),
):
    return {"message": f"Resource updated to '{title}' by {user.username}"}


@app.delete("/admin/resource")
def admin_delete_resource(
    resource_id: int,
    user: UserInDB = Depends(require_role("admin")),
):
    return {"message": f"Resource {resource_id} deleted by admin {user.username}"}


@app.get("/guest/resource")
def guest_read_resource(user: UserInDB = Depends(require_role("admin", "user", "guest"))):
    return {"message": f"Public resource data for {user.username}"}


# ==================== Задание 8.1 — SQLite register ====================

@app.post("/db/register")
def db_register(user: User):
    conn = get_db_connection()
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, user.password))
    conn.commit()
    conn.close()
    return {"message": "User registered successfully!"}


# ==================== Задание 8.2 — CRUD Todo ====================

@app.post("/todos", status_code=201)
def create_todo(todo: TodoCreate):
    conn = get_db_connection()
    cursor = conn.execute(
        "INSERT INTO todos (title, description, completed) VALUES (?, ?, 0)",
        (todo.title, todo.description),
    )
    todo_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": todo_id, "title": todo.title, "description": todo.description, "completed": False}


@app.get("/todos/{todo_id}")
def get_todo(todo_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    conn.close()
    if not row:
        raise HTTPException(status_code=404, detail="Todo not found")
    return {"id": row["id"], "title": row["title"], "description": row["description"], "completed": bool(row["completed"])}


@app.put("/todos/{todo_id}")
def update_todo(todo_id: int, todo: TodoUpdate):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.execute(
        "UPDATE todos SET title = ?, description = ?, completed = ? WHERE id = ?",
        (todo.title, todo.description, int(todo.completed), todo_id),
    )
    conn.commit()
    conn.close()
    return {"id": todo_id, "title": todo.title, "description": todo.description, "completed": todo.completed}


@app.delete("/todos/{todo_id}")
def delete_todo(todo_id: int):
    conn = get_db_connection()
    row = conn.execute("SELECT * FROM todos WHERE id = ?", (todo_id,)).fetchone()
    if not row:
        conn.close()
        raise HTTPException(status_code=404, detail="Todo not found")
    conn.execute("DELETE FROM todos WHERE id = ?", (todo_id,))
    conn.commit()
    conn.close()
    return {"message": "Todo deleted successfully"}
