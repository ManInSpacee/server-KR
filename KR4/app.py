from itertools import count
from threading import Lock
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, conint, constr

from database import get_db, engine
from models import Base, Product
from sqlalchemy.orm import Session
from fastapi import Depends


app = FastAPI()

Base.metadata.create_all(bind=engine)


# ==================== Задание 10.1 — Кастомные исключения ====================

class CustomExceptionA(Exception):
    def __init__(self, message: str = "Custom error A occurred"):
        self.message = message


class CustomExceptionB(Exception):
    def __init__(self, message: str = "Resource not found"):
        self.message = message


class ErrorResponse(BaseModel):
    error: str
    detail: str


@app.exception_handler(CustomExceptionA)
async def handler_a(request: Request, exc: CustomExceptionA):
    return JSONResponse(status_code=400, content={"error": "CustomExceptionA", "detail": exc.message})


@app.exception_handler(CustomExceptionB)
async def handler_b(request: Request, exc: CustomExceptionB):
    return JSONResponse(status_code=404, content={"error": "CustomExceptionB", "detail": exc.message})


@app.get("/exception-a")
def trigger_a(fail: bool = True):
    if fail:
        raise CustomExceptionA("Condition not met")
    return {"message": "OK"}


@app.get("/exception-b/{item_id}")
def trigger_b(item_id: int):
    if item_id != 1:
        raise CustomExceptionB(f"Item {item_id} not found")
    return {"item_id": item_id, "name": "Sample item"}


# ==================== Задание 10.2 — Валидация + обработка ошибок ====================

from pydantic import ValidationError


class User(BaseModel):
    username: str
    age: conint(gt=18)
    email: EmailStr
    password: constr(min_length=8, max_length=16)
    phone: Optional[str] = "Unknown"


@app.exception_handler(ValidationError)
async def validation_error_handler(request: Request, exc: ValidationError):
    errors = [{"field": e["loc"][-1], "message": e["msg"]} for e in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": errors})


@app.post("/users/validate")
def validate_user(user: User):
    return {"message": f"User {user.username} is valid", "user": user.model_dump()}


# ==================== Задание 9.1 — Products CRUD через SQLAlchemy ====================

class ProductCreate(BaseModel):
    title: str
    price: float
    count: int
    description: str = ""


@app.get("/products")
def list_products(db: Session = Depends(get_db)):
    return db.query(Product).all()


@app.post("/products", status_code=201)
def create_product(data: ProductCreate, db: Session = Depends(get_db)):
    product = Product(**data.model_dump())
    db.add(product)
    db.commit()
    db.refresh(product)
    return product


@app.get("/products/{product_id}")
def get_product(product_id: int, db: Session = Depends(get_db)):
    product = db.query(Product).filter(Product.id == product_id).first()
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")
    return product


# ==================== Задание 11.1 + 11.2 — In-memory users (для тестов) ====================

_id_seq = count(start=1)
_id_lock = Lock()


def next_user_id() -> int:
    with _id_lock:
        return next(_id_seq)


class UserIn(BaseModel):
    username: str
    age: int


class UserOut(BaseModel):
    id: int
    username: str
    age: int


db_users: dict[int, dict] = {}


@app.post("/users", response_model=UserOut, status_code=201)
def create_user(user: UserIn):
    user_id = next_user_id()
    db_users[user_id] = user.model_dump()
    return {"id": user_id, **db_users[user_id]}


@app.get("/users/{user_id}", response_model=UserOut)
def get_user(user_id: int):
    if user_id not in db_users:
        raise HTTPException(status_code=404, detail="User not found")
    return {"id": user_id, **db_users[user_id]}


@app.delete("/users/{user_id}", status_code=204)
def delete_user(user_id: int):
    if db_users.pop(user_id, None) is None:
        raise HTTPException(status_code=404, detail="User not found")
