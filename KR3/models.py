from pydantic import BaseModel
from typing import Optional


# Задание 6.2 — модели пользователей
class UserBase(BaseModel):
    username: str


class User(UserBase):
    password: str


class UserInDB(UserBase):
    hashed_password: str
    role: str = "user"


# Задание 8.2 — модель Todo
class TodoCreate(BaseModel):
    title: str
    description: str


class TodoUpdate(BaseModel):
    title: str
    description: str
    completed: bool
