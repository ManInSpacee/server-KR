from typing import Literal, Optional
from pydantic import BaseModel, Field


class TaskCreate(BaseModel):
    title: str = Field(min_length=3, max_length=80)
    description: Optional[str] = None
    status: Literal["todo", "in_progress", "done"] = "todo"
    priority: int = Field(ge=1, le=5)


class TaskOut(TaskCreate):
    id: int
    owner_id: int


class TaskStatusUpdate(BaseModel):
    status: Literal["todo", "in_progress", "done"]


class UserOut(BaseModel):
    id: int
    role: str
