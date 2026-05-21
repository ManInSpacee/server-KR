from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from fastapi import Response as FastAPIResponse
from app.schemas import TaskCreate, TaskOut, TaskStatusUpdate, UserOut
from app.dependencies import get_current_user, get_storage
from app.storage import TaskStorage

router = APIRouter(prefix="/tasks", tags=["tasks"])


@router.post("", response_model=TaskOut, status_code=201)
def create_task(task: TaskCreate,
                user: UserOut = Depends(get_current_user),
                store: TaskStorage = Depends(get_storage)):
    data = task.model_dump()
    data["owner_id"] = user.id
    return store.add(data)


@router.get("", response_model=list[TaskOut])
def list_tasks(status: Optional[str] = None,
               min_priority: Optional[int] = None,
               user: UserOut = Depends(get_current_user),
               store: TaskStorage = Depends(get_storage)):
    return store.list_by_owner(user.id, status, min_priority)


@router.get("/{task_id}", response_model=TaskOut)
def get_task(task_id: int,
             user: UserOut = Depends(get_current_user),
             store: TaskStorage = Depends(get_storage)):
    task = store.get(task_id)
    if not task or task["owner_id"] != user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    return task


@router.patch("/{task_id}/status", response_model=TaskOut)
def update_status(task_id: int,
                  body: TaskStatusUpdate,
                  user: UserOut = Depends(get_current_user),
                  store: TaskStorage = Depends(get_storage)):
    task = store.get(task_id)
    if not task or task["owner_id"] != user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    return store.update_status(task_id, body.status)


@router.delete("/{task_id}", status_code=204)
def delete_task(task_id: int,
                user: UserOut = Depends(get_current_user),
                store: TaskStorage = Depends(get_storage)):
    task = store.get(task_id)
    if not task or task["owner_id"] != user.id:
        raise HTTPException(status_code=404, detail="Task not found")
    store.delete(task_id)
    return FastAPIResponse(status_code=204)
