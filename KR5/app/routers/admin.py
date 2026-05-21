from fastapi import APIRouter, Depends, HTTPException
from fastapi import Response as FastAPIResponse
from app.schemas import UserOut
from app.dependencies import require_admin, get_storage
from app.storage import TaskStorage

router = APIRouter(prefix="/admin", tags=["admin"])


@router.get("/stats")
def get_stats(user: UserOut = Depends(require_admin),
              store: TaskStorage = Depends(get_storage)):
    tasks = store.all()
    by_status = {"todo": 0, "in_progress": 0, "done": 0}
    for t in tasks:
        by_status[t["status"]] = by_status.get(t["status"], 0) + 1
    return {"total_tasks": len(tasks), "by_status": by_status}


@router.delete("/tasks/{task_id}", status_code=204)
def admin_delete_task(task_id: int,
                      user: UserOut = Depends(require_admin),
                      store: TaskStorage = Depends(get_storage)):
    if not store.delete(task_id):
        raise HTTPException(status_code=404, detail="Task not found")
    return FastAPIResponse(status_code=204)
