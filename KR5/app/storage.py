from itertools import count
from threading import Lock


class TaskStorage:
    def __init__(self):
        self._tasks: dict[int, dict] = {}
        self._id_seq = count(start=1)
        self._lock = Lock()

    def next_id(self) -> int:
        with self._lock:
            return next(self._id_seq)

    def add(self, task: dict) -> dict:
        task_id = self.next_id()
        task = {"id": task_id, **task}
        self._tasks[task_id] = task
        return task

    def get(self, task_id: int) -> dict | None:
        return self._tasks.get(task_id)

    def list_by_owner(self, owner_id: int, status: str | None, min_priority: int | None) -> list[dict]:
        tasks = [t for t in self._tasks.values() if t["owner_id"] == owner_id]
        if status:
            tasks = [t for t in tasks if t["status"] == status]
        if min_priority is not None:
            tasks = [t for t in tasks if t["priority"] >= min_priority]
        return tasks

    def update_status(self, task_id: int, status: str) -> dict | None:
        task = self._tasks.get(task_id)
        if task:
            task["status"] = status
        return task

    def delete(self, task_id: int) -> bool:
        return self._tasks.pop(task_id, None) is not None

    def all(self) -> list[dict]:
        return list(self._tasks.values())

    def clear(self):
        self._tasks.clear()
        self._id_seq = count(start=1)


storage = TaskStorage()
