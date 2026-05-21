import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage import storage

client = TestClient(app)
HEADERS = {"X-User-Id": "10"}


@pytest.fixture(autouse=True)
def clear_storage():
    storage.clear()
    yield
    storage.clear()


def create_task(title="Test task", priority=3, headers=None):
    return client.post("/tasks", json={"title": title, "priority": priority}, headers=headers or HEADERS)


def test_create_task_success():
    res = create_task()
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == "Test task"
    assert data["owner_id"] == 10
    assert data["status"] == "todo"


def test_create_task_title_too_short():
    res = client.post("/tasks", json={"title": "ab", "priority": 3}, headers=HEADERS)
    assert res.status_code == 422


def test_create_task_no_auth():
    res = client.post("/tasks", json={"title": "Test task", "priority": 3})
    assert res.status_code == 401


def test_list_tasks_only_own():
    client.post("/tasks", json={"title": "User 10 task", "priority": 2}, headers={"X-User-Id": "10"})
    client.post("/tasks", json={"title": "User 20 task", "priority": 2}, headers={"X-User-Id": "20"})
    res = client.get("/tasks", headers=HEADERS)
    assert res.status_code == 200
    assert all(t["owner_id"] == 10 for t in res.json())


def test_filter_by_status():
    client.post("/tasks", json={"title": "Task todo", "priority": 1, "status": "todo"}, headers=HEADERS)
    client.post("/tasks", json={"title": "Task done", "priority": 1, "status": "done"}, headers=HEADERS)
    res = client.get("/tasks?status=done", headers=HEADERS)
    assert all(t["status"] == "done" for t in res.json())


def test_filter_by_min_priority():
    client.post("/tasks", json={"title": "Low prio", "priority": 1}, headers=HEADERS)
    client.post("/tasks", json={"title": "High prio", "priority": 5}, headers=HEADERS)
    res = client.get("/tasks?min_priority=3", headers=HEADERS)
    assert all(t["priority"] >= 3 for t in res.json())


def test_update_status():
    task = create_task().json()
    res = client.patch(f"/tasks/{task['id']}/status", json={"status": "done"}, headers=HEADERS)
    assert res.status_code == 200
    assert res.json()["status"] == "done"


def test_get_task_not_found_or_other_owner():
    task = client.post("/tasks", json={"title": "Other task", "priority": 1}, headers={"X-User-Id": "20"}).json()
    res = client.get(f"/tasks/{task['id']}", headers=HEADERS)
    assert res.status_code == 404


def test_delete_task():
    task = create_task().json()
    res = client.delete(f"/tasks/{task['id']}", headers=HEADERS)
    assert res.status_code == 204
    assert client.get(f"/tasks/{task['id']}", headers=HEADERS).status_code == 404
