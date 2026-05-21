import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.storage import storage

client = TestClient(app)
USER_HEADERS = {"X-User-Id": "10", "X-User-Role": "user"}
ADMIN_HEADERS = {"X-User-Id": "1", "X-User-Role": "admin"}


@pytest.fixture(autouse=True)
def clear_storage():
    storage.clear()
    yield
    storage.clear()


def test_get_me():
    res = client.get("/users/me", headers=USER_HEADERS)
    assert res.status_code == 200
    assert res.json()["id"] == 10


def test_no_user_id_401():
    res = client.get("/users/me")
    assert res.status_code == 401


def test_user_forbidden_admin_stats():
    res = client.get("/admin/stats", headers=USER_HEADERS)
    assert res.status_code == 403


def test_admin_gets_stats():
    client.post("/tasks", json={"title": "Admin task", "priority": 2}, headers=ADMIN_HEADERS)
    res = client.get("/admin/stats", headers=ADMIN_HEADERS)
    assert res.status_code == 200
    assert res.json()["total_tasks"] == 1


def test_user_cannot_delete_others_task():
    task = client.post("/tasks", json={"title": "Other task", "priority": 1},
                       headers={"X-User-Id": "20", "X-User-Role": "user"}).json()
    res = client.delete(f"/tasks/{task['id']}", headers=USER_HEADERS)
    assert res.status_code == 404


def test_admin_can_delete_any_task():
    task = client.post("/tasks", json={"title": "User task", "priority": 1}, headers=USER_HEADERS).json()
    res = client.delete(f"/admin/tasks/{task['id']}", headers=ADMIN_HEADERS)
    assert res.status_code == 204


def test_health():
    res = client.get("/health")
    assert res.status_code == 200
    assert res.json()["status"] == "ok"
