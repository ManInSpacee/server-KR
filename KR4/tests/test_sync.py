import pytest
from fastapi.testclient import TestClient
from app import app, db_users

client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_db():
    db_users.clear()
    yield
    db_users.clear()


def test_create_user():
    res = client.post("/users", json={"username": "alice", "age": 25})
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == "alice"
    assert data["age"] == 25
    assert "id" in data


def test_get_user():
    created = client.post("/users", json={"username": "bob", "age": 30}).json()
    res = client.get(f"/users/{created['id']}")
    assert res.status_code == 200
    assert res.json()["username"] == "bob"


def test_get_user_not_found():
    res = client.get("/users/9999")
    assert res.status_code == 404


def test_delete_user():
    created = client.post("/users", json={"username": "carol", "age": 22}).json()
    res = client.delete(f"/users/{created['id']}")
    assert res.status_code == 204


def test_delete_user_twice():
    created = client.post("/users", json={"username": "dave", "age": 28}).json()
    client.delete(f"/users/{created['id']}")
    res = client.delete(f"/users/{created['id']}")
    assert res.status_code == 404


def test_custom_exception_a():
    res = client.get("/exception-a?fail=true")
    assert res.status_code == 400
    assert res.json()["error"] == "CustomExceptionA"


def test_custom_exception_b_not_found():
    res = client.get("/exception-b/42")
    assert res.status_code == 404
    assert res.json()["error"] == "CustomExceptionB"


def test_custom_exception_b_found():
    res = client.get("/exception-b/1")
    assert res.status_code == 200


def test_validate_user_valid():
    res = client.post("/users/validate", json={
        "username": "john",
        "age": 25,
        "email": "john@example.com",
        "password": "secure123",
    })
    assert res.status_code == 200


def test_validate_user_invalid_age():
    res = client.post("/users/validate", json={
        "username": "teen",
        "age": 16,
        "email": "teen@example.com",
        "password": "secure123",
    })
    assert res.status_code == 422


def test_validate_user_short_password():
    res = client.post("/users/validate", json={
        "username": "user",
        "age": 20,
        "email": "user@example.com",
        "password": "123",
    })
    assert res.status_code == 422
