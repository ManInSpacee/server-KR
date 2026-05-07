import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from faker import Faker
from app import app, db_users

fake = Faker()

pytestmark = pytest.mark.asyncio


@pytest.fixture(autouse=True)
def clear_db():
    db_users.clear()
    yield
    db_users.clear()


@pytest.fixture
def user_data():
    return {"username": fake.user_name(), "age": fake.random_int(min=18, max=80)}


async def make_client():
    return AsyncClient(transport=ASGITransport(app=app), base_url="http://test")


async def test_create_user_async(user_data):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.post("/users", json=user_data)
    assert res.status_code == 201
    data = res.json()
    assert data["username"] == user_data["username"]
    assert "id" in data


async def test_get_user_async(user_data):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await client.post("/users", json=user_data)).json()
        res = await client.get(f"/users/{created['id']}")
    assert res.status_code == 200
    assert res.json()["username"] == user_data["username"]


async def test_get_user_not_found_async():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/users/99999")
    assert res.status_code == 404


async def test_delete_user_async(user_data):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await client.post("/users", json=user_data)).json()
        res = await client.delete(f"/users/{created['id']}")
    assert res.status_code == 204


async def test_delete_user_twice_async(user_data):
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        created = (await client.post("/users", json=user_data)).json()
        await client.delete(f"/users/{created['id']}")
        res = await client.delete(f"/users/{created['id']}")
    assert res.status_code == 404
