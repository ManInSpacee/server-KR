import uuid
import time
from datetime import datetime

from fastapi import FastAPI, HTTPException, Cookie, Response, Request, Header
from pydantic import BaseModel, EmailStr, Field
from typing import Optional
from itsdangerous import URLSafeSerializer

app = FastAPI()

SECRET_KEY = "super-secret-key-for-signing"
signer = URLSafeSerializer(SECRET_KEY)


# ==================== Задание 3.1 ====================

class UserCreate(BaseModel):
    name: str
    email: EmailStr
    age: Optional[int] = Field(default=None, gt=0)
    is_subscribed: Optional[bool] = None


@app.post("/create_user")
def create_user(user: UserCreate):
    return user


# ==================== Задание 3.2 ====================

sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]


@app.get("/product/{product_id}")
def get_product(product_id: int):
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/search")
def search_products(keyword: str, category: Optional[str] = None, limit: int = 10):
    results = []
    for product in sample_products:
        if keyword.lower() in product["name"].lower():
            if category is None or product["category"] == category:
                results.append(product)
    return results[:limit]


# ==================== Задание 5.1 ====================

fake_users_db = {
    "user123": {
        "username": "user123",
        "password": "password123",
        "name": "Alice",
        "email": "alice@example.com",
    }
}

sessions: dict[str, str] = {}  # token -> username


@app.post("/login")
def login(response: Response, username: str = None, password: str = None):
    # Поддержка JSON body
    user = fake_users_db.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    session_token = str(uuid.uuid4())
    sessions[session_token] = username
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
    )
    return {"message": "Login successful"}


@app.get("/user")
def get_user(session_token: Optional[str] = Cookie(default=None)):
    if session_token is None or session_token not in sessions:
        return Response(
            content='{"message": "Unauthorized"}',
            status_code=401,
            media_type="application/json",
        )
    username = sessions[session_token]
    user = fake_users_db[username]
    return {"username": user["username"], "name": user["name"], "email": user["email"]}


# ==================== Задание 5.2 ====================

users_db_v2 = {
    "user123": {
        "username": "user123",
        "password": "password123",
        "user_id": str(uuid.uuid4()),
        "name": "Alice",
        "email": "alice@example.com",
    }
}

# username -> user_id mapping для поиска
user_id_map: dict[str, dict] = {}
for _uname, _udata in users_db_v2.items():
    user_id_map[_udata["user_id"]] = _udata


@app.post("/login_v2")
def login_v2(response: Response, username: str = None, password: str = None):
    user = users_db_v2.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = user["user_id"]
    token = signer.dumps(user_id)
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        max_age=3600,
    )
    return {"message": "Login successful"}


@app.get("/profile")
def get_profile(session_token: Optional[str] = Cookie(default=None)):
    if session_token is None:
        return Response(
            content='{"message": "Unauthorized"}',
            status_code=401,
            media_type="application/json",
        )
    try:
        user_id = signer.loads(session_token)
    except Exception:
        return Response(
            content='{"message": "Unauthorized"}',
            status_code=401,
            media_type="application/json",
        )

    user = user_id_map.get(user_id)
    if not user:
        return Response(
            content='{"message": "Unauthorized"}',
            status_code=401,
            media_type="application/json",
        )
    return {"user_id": user_id, "username": user["username"], "name": user["name"], "email": user["email"]}


# ==================== Задание 5.3 ====================

SESSION_MAX_AGE = 300  # 5 минут
SESSION_RENEW_AFTER = 180  # 3 минуты


@app.post("/login_v3")
def login_v3(response: Response, username: str = None, password: str = None):
    user = users_db_v2.get(username)
    if not user or user["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    user_id = user["user_id"]
    timestamp = int(time.time())
    token = signer.dumps({"user_id": user_id, "last_active": timestamp})
    response.set_cookie(
        key="session_token",
        value=token,
        httponly=True,
        secure=False,
        max_age=SESSION_MAX_AGE,
    )
    return {"message": "Login successful"}


@app.get("/profile_v3")
def get_profile_v3(response: Response, session_token: Optional[str] = Cookie(default=None)):
    if session_token is None:
        return Response(
            content='{"message": "Invalid session"}',
            status_code=401,
            media_type="application/json",
        )

    try:
        data = signer.loads(session_token)
        user_id = data["user_id"]
        last_active = data["last_active"]
    except Exception:
        return Response(
            content='{"message": "Invalid session"}',
            status_code=401,
            media_type="application/json",
        )

    now = int(time.time())
    elapsed = now - last_active

    if elapsed >= SESSION_MAX_AGE:
        return Response(
            content='{"message": "Session expired"}',
            status_code=401,
            media_type="application/json",
        )

    user = user_id_map.get(user_id)
    if not user:
        return Response(
            content='{"message": "Invalid session"}',
            status_code=401,
            media_type="application/json",
        )

    # Продлеваем сессию если прошло >= 3 и < 5 минут
    if elapsed >= SESSION_RENEW_AFTER:
        new_timestamp = now
        new_token = signer.dumps({"user_id": user_id, "last_active": new_timestamp})
        response.set_cookie(
            key="session_token",
            value=new_token,
            httponly=True,
            secure=False,
            max_age=SESSION_MAX_AGE,
        )

    return {"user_id": user_id, "username": user["username"], "name": user["name"], "email": user["email"]}


# ==================== Задание 5.4 ====================

@app.get("/headers")
def get_headers(
    user_agent: Optional[str] = Header(default=None),
    accept_language: Optional[str] = Header(default=None),
):
    if not user_agent:
        raise HTTPException(status_code=400, detail="User-Agent header is missing")
    if not accept_language:
        raise HTTPException(status_code=400, detail="Accept-Language header is missing")

    return {
        "User-Agent": user_agent,
        "Accept-Language": accept_language,
    }


# ==================== Задание 5.5 ====================

class CommonHeaders(BaseModel):
    user_agent: str = Field(alias="user-agent")
    accept_language: str = Field(alias="accept-language")

    model_config = {"populate_by_name": True}


@app.get("/headers_v2")
def get_headers_v2(request: Request):
    ua = request.headers.get("user-agent")
    al = request.headers.get("accept-language")
    if not ua:
        raise HTTPException(status_code=400, detail="User-Agent header is missing")
    if not al:
        raise HTTPException(status_code=400, detail="Accept-Language header is missing")

    headers = CommonHeaders(**{"user-agent": ua, "accept-language": al})
    return {
        "User-Agent": headers.user_agent,
        "Accept-Language": headers.accept_language,
    }


@app.get("/info")
def get_info(request: Request, response: Response):
    ua = request.headers.get("user-agent")
    al = request.headers.get("accept-language")
    if not ua:
        raise HTTPException(status_code=400, detail="User-Agent header is missing")
    if not al:
        raise HTTPException(status_code=400, detail="Accept-Language header is missing")

    headers = CommonHeaders(**{"user-agent": ua, "accept-language": al})
    response.headers["X-Server-Time"] = datetime.now().strftime("%Y-%m-%dT%H:%M:%S")
    return {
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": headers.user_agent,
            "Accept-Language": headers.accept_language,
        },
    }
