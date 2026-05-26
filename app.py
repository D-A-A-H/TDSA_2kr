from fastapi import FastAPI, HTTPException, status, Request, Response, Cookie, Header
from fastapi.responses import JSONResponse
from pydantic import ValidationError
from typing import Optional, List
import uuid
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
import time
from datetime import datetime, timezone
from models import UserCreate, LoginRequest, ProfileResponse

# ---------- Инициализация приложения ----------
app = FastAPI(title="Server Technologies Control Work #2")

# Секретный ключ для подписи (в реальном проекте хранить в .env)
SECRET_KEY = "my-super-secret-key-for-session-signing-2025"
serializer = URLSafeTimedSerializer(SECRET_KEY)

# ---------- Тестовые данные для заданий 3.2, 5.1, 5.2, 5.3 ----------
sample_products = [
    {"product_id": 123, "name": "Smartphone", "category": "Electronics", "price": 599.99},
    {"product_id": 456, "name": "Phone Case", "category": "Accessories", "price": 19.99},
    {"product_id": 789, "name": "Iphone", "category": "Electronics", "price": 1299.99},
    {"product_id": 101, "name": "Headphones", "category": "Accessories", "price": 99.99},
    {"product_id": 202, "name": "Smartwatch", "category": "Electronics", "price": 299.99},
]

# Хранилище валидных пользователей (для аутентификации)
# В реальном приложении — база данных
VALID_USERS = {
    "user123": {"password": "password123", "user_id": str(uuid.uuid4())},
    "alice": {"password": "alicepass", "user_id": str(uuid.uuid4())},
}

# ---------- Задание 3.1: POST /create_user ----------
@app.post("/create_user", response_model=UserCreate)
async def create_user(user: UserCreate):
    """
    Принимает данные пользователя, валидирует их и возвращает те же данные.
    """
    # Pydantic автоматически выполнит валидацию (EmailStr, age>=1)
    return user

# ---------- Задание 3.2: GET /product/{product_id} и GET /products/search ----------
@app.get("/product/{product_id}")
async def get_product(product_id: int):
    """
    Возвращает продукт по ID.
    """
    for product in sample_products:
        if product["product_id"] == product_id:
            return product
    raise HTTPException(status_code=404, detail="Product not found")


@app.get("/products/search")
async def search_products(
    keyword: str,
    category: Optional[str] = None,
    limit: int = 10
):
    """
    Поиск продуктов по ключевому слову (без учёта регистра), фильтрации по категории и ограничению.
    """
    results = []
    keyword_lower = keyword.lower()
    for product in sample_products:
        if keyword_lower in product["name"].lower():
            if category is None or product["category"].lower() == category.lower():
                results.append(product)
    return results[:limit]

# ---------- Задание 5.1: Простая cookie-аутентификация ----------
@app.post("/login-simple")
async def login_simple(request: Request):
    """
    Простая аутентификация без подписи (для Задания 5.1).
    Принимает JSON: {"username": "...", "password": "..."}
    """
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    username = body.get("username")
    password = body.get("password")
    
    if username not in VALID_USERS or VALID_USERS[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    session_token = str(uuid.uuid4())
    response = JSONResponse({"message": "Login successful"})
    response.set_cookie(
        key="session_token",
        value=session_token,
        httponly=True,
        max_age=300,
        secure=False  # Для тестирования (без HTTPS)
    )
    return response


@app.get("/user")
async def get_user_profile(session_token: Optional[str] = Cookie(None)):
    """
    Защищённый маршрут (Задание 5.1).
    Проверяет наличие и валидность cookie (просто факт наличия, без подписи).
    """
    if not session_token:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})
    # В реальном приложении нужно хранить и проверять токены
    # Здесь для простоты считаем любой непустой токен валидным
    return {"user_id": "user123", "username": "user123", "message": "Profile data"}

# ---------- Задание 5.2: Подписанная cookie (itsdangerous) ----------
@app.post("/login")
async def login_signed(request: Request, response: Response):
    """
    Логин с подписанной cookie.
    Формат: <user_id>.<signature>
    """
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    username = body.get("username")
    password = body.get("password")
    
    if username not in VALID_USERS or VALID_USERS[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = VALID_USERS[username]["user_id"]
    # Подписываем user_id
    signed_token = serializer.dumps(user_id)
    
    response.set_cookie(
        key="session_token",
        value=signed_token,
        httponly=True,
        max_age=300,
        secure=False
    )
    return {"message": "Login successful"}


@app.get("/profile")
async def get_profile_signed(session_token: Optional[str] = Cookie(None)):
    """
    Защищённый маршрут с проверкой подписи (Задание 5.2).
    """
    if not session_token:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})
    
    try:
        user_id = serializer.loads(session_token, max_age=300)
    except SignatureExpired:
        raise HTTPException(status_code=401, detail={"message": "Session expired"})
    except BadSignature:
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})
    
    # Находим username по user_id
    username = None
    for name, data in VALID_USERS.items():
        if data["user_id"] == user_id:
            username = name
            break
    
    return {"user_id": user_id, "username": username, "message": "Profile data"}

# ---------- Задание 5.3: Динамическое продление сессии ----------
# Формат: <user_id>.<timestamp>.<signature>
# timestamp — время последней активности (Unix time)

def create_session_token(user_id: str, timestamp: int) -> str:
    """Создаёт подписанный токен с временем последней активности."""
    data = f"{user_id}.{timestamp}"
    signature = serializer.dumps(data)[len(serializer.dumps("")): ]  # упрощённо: не подходит
    # Правильный способ — использовать URLSafeTimedSerializer для одной строки
    # Но для нашего формата user_id.timestamp.signature сделаем вручную:
    # Используем serializer для подписи полной строки
    full_data = f"{user_id}.{timestamp}"
    signed = serializer.dumps(full_data)
    return signed


def parse_session_token(token: str):
    """
    Разбирает токен, возвращает (user_id, timestamp) или вызывает исключение.
    """
    try:
        # loads проверяет срок действия через max_age отдельно
        full_data = serializer.loads(token)
    except (BadSignature, SignatureExpired):
        raise BadSignature("Invalid token")
    
    parts = full_data.split(".")
    if len(parts) != 2:
        raise BadSignature("Invalid format")
    user_id, timestamp_str = parts
    try:
        timestamp = int(timestamp_str)
    except ValueError:
        raise BadSignature("Invalid timestamp")
    return user_id, timestamp


@app.post("/login-extended")
async def login_extended(request: Request, response: Response):
    """
    Логин с динамической сессией (Задание 5.3).
    """
    try:
        body = await request.json()
    except:
        raise HTTPException(status_code=400, detail="Invalid JSON")
    
    username = body.get("username")
    password = body.get("password")
    
    if username not in VALID_USERS or VALID_USERS[username]["password"] != password:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    
    user_id = VALID_USERS[username]["user_id"]
    now_timestamp = int(time.time())
    # Формат: user_id.timestamp (подписываем целиком)
    data_to_sign = f"{user_id}.{now_timestamp}"
    signed_token = serializer.dumps(data_to_sign)
    
    response.set_cookie(
        key="session_token",
        value=signed_token,
        httponly=True,
        max_age=300,
        secure=False
    )
    return {"message": "Login successful"}


@app.get("/profile-extended")
async def get_profile_extended(request: Request, response: Response, session_token: Optional[str] = Cookie(None)):
    """
    Защищённый маршрут с динамическим продлением сессии.
    Правила:
    - прошло < 3 минут → не обновляем cookie
    - прошло 3–5 минут → обновляем cookie (продлеваем на 5 минут от текущего времени)
    - прошло > 5 минут → 401
    """
    if not session_token:
        raise HTTPException(status_code=401, detail={"message": "Unauthorized"})
    
    try:
        # Проверяем целостность, но без проверки срока (своя логика)
        full_data = serializer.loads(session_token)  # может выбросить BadSignature
        parts = full_data.split(".")
        if len(parts) != 2:
            raise BadSignature("Invalid format")
        user_id, last_active = parts[0], int(parts[1])
    except (BadSignature, ValueError, IndexError):
        raise HTTPException(status_code=401, detail={"message": "Invalid session"})
    
    now = int(time.time())
    elapsed = now - last_active
    
    if elapsed > 300:  # больше 5 минут
        raise HTTPException(status_code=401, detail={"message": "Session expired"})
    
    # Обновляем cookie, если прошло от 3 до 5 минут
    if elapsed >= 180 and elapsed < 300:
        new_timestamp = now
        new_data = f"{user_id}.{new_timestamp}"
        new_signed = serializer.dumps(new_data)
        response.set_cookie(
            key="session_token",
            value=new_signed,
            httponly=True,
            max_age=300,
            secure=False
        )
    
    # Находим username
    username = None
    for name, data in VALID_USERS.items():
        if data["user_id"] == user_id:
            username = name
            break
    
    return {
        "user_id": user_id,
        "username": username,
        "last_activity": datetime.fromtimestamp(last_active, tz=timezone.utc).isoformat(),
        "elapsed_seconds": elapsed,
        "message": "Profile data with extended session"
    }

# ---------- Задание 5.4: Работа с заголовками ----------
@app.get("/headers")
async def get_headers(
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    accept_language: Optional[str] = Header(None, alias="Accept-Language")
):
    """
    Возвращает заголовки User-Agent и Accept-Language.
    """
    return {
        "User-Agent": user_agent,
        "Accept-Language": accept_language
    }


@app.get("/info")
async def get_info(
    request: Request,
    user_agent: Optional[str] = Header(None, alias="User-Agent"),
    accept_language: Optional[str] = Header(None, alias="Accept-Language")
):
    """
    Возвращает приветствие, заголовки и добавляет X-Server-Time в заголовки ответа.
    """
    response = JSONResponse(content={
        "message": "Добро пожаловать! Ваши заголовки успешно обработаны.",
        "headers": {
            "User-Agent": user_agent,
            "Accept-Language": accept_language
        }
    })
    response.headers["X-Server-Time"] = datetime.now(timezone.utc).isoformat()
    return response

# ---------- Дополнительно: корень для проверки ----------
@app.get("/")
async def root():
    return {
        "message": "Server Technologies Control Work #2",
        "endpoints": [
            "/create_user (POST)",
            "/product/{product_id} (GET)",
            "/products/search?keyword=&category=&limit= (GET)",
            "/login-simple (POST) - for task 5.1",
            "/user (GET) - for task 5.1",
            "/login (POST) - for task 5.2",
            "/profile (GET) - for task 5.2",
            "/login-extended (POST) - for task 5.3",
            "/profile-extended (GET) - for task 5.3",
            "/headers (GET) - for task 5.4",
            "/info (GET) - for task 5.4"
        ]
    }