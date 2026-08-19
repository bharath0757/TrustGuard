"""Pytest configuration and async test fixtures."""

import os
import sys
from typing import AsyncGenerator
from httpx import ASGITransport, AsyncClient
import pytest
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Ensure root and backend directory are in sys.path
root_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
backend_dir = os.path.join(root_dir, "backend")
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
if backend_dir not in sys.path:
    sys.path.insert(0, backend_dir)

from backend.main import app
from app.db.database import get_db, init_db
from app.db.models import Base

# Test database URL (SQLite in-memory for fast execution)
TEST_DATABASE_URL = "sqlite+aiosqlite:///:memory:"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)


async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    async with TestingSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Ensure in-memory database tables are initialized and dependency overridden."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    app.dependency_overrides[get_db] = override_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client targeting FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client


async def create_user_and_login(client: AsyncClient, username: str, role: str) -> dict:
    """Helper to create user and return auth headers."""
    reg_payload = {
        "username": username,
        "email": f"{username}@trustguard.org",
        "password": "Password123!",
        "role": role,
    }
    await client.post("/api/v1/auth/register", json=reg_payload)
    login_res = await client.post("/api/v1/auth/login", json={"username": username, "password": "Password123!"})
    data = login_res.json()
    token = data["access_token"]
    user_id = data["user_id"]
    return {"headers": {"Authorization": f"Bearer {token}"}, "user_id": user_id, "token": token}
