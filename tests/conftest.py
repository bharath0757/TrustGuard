"""
Shared pytest configuration and fixtures for TrustGuard test suites.

Ensures:
1. Both project root (D:\\TrustGuard) and backend root (D:\\TrustGuard\\backend) are on sys.path.
2. In-memory async SQLite engine is used for fast and clean test isolation.
3. Database tables are recreated per test and ephemeral RAM store is cleared.
4. FastAPI async HTTP client fixture is available across all integration tests.
"""

import os
import sys
from typing import AsyncGenerator
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine

# Path configuration
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

BACKEND_ROOT = os.path.join(PROJECT_ROOT, "backend")
if BACKEND_ROOT not in sys.path:
    sys.path.insert(0, BACKEND_ROOT)

from app.db.database import get_db as app_get_db
from app.db.models import Base as AppBase
from app.db.ephemeral import get_ephemeral_store
from main import app

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


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Create clean database schema and reset ephemeral store before each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(AppBase.metadata.drop_all)
        await conn.run_sync(AppBase.metadata.create_all)

    # Clean in-memory ephemeral store
    ephemeral = get_ephemeral_store()
    ephemeral.memory_fallback._store.clear()

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(AppBase.metadata.drop_all)

    ephemeral.memory_fallback._store.clear()


async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    """Override FastAPI database dependency with test session."""
    async with TestingSessionLocal() as session:
        yield session


app.dependency_overrides[app_get_db] = override_get_db


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client targeting FastAPI application for integration testing."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
