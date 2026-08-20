"""Pytest configuration and async test fixtures for backend test suite."""

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

import app.db.database as db_module
from app.db.database import get_db as app_get_db
from app.db.models import Base as AppBase
from backend.main import app

# Test database URL (SQLite shared in-memory for clean cross-client test isolation)
TEST_DATABASE_URL = "sqlite+aiosqlite:///file:memdb_backend_test?mode=memory&cache=shared&uri=true"

test_engine = create_async_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False, "uri": True},
)

TestingSessionLocal = async_sessionmaker(
    bind=test_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
)

# Bind test session and engine to database module for test execution
db_module.AsyncSessionLocal = TestingSessionLocal
db_module.engine = test_engine


@pytest.fixture(autouse=True)
async def setup_test_db():
    """Create clean database schema before each test and clean up after."""
    async with test_engine.begin() as conn:
        await conn.run_sync(AppBase.metadata.drop_all)
        await conn.run_sync(AppBase.metadata.create_all)

    yield

    async with test_engine.begin() as conn:
        await conn.run_sync(AppBase.metadata.drop_all)


async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    """Override FastAPI database dependency with test session."""
    async with TestingSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()


app.dependency_overrides[app_get_db] = override_get_db


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client targeting FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
