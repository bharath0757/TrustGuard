"""Pytest configuration and async test fixtures."""

from typing import AsyncGenerator
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from app.db.database import get_db
from app.db.models import Base
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
async def setup_db():
    """Create clean database schema before each test."""
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def override_get_db() -> AsyncGenerator[AsyncSession, None]:
    """Override database dependency with test session."""
    async with TestingSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


@pytest.fixture
async def async_client() -> AsyncGenerator[AsyncClient, None]:
    """Async HTTP client targeting FastAPI application."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        yield client
