"""
TrustGuard Integration Test Suite: End-to-End System Health, Connectivity & Startup Validation.
"""

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from backend.app.db.database import get_db
from backend.app.db.models import Base
from backend.main import app
from security.crypto.key_manager import generate_master_key, get_master_key
from security.crypto.encryption import encrypt, decrypt
from security.crypto.integrity import generate_integrity_hash
import os


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
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield
    async with test_engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)


async def override_get_db():
    async with TestingSessionLocal() as session:
        yield session


app.dependency_overrides[get_db] = override_get_db


@pytest.mark.asyncio
async def test_health_endpoints():
    """Verify /health and /api/v1/health return 200 and healthy status without exposing secrets."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        res = await client.get("/health")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "healthy"
        assert data["service"] == "TrustGuard Backend API"
        assert data["database"] == "connected"
        assert "ephemeral_store" in data
        assert "password" not in str(data).lower()
        assert "secret" not in str(data).lower()

        v1_res = await client.get("/api/v1/health")
        assert v1_res.status_code == 200
        v1_data = v1_res.json()
        assert v1_data["status"] == "healthy"
        assert v1_data["database"] == "connected"


@pytest.mark.asyncio
async def test_crypto_engine_startup():
    """Verify cryptographic primitives initialize and execute authenticated encryption."""
    if not os.environ.get("TRUSTGUARD_MASTER_KEY"):
        os.environ["TRUSTGUARD_MASTER_KEY"] = generate_master_key()

    key = get_master_key()
    assert len(key) == 32

    raw_data = b"CONFIDENTIAL_EXAMINATION_QUESTION_PAPER_CONTENT"
    encrypted = encrypt(raw_data, key=key)
    decrypted = decrypt(encrypted, key=key)
    assert decrypted == raw_data

    h = generate_integrity_hash(raw_data)
    assert h.startswith("sha256:")
