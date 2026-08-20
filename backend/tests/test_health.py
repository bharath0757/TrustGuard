"""API health and Vercel routing test suite."""

import os
from httpx import AsyncClient
import pytest

from app.db.database import get_async_database_url


@pytest.mark.asyncio
async def test_root_and_health_endpoints(async_client: AsyncClient):
    # Test GET /
    res_root = await async_client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "online"

    # Test GET /health
    res_health = await async_client.get("/health")
    assert res_health.status_code == 200
    data_health = res_health.json()
    assert data_health["status"] == "healthy"
    assert data_health["database"] == "connected"

    # Test GET /api/health (Vercel routed path)
    res_api_health = await async_client.get("/api/health")
    assert res_api_health.status_code == 200
    assert res_api_health.json()["status"] == "healthy"
    assert res_api_health.json()["database"] == "connected"

    # Test GET /api/v1/health (Frontend System Health hook path)
    res_v1_health = await async_client.get("/api/v1/health")
    assert res_v1_health.status_code == 200
    data_v1 = res_v1_health.json()
    assert data_v1["status"] == "healthy"
    assert data_v1["database"] == "connected"
    assert "engine" in data_v1


def test_database_url_conversions():
    # 1. postgresql:// -> postgresql+asyncpg://
    pg_url = "postgresql://user:pass@ep-cool-db.aws.neon.tech/neondb"
    assert get_async_database_url(pg_url) == "postgresql+asyncpg://user:pass@ep-cool-db.aws.neon.tech/neondb"

    # 2. postgres:// -> postgresql+asyncpg://
    pg_legacy = "postgres://user:pass@host.supabase.co:5432/postgres"
    assert get_async_database_url(pg_legacy) == "postgresql+asyncpg://user:pass@host.supabase.co:5432/postgres"

    # 3. sqlite:// -> sqlite+aiosqlite://
    sq_url = "sqlite:///./trustguard.db"
    assert get_async_database_url(sq_url) == "sqlite+aiosqlite:///./trustguard.db"

    # 4. sqlite+aiosqlite:// stays intact
    sq_async = "sqlite+aiosqlite:///./trustguard.db"
    assert get_async_database_url(sq_async) == "sqlite+aiosqlite:///./trustguard.db"

    # 5. postgresql+asyncpg:// stays intact
    pg_async = "postgresql+asyncpg://user:pass@host/db"
    assert get_async_database_url(pg_async) == "postgresql+asyncpg://user:pass@host/db"

    # 6. sslmode conversion
    pg_ssl = "postgresql://user:pass@host/db?sslmode=require"
    assert "ssl=require" in get_async_database_url(pg_ssl)


def test_vercel_production_fail_fast_on_missing_postgres():
    # Simulate Vercel environment
    old_vercel = os.environ.get("VERCEL")
    try:
        os.environ["VERCEL"] = "1"
        with pytest.raises(RuntimeError, match="DATABASE_URL.*is missing or set to SQLite.*in Vercel production"):
            get_async_database_url("sqlite+aiosqlite:///./trustguard.db")
    finally:
        if old_vercel is None:
            os.environ.pop("VERCEL", None)
        else:
            os.environ["VERCEL"] = old_vercel
