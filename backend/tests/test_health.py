"""API health and Vercel routing test suite."""

from httpx import AsyncClient
import pytest


@pytest.mark.asyncio
async def test_root_and_health_endpoints(async_client: AsyncClient):
    # Test GET /
    res_root = await async_client.get("/")
    assert res_root.status_code == 200
    assert res_root.json()["status"] == "online"

    # Test GET /health
    res_health = await async_client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "ok"

    # Test GET /api/health (Vercel routed path)
    res_api_health = await async_client.get("/api/health")
    assert res_api_health.status_code == 200
    assert res_api_health.json()["status"] == "ok"
