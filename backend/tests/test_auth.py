"""Authentication API test suite."""

from httpx import AsyncClient
import pytest


@pytest.mark.asyncio
async def test_root_and_health(async_client: AsyncClient):
    res_root = await async_client.get("/")
    assert res_root.status_code == 200
    assert res_root.json() == {"message": "Welcome to TrustGuard API", "status": "online"}

    res_health = await async_client.get("/health")
    assert res_health.status_code == 200
    assert res_health.json()["status"] == "healthy"
    assert res_health.json()["database"] == "connected"


@pytest.mark.asyncio
async def test_register_and_login_flow(async_client: AsyncClient):
    # Register user
    reg_payload = {
        "username": "admin_user",
        "email": "admin@trustguard.org",
        "password": "SecurePassword123",
        "role": "ADMIN",
    }
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    user_data = reg_res.json()
    assert user_data["username"] == "admin_user"
    assert user_data["role"] == "ADMIN"
    assert "id" in user_data

    # Login user
    login_payload = {"username": "admin_user", "password": "SecurePassword123"}
    login_res = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["role"] == "ADMIN"

    # Get /auth/me with Bearer token
    headers = {"Authorization": f"Bearer {token_data['access_token']}"}
    me_res = await async_client.get("/api/v1/auth/me", headers=headers)
    assert me_res.status_code == 200
    assert me_res.json()["username"] == "admin_user"


@pytest.mark.asyncio
async def test_login_invalid_credentials(async_client: AsyncClient):
    login_payload = {"username": "non_existent", "password": "WrongPassword"}
    res = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert res.status_code == 401
