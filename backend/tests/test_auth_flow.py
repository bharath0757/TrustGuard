"""End-to-end authentication and user management test suite."""

from httpx import AsyncClient
import pytest


@pytest.mark.asyncio
async def test_auth_full_lifecycle(async_client: AsyncClient):
    """Test full auth sequence: Register -> Login -> Me -> Rejection cases."""
    # 1. Register new user
    reg_payload = {
        "username": "prof_alice",
        "email": "alice@university.edu",
        "password": "SuperSecretPassword123!",
        "role": "EXAM_SETTER",
    }
    reg_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201, f"Registration failed: {reg_res.text}"
    user_data = reg_res.json()
    assert user_data["username"] == "prof_alice"
    assert user_data["email"] == "alice@university.edu"
    assert user_data["role"] == "EXAM_SETTER"
    assert "id" in user_data

    # 2. Login with valid credentials
    login_payload = {
        "username": "prof_alice",
        "password": "SuperSecretPassword123!",
    }
    login_res = await async_client.post("/api/v1/auth/login", json=login_payload)
    assert login_res.status_code == 200, f"Login failed: {login_res.text}"
    token_data = login_res.json()
    assert "access_token" in token_data
    assert token_data["token_type"] == "bearer"
    assert token_data["role"] == "EXAM_SETTER"
    token = token_data["access_token"]

    # 3. Access /auth/me with JWT bearer token
    me_res = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200, f"Get me failed: {me_res.text}"
    me_data = me_res.json()
    assert me_data["username"] == "prof_alice"
    assert me_data["email"] == "alice@university.edu"
    assert me_data["role"] == "EXAM_SETTER"

    # 4. Duplicate registration rejection
    dup_res = await async_client.post("/api/v1/auth/register", json=reg_payload)
    assert dup_res.status_code == 400
    assert "already exists" in dup_res.json()["detail"].lower()

    # 5. Invalid password login rejection
    bad_login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "prof_alice", "password": "WrongPassword999!"},
    )
    assert bad_login_res.status_code == 401
    assert "invalid username or password" in bad_login_res.json()["detail"].lower()
