"""Test helper functions for TrustGuard backend test suites."""

from typing import Any, Dict
from httpx import AsyncClient


async def create_user_and_login(
    client: AsyncClient,
    username: str,
    role: str,
    password: str = "SecurePassword123!",
) -> Dict[str, Any]:
    """Helper to register a user and immediately log in, returning tokens and headers."""
    email = f"{username.lower().replace('_', '')}@example.com"
    reg_payload = {
        "username": username,
        "email": email,
        "password": password,
        "role": role,
    }
    reg_res = await client.post("/api/v1/auth/register", json=reg_payload)
    if reg_res.status_code not in (200, 201):
        # If user already exists, proceed to login
        pass

    login_res = await client.post(
        "/api/v1/auth/login",
        json={"username": username, "password": password},
    )
    assert login_res.status_code == 200, f"Login failed for {username}: status={login_res.status_code} body={login_res.text} reg_status={reg_res.status_code} reg_text={reg_res.text}"
    token_data = login_res.json()
    token = token_data["access_token"]

    return {
        "user_id": token_data.get("user_id"),
        "username": username,
        "email": email,
        "role": token_data.get("role", role),
        "access_token": token,
        "token": token,
        "headers": {"Authorization": f"Bearer {token}"},
    }
