"""Exam management and ephemeral staging test suite."""

from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
import pytest


async def create_user_and_login(client: AsyncClient, username: str, role: str) -> dict:
    reg_payload = {
        "username": username,
        "email": f"{username}@trustguard.org",
        "password": "Password123!",
        "role": role,
    }
    await client.post("/api/v1/auth/register", json=reg_payload)
    login_res = await client.post("/api/v1/auth/login", json={"username": username, "password": "Password123!"})
    token = login_res.json()["access_token"]
    user_id = login_res.json()["user_id"]
    return {"headers": {"Authorization": f"Bearer {token}"}, "user_id": user_id}


@pytest.mark.asyncio
async def test_create_and_stage_exam(async_client: AsyncClient):
    admin_auth = await create_user_and_login(async_client, "exam_setter_1", "EXAM_SETTER")
    g1 = await create_user_and_login(async_client, "guardian_1", "KEY_GUARDIAN")
    g2 = await create_user_and_login(async_client, "guardian_2", "KEY_GUARDIAN")

    now = datetime.now(timezone.utc)
    start_time = (now - timedelta(minutes=5)).isoformat()
    end_time = (now + timedelta(hours=2)).isoformat()

    # 1. Create Exam (k=2, n=2)
    exam_payload = {
        "title": "Computer Science Final 2026",
        "course_code": "CS-401",
        "scheduled_start": start_time,
        "scheduled_end": end_time,
        "required_quorum": 2,
        "total_guardians": 2,
    }
    create_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=admin_auth["headers"])
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]
    assert exam["status"] == "DRAFT"
    assert exam["required_quorum"] == 2

    # 2. Assign Guardians
    g1_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "FINGERPRINT_G1_KEY_9999"},
        headers=admin_auth["headers"],
    )
    assert g1_assign.status_code == 201

    g2_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "FINGERPRINT_G2_KEY_8888"},
        headers=admin_auth["headers"],
    )
    assert g2_assign.status_code == 201

    # 3. Stage Encrypted Payload into RAM
    stage_payload = {
        "encrypted_chunks": ["SGVsbG8gV29ybGQgQ2h1bmsgMQ==", "SGVsbG8gV29ybGQgQ2h1bmsgMg=="],
        "ttl_seconds": 1800,
    }
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json=stage_payload,
        headers=admin_auth["headers"],
    )
    assert stage_res.status_code == 200
    staged = stage_res.json()
    assert staged["status"] == "CONSENSUS_PENDING"
    assert staged["chunks_staged"] == 2
    assert "encrypted_payload_hash" in staged
