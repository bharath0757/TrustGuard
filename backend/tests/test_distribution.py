"""Ephemeral Distribution and Purge test suite."""

from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
import pytest
from tests.test_exams import create_user_and_login


@pytest.mark.asyncio
async def test_ephemeral_jit_distribution_flow(async_client: AsyncClient):
    admin_auth = await create_user_and_login(async_client, "setter_dist", "EXAM_SETTER")
    g1_auth = await create_user_and_login(async_client, "g1_dist", "KEY_GUARDIAN")
    center_auth = await create_user_and_login(async_client, "center_001", "EXAM_CENTER")

    now = datetime.now(timezone.utc)

    # 1. Create Exam (k=1, n=1)
    exam_payload = {
        "title": "Physics Special Exam 2026",
        "course_code": "PHYS-101",
        "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(hours=1)).isoformat(),
        "required_quorum": 1,
        "total_guardians": 1,
    }
    exam_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=admin_auth["headers"])
    exam_id = exam_res.json()["id"]

    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1_auth["user_id"], "public_key_fingerprint": "FP_PHYSICS"},
        headers=admin_auth["headers"],
    )

    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": ["SGVsbG8gUGh5c2ljcw=="], "ttl_seconds": 1800},
        headers=admin_auth["headers"],
    )

    # 2. Try streaming BEFORE quorum unlock -> Should return 403 Forbidden
    stream_fail = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center_auth["headers"])
    assert stream_fail.status_code == 403

    # 3. Guardian 1 approves -> Unlocks exam (k=1)
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K1_N1_IDX1_HASH12345678_{g1_auth['user_id']}"},
        headers=g1_auth["headers"],
    )

    # 4. Stream question paper -> Should return 200 OK with streamed chunk content
    stream_ok = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center_auth["headers"])
    assert stream_ok.status_code == 200
    assert "no-store" in stream_ok.headers["cache-control"]
    content = stream_ok.content
    assert b"[TRUSTGUARD_TRACEABILITY:CENTER=" in content
    assert b"Hello Physics" in content

    # 5. Purge Ephemeral Memory Buffer
    purge_res = await async_client.post(f"/api/v1/distribution/{exam_id}/purge", headers=admin_auth["headers"])
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True

    # 6. Stream after purge -> Should return 410 Gone (RAM cleared)
    stream_after_purge = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream", headers=center_auth["headers"]
    )
    assert stream_after_purge.status_code == 410
