"""Multi-party threshold consensus test suite."""

from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
import pytest
from backend.tests.conftest import create_user_and_login


@pytest.mark.asyncio
async def test_consensus_quorum_threshold(async_client: AsyncClient):
    admin_auth = await create_user_and_login(async_client, "setter_consensus", "EXAM_SETTER")
    g1_auth = await create_user_and_login(async_client, "g1_consensus", "KEY_GUARDIAN")
    g2_auth = await create_user_and_login(async_client, "g2_consensus", "KEY_GUARDIAN")

    now = datetime.now(timezone.utc)

    # 1. Create Exam (k=2, n=2)
    exam_payload = {
        "title": "Mathematics Midterm 2026",
        "course_code": "MATH-201",
        "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(hours=2)).isoformat(),
        "required_quorum": 2,
        "total_guardians": 2,
    }
    exam_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=admin_auth["headers"])
    exam_id = exam_res.json()["id"]

    # 2. Assign guardians
    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1_auth["user_id"], "public_key_fingerprint": "FP_G1_MATH"},
        headers=admin_auth["headers"],
    )
    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2_auth["user_id"], "public_key_fingerprint": "FP_G2_MATH"},
        headers=admin_auth["headers"],
    )

    # 3. Stage payload
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": ["Q2h1bmsx", "Q2h1azI="], "ttl_seconds": 1800},
        headers=admin_auth["headers"],
    )

    # Check status before approvals
    status_res = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=admin_auth["headers"])
    assert status_res.json()["current_approvals_count"] == 0
    assert status_res.json()["quorum_reached"] is False

    # 4. Guardian 1 approves
    share_token_1 = f"MOCK_SHARE_K2_N2_IDX1_HASH12345678_{g1_auth['user_id']}"
    app1_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": share_token_1},
        headers=g1_auth["headers"],
    )
    assert app1_res.status_code == 200
    assert app1_res.json()["current_quorum_count"] == 1
    assert app1_res.json()["quorum_reached"] is False
    assert app1_res.json()["new_exam_status"] == "CONSENSUS_PENDING"

    # 5. Guardian 2 approves (Quorum threshold k=2 reached!)
    share_token_2 = f"MOCK_SHARE_K2_N2_IDX2_HASH12345678_{g2_auth['user_id']}"
    app2_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": share_token_2},
        headers=g2_auth["headers"],
    )
    assert app2_res.status_code == 200
    assert app2_res.json()["current_quorum_count"] == 2
    assert app2_res.json()["quorum_reached"] is True
    assert app2_res.json()["new_exam_status"] in ["AUTHORIZED", "UNLOCKED"]
