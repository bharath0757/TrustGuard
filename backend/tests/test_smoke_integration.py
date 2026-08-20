"""Comprehensive End-to-End API Smoke & Integration Test Suite.

Simulates complete Zero-Trust Examination Lifecycle:
1. Multi-role Authentication (Admin, Setter, Guardians, Center, Auditor)
2. Exam Metadata Creation, Retrieval, & Guardian Assignment
3. Encrypted Payload Staging into Ephemeral RAM
4. Multi-Party Consensus & Threshold Quorum Approval (k-of-n)
5. Ephemeral JIT Question-Paper Streaming & Dynamic Watermarking
6. Ephemeral RAM Purge & Closed State Validation
7. Comprehensive Audit Log Traceability
"""

from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
import pytest
try:
    from backend.tests.helpers import create_user_and_login
except ImportError:
    from helpers import create_user_and_login


@pytest.mark.asyncio
async def test_complete_trustguard_api_smoke_flow(async_client: AsyncClient):
    # ---------------------------------------------------------
    # 1. AUTHENTICATION & ROLE REGISTRATION
    # ---------------------------------------------------------
    admin = await create_user_and_login(async_client, "smoke_admin", "ADMIN")
    setter = await create_user_and_login(async_client, "smoke_setter", "EXAM_SETTER")
    g1 = await create_user_and_login(async_client, "smoke_g1", "KEY_GUARDIAN")
    g2 = await create_user_and_login(async_client, "smoke_g2", "KEY_GUARDIAN")
    center = await create_user_and_login(async_client, "smoke_center", "EXAM_CENTER")
    auditor = await create_user_and_login(async_client, "smoke_auditor", "AUDITOR")

    # Verify user profile retrieval
    me_res = await async_client.get("/api/v1/auth/me", headers=setter["headers"])
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "EXAM_SETTER"

    # ---------------------------------------------------------
    # 2. EXAM CREATION, RETRIEVAL, AND LISTING
    # ---------------------------------------------------------
    now = datetime.now(timezone.utc)
    exam_payload = {
        "title": "National Engineering Entrance 2026 - Physics",
        "course_code": "PHY-2026-NEET",
        "scheduled_start": (now - timedelta(minutes=10)).isoformat(),
        "scheduled_end": (now + timedelta(hours=3)).isoformat(),
        "required_quorum": 2,  # k = 2
        "total_guardians": 2,  # n = 2
    }
    create_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=setter["headers"])
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]
    assert exam["status"] == "DRAFT"
    assert exam["encrypted_payload_hash"] is None

    # Retrieve specific exam
    get_res = await async_client.get(f"/api/v1/exams/{exam_id}", headers=admin["headers"])
    assert get_res.status_code == 200
    assert get_res.json()["title"] == "National Engineering Entrance 2026 - Physics"

    # List all exams
    list_res = await async_client.get("/api/v1/exams/", headers=auditor["headers"])
    assert list_res.status_code == 200
    exam_ids = [e["id"] for e in list_res.json()]
    assert exam_id in exam_ids

    # ---------------------------------------------------------
    # 3. GUARDIAN ASSIGNMENTS & PAYLOAD STAGING
    # ---------------------------------------------------------
    # Assign Guardian 1
    g1_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1_SMOKE"},
        headers=setter["headers"],
    )
    assert g1_assign.status_code == 201

    # Assign Guardian 2
    g2_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "RSA_4096_FP_G2_SMOKE"},
        headers=setter["headers"],
    )
    assert g2_assign.status_code == 201

    # Stage Encrypted Payload Chunks (Dummy encrypted Base64 strings)
    dummy_chunks = [
        "RUMxX0RVTU1ZX0VOQ1JZUFRFRF9DSEVDS1NVTV9QQVBFUl9DSEVOSzE=",  # Chunk 1
        "RUMxX0RVTU1ZX0VOQ1JZUFRFRF9DSEVDS1NVTV9QQVBFUl9DSEVOSzI=",  # Chunk 2
    ]
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": dummy_chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200
    staged = stage_res.json()
    assert staged["status"] == "CONSENSUS_PENDING"
    assert staged["chunks_staged"] == 2
    assert staged["encrypted_payload_hash"] is not None

    # ---------------------------------------------------------
    # 4. MULTI-PARTY CONSENSUS & APPROVAL FLOW (k=2 of n=2)
    # ---------------------------------------------------------
    # Quorum status check before approvals
    status_before = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
    assert status_before.json()["current_approvals_count"] == 0
    assert status_before.json()["quorum_reached"] is False

    # Attempt stream before unlock -> 403 Forbidden
    early_stream = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
    assert early_stream.status_code == 403

    # Guardian 1 submits approval
    g1_token = f"MOCK_SHARE_K2_N2_IDX1_HASH12345678_{g1['user_id']}"
    app1_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": g1_token},
        headers=g1["headers"],
    )
    assert app1_res.status_code == 200
    assert app1_res.json()["current_quorum_count"] == 1
    assert app1_res.json()["quorum_reached"] is False

    # Guardian 2 submits approval -> Reaches Quorum k=2! State updates to UNLOCKED
    g2_token = f"MOCK_SHARE_K2_N2_IDX2_HASH12345678_{g2['user_id']}"
    app2_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": g2_token},
        headers=g2["headers"],
    )
    assert app2_res.status_code == 200
    assert app2_res.json()["current_quorum_count"] == 2
    assert app2_res.json()["quorum_reached"] is True
    assert app2_res.json()["new_exam_status"] in ["AUTHORIZED", "UNLOCKED"]

    # ---------------------------------------------------------
    # 5. EPHEMERAL JIT DISTRIBUTION STREAMING
    # ---------------------------------------------------------
    stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
    assert stream_res.status_code == 200
    assert "no-store" in stream_res.headers["cache-control"]
    streamed_content = stream_res.content

    # Verify watermarked content received in memory stream
    assert b"[TRUSTGUARD_TRACEABILITY:CENTER=" in streamed_content

    # ---------------------------------------------------------
    # 6. EPHEMERAL RAM PURGE & CLOSED STATE
    # ---------------------------------------------------------
    purge_res = await async_client.post(f"/api/v1/distribution/{exam_id}/purge", headers=admin["headers"])
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True
    assert purge_res.json()["status"] == "COMPLETED"

    # Stream after purge -> Returns 410 Gone
    post_purge_stream = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"]
    )
    assert post_purge_stream.status_code == 410

    # ---------------------------------------------------------
    # 7. AUDIT TRAIL VERIFICATION
    # ---------------------------------------------------------
    # External client receipt event ingestion
    client_audit = await async_client.post(
        "/api/v1/audit/events",
        json={"exam_id": exam_id, "action": "RECEIPT_ACKNOWLEDGED_BY_CENTER"},
        headers=center["headers"],
    )
    assert client_audit.status_code == 201

    # Query all audit events for exam
    audit_logs_res = await async_client.get(
        f"/api/v1/audit/events?exam_id={exam_id}", headers=auditor["headers"]
    )
    assert audit_logs_res.status_code == 200
    events = audit_logs_res.json()
    actions = [e["action"] for e in events]

    assert "EXAM_CREATED" in actions
    assert "GUARDIAN_ASSIGNED" in actions
    assert "EPHEMERAL_PAYLOAD_STAGED" in actions
    assert "GUARDIAN_APPROVED" in actions
    assert "QUORUM_REACHED" in actions
    assert "EPHEMERAL_STREAM_ACCESSED" in actions
    assert "EPHEMERAL_DATA_PURGED" in actions
    assert "RECEIPT_ACKNOWLEDGED_BY_CENTER" in actions
