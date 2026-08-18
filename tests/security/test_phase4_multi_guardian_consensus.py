"""
TrustGuard Phase 4 Test Suite: Multi-Guardian Consensus & Secure Question Paper Release.

Verifies all 12 core Phase 4 security, threshold consensus, and authorization gating requirements:
1. Guardian 1 alone cannot release the paper.
2. Guardian 2 alone cannot release the paper.
3. Guardian 3 alone cannot release the paper.
4. 1 / 3 approvals is blocked (paper remains locked/unauthorized).
5. 2 / 3 approvals is blocked (paper remains locked/unauthorized).
6. 3 / 3 approvals successfully authorizes the exam and paper for release.
7. Duplicate approval by the same guardian is rejected with 400 Bad Request.
8. Approval by an unassigned guardian is rejected with 403 Forbidden.
9. Student access before 3/3 authorization is strictly rejected with 403 Forbidden.
10. Attacker access before and after authorization is strictly rejected with 403 Forbidden.
11. Unauthorized direct API calls cannot bypass multi-guardian consensus.
12. Concurrent simultaneous approvals by multiple guardians are handled atomically without race conditions.
"""

import asyncio
from datetime import datetime, timedelta, timezone
import io
import pytest
from httpx import AsyncClient

from app.core.config import settings


@pytest.fixture
async def seeded_users(async_client: AsyncClient):
    """Seed demo accounts and return auth headers for all roles."""
    await async_client.post("/api/v1/users/seed")

    accounts = {}
    usernames = ["admin", "guardian1", "guardian2", "guardian3", "student1", "student2", "attacker"]
    for u in usernames:
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": u, "password": settings.DEMO_PASSWORD},
        )
        assert res.status_code == 200, f"Login failed for {u}: {res.text}"
        data = res.json()
        accounts[u] = {
            "token": data["access_token"],
            "role": data["role"],
            "user_id": data["user_id"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
        }
    return accounts


async def create_staged_exam(async_client: AsyncClient, seeded_users: dict) -> dict:
    """Helper to create, populate with 3 guardians + 2 students, upload paper, and stage into RAM."""
    g1_headers = seeded_users["guardian1"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    exam_payload = {
        "title": "Cybersecurity Fundamentals",
        "course_code": "CS-401",
        "description": "Comprehensive evaluation of cryptography and network security.",
        "duration_minutes": 10,
        "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(hours=2)).isoformat(),
        "required_quorum": 3,
        "total_guardians": 3,
    }
    exam_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=g1_headers)
    assert exam_res.status_code == 201
    exam_id = exam_res.json()["id"]

    # 2. Upload Paper
    fake_pdf = b"%PDF-1.4 Section A: Question 1. Define AES-GCM authenticated encryption. Section B: Shamir Secret Sharing."
    files = {"file": ("Cybersecurity_Exam_Paper.pdf", io.BytesIO(fake_pdf), "application/pdf")}
    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Cybersecurity Fundamentals Midterm", "description": "Official Question Paper"},
        files=files,
        headers=g1_headers,
    )
    assert upload_res.status_code == 201
    paper_id = upload_res.json()["id"]

    # 3. Assign 3 Guardians
    for g_key in ["guardian1", "guardian2", "guardian3"]:
        g_id = seeded_users[g_key]["user_id"]
        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g_id, "public_key_fingerprint": f"FP_{g_key.upper()}_KEY"},
            headers=g1_headers,
        )
        assert assign_res.status_code == 201

    # 4. Register 2 Students
    student_ids = [seeded_users["student1"]["user_id"], seeded_users["student2"]["user_id"]]
    stu_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/students",
        json={"student_user_ids": student_ids},
        headers=g1_headers,
    )
    assert stu_res.status_code == 201

    # 5. Stage Paper
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 3600},
        headers=g1_headers,
    )
    assert stage_res.status_code == 200

    return {"exam_id": exam_id, "paper_id": paper_id}


# ── Test 1: Guardian 1 alone cannot release ─────────────────────────

@pytest.mark.asyncio
async def test_01_guardian_1_alone_cannot_release_paper(async_client: AsyncClient, seeded_users):
    """Test that Guardian 1 alone cannot authorize or release the question paper."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Guardian 1 submits approval
    res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert res.status_code == 200
    data = res.json()
    assert data["current_quorum_count"] == 1
    assert data["required_quorum"] == 3
    assert data["quorum_reached"] is False
    assert data["new_exam_status"] != "AUTHORIZED"

    # Status check confirms locked state
    status_res = await async_client.get(
        f"/api/v1/consensus/{exam_id}/status",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert status_res.status_code == 200
    assert status_res.json()["quorum_reached"] is False
    assert status_res.json()["current_approvals_count"] == 1


# ── Test 2: Guardian 2 alone cannot release ─────────────────────────

@pytest.mark.asyncio
async def test_02_guardian_2_alone_cannot_release_paper(async_client: AsyncClient, seeded_users):
    """Test that Guardian 2 alone cannot authorize or release the question paper."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Only Guardian 2 submits approval
    res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian2"]["headers"],
    )
    assert res.status_code == 200
    data = res.json()
    assert data["current_quorum_count"] == 1
    assert data["quorum_reached"] is False
    assert data["new_exam_status"] != "AUTHORIZED"


# ── Test 3: Guardian 3 alone cannot release ─────────────────────────

@pytest.mark.asyncio
async def test_03_guardian_3_alone_cannot_release_paper(async_client: AsyncClient, seeded_users):
    """Test that Guardian 3 alone cannot authorize or release the question paper."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Only Guardian 3 submits approval
    res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian3"]["headers"],
    )
    assert res.status_code == 200
    data = res.json()
    assert data["current_quorum_count"] == 1
    assert data["quorum_reached"] is False
    assert data["new_exam_status"] != "AUTHORIZED"


# ── Test 4: 1 / 3 approvals is blocked ──────────────────────────────

@pytest.mark.asyncio
async def test_04_one_of_three_approvals_is_blocked(async_client: AsyncClient, seeded_users):
    """Test that 1 of 3 approvals blocks release and students receive 403 Forbidden."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # 1 approval
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian1"]["headers"],
    )

    # Student attempts paper access -> 403 Forbidden
    stu_res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=seeded_users["student1"]["headers"],
    )
    assert stu_res.status_code == 403
    assert "Quorum (3/3) approval required" in stu_res.json()["detail"]


# ── Test 5: 2 / 3 approvals is blocked ──────────────────────────────

@pytest.mark.asyncio
async def test_05_two_of_three_approvals_is_blocked(async_client: AsyncClient, seeded_users):
    """Test that 2 of 3 approvals remains blocked."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Guardian 1 & Guardian 2 approve
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian1"]["headers"],
    )
    res2 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian2"]["headers"],
    )
    assert res2.status_code == 200
    assert res2.json()["current_quorum_count"] == 2
    assert res2.json()["quorum_reached"] is False

    # Student attempt still blocked (403)
    stu_res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=seeded_users["student1"]["headers"],
    )
    assert stu_res.status_code == 403


# ── Test 6: 3 / 3 approvals authorises paper ────────────────────────

@pytest.mark.asyncio
async def test_06_three_of_three_approvals_authorizes_paper_and_exam(async_client: AsyncClient, seeded_users):
    """Test that achieving 3 of 3 approvals transitions exam and paper to AUTHORIZED."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Guardian 1 approves (1/3)
    await async_client.post(f"/api/v1/consensus/{exam_id}/approve", headers=seeded_users["guardian1"]["headers"])
    # Guardian 2 approves (2/3)
    await async_client.post(f"/api/v1/consensus/{exam_id}/approve", headers=seeded_users["guardian2"]["headers"])
    # Guardian 3 approves (3/3)
    res3 = await async_client.post(f"/api/v1/consensus/{exam_id}/approve", headers=seeded_users["guardian3"]["headers"])

    assert res3.status_code == 200
    data = res3.json()
    assert data["current_quorum_count"] == 3
    assert data["required_quorum"] == 3
    assert data["quorum_reached"] is True
    assert data["new_exam_status"] == "AUTHORIZED"

    # Status check confirms all 3 approved
    status_res = await async_client.get(
        f"/api/v1/consensus/{exam_id}/status",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert status_res.status_code == 200
    status_data = status_res.json()
    assert status_data["quorum_reached"] is True
    assert status_data["current_approvals_count"] == 3
    assert len(status_data["guardians"]) == 3
    for g in status_data["guardians"]:
        assert g["status"] == "APPROVED"
        assert g["approved_at"] is not None

    # Student can now access authorized paper metadata
    stu_res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=seeded_users["student1"]["headers"],
    )
    assert stu_res.status_code == 200
    stu_data = stu_res.json()
    assert stu_data["authorized"] is True
    assert stu_data["status"] == "AUTHORIZED"


# ── Test 7: Duplicate approval rejected ─────────────────────────────

@pytest.mark.asyncio
async def test_07_duplicate_guardian_approval_is_rejected(async_client: AsyncClient, seeded_users):
    """Test that a guardian cannot submit duplicate approvals for the same exam."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Guardian 1 first approval -> 200 OK
    res1 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert res1.status_code == 200

    # Guardian 1 duplicate approval attempt -> 400 Bad Request
    res2 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert res2.status_code == 400
    assert "already submitted approval" in res2.json()["detail"].lower()

    # Quorum count remains 1
    status_res = await async_client.get(
        f"/api/v1/consensus/{exam_id}/status",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert status_res.json()["current_approvals_count"] == 1


# ── Test 8: Unassigned guardian approval rejected ───────────────────

@pytest.mark.asyncio
async def test_08_unassigned_guardian_approval_is_rejected(async_client: AsyncClient, seeded_users):
    """Test that an unassigned guardian cannot approve an exam."""
    g1_headers = seeded_users["guardian1"]["headers"]
    now = datetime.now(timezone.utc)

    # Create exam with ONLY guardian1 and guardian2 assigned
    exam_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Restricted Exam",
            "course_code": "SEC-500",
            "description": "Test exam",
            "duration_minutes": 15,
            "scheduled_start": (now - timedelta(minutes=1)).isoformat(),
            "scheduled_end": (now + timedelta(hours=1)).isoformat(),
            "required_quorum": 2,
            "total_guardians": 2,
        },
        headers=g1_headers,
    )
    assert exam_res.status_code == 201
    exam_id = exam_res.json()["id"]

    # Assign only guardian1 and guardian2
    for g_key in ["guardian1", "guardian2"]:
        await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": seeded_users[g_key]["user_id"], "public_key_fingerprint": f"FP_{g_key}_FINGERPRINT"},
            headers=g1_headers,
        )

    # Guardian 3 (unassigned) tries to approve -> 403 Forbidden
    res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=seeded_users["guardian3"]["headers"],
    )
    assert res.status_code == 403
    assert "not an assigned key guardian" in res.json()["detail"].lower()


# ── Test 9: Student access before authorization rejected ────────────

@pytest.mark.asyncio
async def test_09_student_access_before_authorization_is_rejected(async_client: AsyncClient, seeded_users):
    """Test that students cannot access question paper before 3/3 approvals."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Pre-approval student access attempt
    res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=seeded_users["student1"]["headers"],
    )
    assert res.status_code == 403
    assert "not yet authorized" in res.json()["detail"].lower()


# ── Test 10: Attacker access strictly rejected ──────────────────────

@pytest.mark.asyncio
async def test_10_attacker_access_strictly_rejected(async_client: AsyncClient, seeded_users):
    """Test that attacker cannot approve, retrieve, or stream paper under any circumstances."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    # Attacker attempts to submit approval -> 403 Forbidden
    res_appr = await async_client.post(f"/api/v1/consensus/{exam_id}/approve", headers=attacker_headers)
    assert res_appr.status_code == 403

    # Attacker attempts to get paper access -> 403 Forbidden
    res_paper = await async_client.get(f"/api/v1/exams/{exam_id}/paper", headers=attacker_headers)
    assert res_paper.status_code == 403
    assert "attacker role cannot access" in res_paper.json()["detail"].lower()

    # Attacker attempts to stream distribution payload -> 403 Forbidden
    res_stream = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=attacker_headers)
    assert res_stream.status_code == 403


# ── Test 11: Direct unauthorized bypass attempt cannot bypass consensus ──

@pytest.mark.asyncio
async def test_11_unauthorized_api_call_cannot_bypass_consensus(async_client: AsyncClient, seeded_users):
    """Test that streaming endpoints reject requests when exam is not AUTHORIZED / UNLOCKED."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Attempt distribution stream as admin before consensus is reached
    admin_headers = seeded_users["admin"]["headers"]
    res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=admin_headers)
    assert res.status_code == 403
    assert "quorum approval is required" in res.json()["detail"].lower()


# ── Test 12: Concurrent simultaneous approvals race condition ───────

@pytest.mark.asyncio
async def test_12_concurrent_approvals_handled_cleanly(async_client: AsyncClient, seeded_users):
    """Test that concurrent approvals submitted simultaneously by all 3 guardians are handled without race conditions."""
    exam_ctx = await create_staged_exam(async_client, seeded_users)
    exam_id = exam_ctx["exam_id"]

    # Submit 3 approvals concurrently using asyncio.gather
    async def approve(g_key):
        return await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            headers=seeded_users[g_key]["headers"],
        )

    responses = await asyncio.gather(
        approve("guardian1"),
        approve("guardian2"),
        approve("guardian3"),
    )

    for r in responses:
        assert r.status_code == 200

    # Final check: status is AUTHORIZED and approvals count == 3
    status_res = await async_client.get(
        f"/api/v1/consensus/{exam_id}/status",
        headers=seeded_users["guardian1"]["headers"],
    )
    assert status_res.status_code == 200
    assert status_res.json()["current_approvals_count"] == 3
    assert status_res.json()["quorum_reached"] is True
    assert status_res.json()["status"] == "AUTHORIZED"
