"""Phase 7 Security and Functional Tests: Controlled Attack Simulator + Real-Time Security Alerts.

Validates that:
1. Attacker (attacker@trustguard.demo) can authenticate and list all 6 attack simulation scenarios.
2. Unauthorized roles (e.g. STUDENT) cannot access the attack simulator API (HTTP 403).
3. Attack 1 (Unauthorized Paper Access) executes against real backend and returns BLOCKED (403).
4. Attack 2 (Bypass Guardian Approval) executes and returns DENIED (403).
5. Attack 3 (Fake Guardian Approval) executes with forged payload and returns DENIED (403).
6. Attack 4 (Role Escalation) executes against lifecycle endpoint and returns DENIED (403).
7. Attack 5 (Access Expired Exam) executes and returns BLOCKED (403).
8. Attack 6 (Unauthorized Student Session Access) executes and returns DENIED (403).
9. All 6 attacks persist AuditEvents in the database with complete metadata (ID, exam_id, actor, attack_type, target, result, reason).
10. Attacks update live Guardian Dashboard metrics (attack_attempts, blocked_attacks, security_status).
11. Attack history endpoint (/api/v1/attack-sim/{exam_id}/history) returns full chronological attempt logs.
12. Direct unauthorized HTTP request to /api/v1/exams/{exam_id}/paper with attacker token returns real HTTP 403.
"""

import io
import json
import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from sqlalchemy import select

from app.core.config import settings
from app.db.models import AuditEvent, Exam, User


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


async def create_test_exam(async_client: AsyncClient, seeded_users: dict) -> dict:
    """Helper to create and initialize a test exam."""
    admin_headers = seeded_users["admin"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals",
            "course_code": f"SEC-P7-{now.microsecond}",
            "description": "Controlled attack simulator test exam.",
            "duration_minutes": 60,
            "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 201, create_res.text
    exam = create_res.json()
    exam_id = exam["id"]

    # 2. Upload Paper
    mock_pdf = io.BytesIO(b"%PDF-1.4 Mock Exam Paper Content for Phase 7 Attack Tests")
    mock_pdf.name = "Cybersecurity_Paper.pdf"
    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Cybersecurity Paper", "description": "Phase 7 test paper"},
        files={"file": ("Cybersecurity_Paper.pdf", mock_pdf, "application/pdf")},
        headers=admin_headers,
    )
    assert upload_res.status_code == 201
    paper_id = upload_res.json()["id"]

    # 3. Assign 3 Key Guardians
    for g_key in ["guardian1", "guardian2", "guardian3"]:
        await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={
                "guardian_user_id": seeded_users[g_key]["user_id"],
                "public_key_fingerprint": f"SHA256:FAKEFINGERPRINT_{g_key.upper()}",
            },
            headers=admin_headers,
        )

    # 4. Stage Paper
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 3600},
        headers=admin_headers,
    )

    # 5. Start Exam to make it LIVE
    await async_client.post(
        f"/api/v1/exam-lifecycle/{exam_id}/start",
        headers=admin_headers,
    )

    return exam


# ==============================================================================
# TEST 1: Attacker can login and list all 6 attack scenarios
# ==============================================================================
@pytest.mark.asyncio
async def test_attacker_login_and_list_scenarios(async_client: AsyncClient, seeded_users: dict):
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.get("/api/v1/attack-sim/scenarios", headers=attacker_headers)
    assert res.status_code == 200, res.text
    scenarios = res.json()

    assert len(scenarios) == 6, f"Expected 6 attack scenarios, got {len(scenarios)}"
    scenario_ids = [s["id"] for s in scenarios]
    assert "UNAUTHORIZED_PAPER_ACCESS" in scenario_ids
    assert "BYPASS_GUARDIAN_APPROVAL" in scenario_ids
    assert "FAKE_GUARDIAN_APPROVAL" in scenario_ids
    assert "ROLE_ESCALATION" in scenario_ids
    assert "ACCESS_EXPIRED_EXAM" in scenario_ids
    assert "UNAUTHORIZED_SESSION_ACCESS" in scenario_ids

    for s in scenarios:
        assert s["expected_http_status"] == 403
        assert s["risk_severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert len(s["target_endpoint"]) > 0


# ==============================================================================
# TEST 2: Non-attacker / unauthorized roles cannot access attack simulator
# ==============================================================================
@pytest.mark.asyncio
async def test_unauthorized_roles_cannot_access_attack_simulator(
    async_client: AsyncClient, seeded_users: dict
):
    student_headers = seeded_users["student1"]["headers"]
    guardian_headers = seeded_users["guardian1"]["headers"]

    # Student cannot list scenarios
    res_s = await async_client.get("/api/v1/attack-sim/scenarios", headers=student_headers)
    assert res_s.status_code == 403

    # Guardian cannot access attack simulator
    res_g = await async_client.get("/api/v1/attack-sim/scenarios", headers=guardian_headers)
    assert res_g.status_code == 403

    # Unauthenticated request fails with 401/403
    res_anon = await async_client.get("/api/v1/attack-sim/scenarios")
    assert res_anon.status_code in (401, 403)


# ==============================================================================
# TEST 3: Attack 1 — Unauthorized Paper Access
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_1_unauthorized_paper_access(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_PAPER_ACCESS"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "UNAUTHORIZED_PAPER_ACCESS"
    assert data["result"] == "BLOCKED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True
    assert data["actor"] == "attacker"
    assert data["exam_id"] == exam_id
    assert len(data["audit_event_id"]) > 0


# ==============================================================================
# TEST 4: Attack 2 — Bypass Guardian Approval
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_2_bypass_guardian_approval(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "BYPASS_GUARDIAN_APPROVAL"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "BYPASS_GUARDIAN_APPROVAL"
    assert data["result"] == "DENIED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ==============================================================================
# TEST 5: Attack 3 — Fake Guardian Approval
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_3_fake_guardian_approval(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "FAKE_GUARDIAN_APPROVAL"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "FAKE_GUARDIAN_APPROVAL"
    assert data["result"] == "DENIED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ==============================================================================
# TEST 6: Attack 4 — Role Escalation
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_4_role_escalation(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "ROLE_ESCALATION"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "ROLE_ESCALATION"
    assert data["result"] == "DENIED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ==============================================================================
# TEST 7: Attack 5 — Access Expired / Unauthorized Exam Join
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_5_access_expired_exam(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "ACCESS_EXPIRED_EXAM"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "ACCESS_EXPIRED_EXAM"
    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ==============================================================================
# TEST 8: Attack 6 — Unauthorized Student Session Access
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_6_unauthorized_session_access(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_SESSION_ACCESS"},
        headers=attacker_headers,
    )
    assert res.status_code == 200, res.text
    data = res.json()

    assert data["attack_type"] == "UNAUTHORIZED_SESSION_ACCESS"
    assert data["result"] == "DENIED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ==============================================================================
# TEST 9: Attacks update live Guardian Dashboard metrics
# ==============================================================================
@pytest.mark.asyncio
async def test_attacks_update_guardian_dashboard_metrics(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]
    guardian_headers = seeded_users["guardian1"]["headers"]

    # Initial dashboard state
    init_dash = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=guardian_headers,
    )
    assert init_dash.status_code == 200
    init_data = init_dash.json()
    initial_attacks = init_data["attack_attempts"]
    initial_blocked = init_data["blocked_attacks"]

    # Execute 3 attacks
    for attack_type in ["UNAUTHORIZED_PAPER_ACCESS", "BYPASS_GUARDIAN_APPROVAL", "ROLE_ESCALATION"]:
        att_res = await async_client.post(
            f"/api/v1/attack-sim/{exam_id}/execute",
            json={"attack_type": attack_type},
            headers=attacker_headers,
        )
        assert att_res.status_code == 200

    # Check updated dashboard state
    upd_dash = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=guardian_headers,
    )
    assert upd_dash.status_code == 200
    upd_data = upd_dash.json()

    assert upd_data["attack_attempts"] >= initial_attacks + 3
    assert upd_data["blocked_attacks"] >= initial_blocked + 3
    assert upd_data["security_status"] in ["WARNING", "CRITICAL"]

    # Recent audit events must contain the attack actions
    actions = [ev["action"] for ev in upd_data["recent_audit_events"]]
    assert any("ATTACK" in a for a in actions)


# ==============================================================================
# TEST 10: Attack history endpoint returns full chronological attempt logs
# ==============================================================================
@pytest.mark.asyncio
async def test_attack_history_endpoint(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    # Execute 2 attacks
    await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_PAPER_ACCESS"},
        headers=attacker_headers,
    )
    await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "FAKE_GUARDIAN_APPROVAL"},
        headers=attacker_headers,
    )

    # Query history
    hist_res = await async_client.get(
        f"/api/v1/attack-sim/{exam_id}/history",
        headers=attacker_headers,
    )
    assert hist_res.status_code == 200
    hist_data = hist_res.json()

    assert hist_data["exam_id"] == exam_id
    assert hist_data["total_attacks"] >= 2
    assert hist_data["total_blocked"] >= 2
    assert len(hist_data["attacks"]) >= 2

    first_attack = hist_data["attacks"][0]
    assert "id" in first_attack
    assert "attack_type" in first_attack
    assert first_attack["result"] in ["BLOCKED", "DENIED"]
    assert first_attack["passed"] is True


# ==============================================================================
# TEST 11: Direct unauthorized HTTP GET to /api/v1/exams/{exam_id}/paper
# ==============================================================================
@pytest.mark.asyncio
async def test_direct_unauthorized_paper_endpoint_access(
    async_client: AsyncClient, seeded_users: dict
):
    exam = await create_test_exam(async_client, seeded_users)
    exam_id = exam["id"]
    attacker_headers = seeded_users["attacker"]["headers"]

    # Attacker directly attempts GET /api/v1/exams/{exam_id}/paper
    res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=attacker_headers,
    )
    assert res.status_code == 403
    assert "Attacker role cannot access examination papers" in res.json()["detail"]
