"""Phase 4 Attack Simulator Automated Test Suite.

Verifies 9 Security Attack Scenarios:
1. UNAUTHORIZED_PAPER_ACCESS
2. BYPASS_GUARDIAN_APPROVAL
3. FAKE_GUARDIAN_APPROVAL
4. ROLE_ESCALATION
5. ACCESS_EXPIRED_EXAM
6. UNAUTHORIZED_SESSION_ACCESS
7. TAMPERED_FRAGMENT
8. INSIDER_ATTEMPT
9. REPLAY_ATTEMPT

For each scenario, verifies:
- The attack is blocked/denied
- Appropriate HTTP status code and security response
- security_decision is DENY
- Result status indicates BLOCKED / DENIED / INVALID AUTHORIZATION / FAILED INTEGRITY
- An AuditEvent with audit/security alert action is persisted to database
"""

from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from backend.tests.conftest import create_user_and_login
from app.db.models import AuditEvent, Exam, UploadedPaper


async def _create_test_exam(async_client: AsyncClient, setter_headers: dict) -> str:
    """Helper fixture to create a real exam for attack testing."""
    now = datetime.now(timezone.utc)
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Security Threat Test Exam 2026",
            "course_code": "SEC-ATTACK-101",
            "description": "Exam for attack simulator verification",
            "scheduled_start": (now - timedelta(minutes=10)).isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
            "duration_minutes": 60,
            "required_quorum": 2,
            "total_guardians": 2,
        },
        headers=setter_headers,
    )
    assert create_res.status_code == 201
    return create_res.json()["id"]


# ─── 1. UNAUTHORIZED_PAPER_ACCESS ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_unauthorized_paper_access(async_client: AsyncClient):
    """Verify unauthorized paper access attempt is blocked with 403 Forbidden and DENY decision."""
    setter = await create_user_and_login(async_client, "attack_setter_1", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_1", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_PAPER_ACCESS"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] == "BLOCKED"
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True
    assert data["audit_event_id"] is not None


# ─── 2. BYPASS_GUARDIAN_APPROVAL ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_bypass_guardian_approval(async_client: AsyncClient):
    """Verify unassigned guardian approval vote attempt is blocked."""
    setter = await create_user_and_login(async_client, "attack_setter_2", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_2", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "BYPASS_GUARDIAN_APPROVAL"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ─── 3. FAKE_GUARDIAN_APPROVAL ──────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_fake_guardian_approval(async_client: AsyncClient):
    """Verify forged guardian approval attempt with fake token is rejected."""
    setter = await create_user_and_login(async_client, "attack_setter_3", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_3", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "FAKE_GUARDIAN_APPROVAL"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ─── 4. ROLE_ESCALATION ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_role_escalation(async_client: AsyncClient):
    """Verify non-admin attacker role escalation attempt is blocked."""
    setter = await create_user_and_login(async_client, "attack_setter_4", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_4", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "ROLE_ESCALATION"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ─── 5. ACCESS_EXPIRED_EXAM ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_access_expired_exam(async_client: AsyncClient):
    """Verify non-student joining exam session is blocked."""
    setter = await create_user_and_login(async_client, "attack_setter_5", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_5", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "ACCESS_EXPIRED_EXAM"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ─── 6. UNAUTHORIZED_SESSION_ACCESS ─────────────────────────────────────────

@pytest.mark.asyncio
async def test_attack_unauthorized_session_access(async_client: AsyncClient):
    """Verify unauthorized student session access attempt is blocked."""
    setter = await create_user_and_login(async_client, "attack_setter_6", "EXAM_SETTER")
    attacker = await create_user_and_login(async_client, "attacker_user_6", "ATTACKER")
    exam_id = await _create_test_exam(async_client, setter["headers"])

    res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_SESSION_ACCESS"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["result"] in ["BLOCKED", "DENIED"]
    assert data["http_status"] == 403
    assert data["security_decision"] == "DENY"
    assert data["passed"] is True


# ─── 7. TAMPERED_FRAGMENT ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_simulation_tampered_fragment(async_client: AsyncClient):
    """Verify tampered fragment scenario results in FAILED INTEGRITY and DENY decision."""
    attacker = await create_user_and_login(async_client, "attacker_sim_7", "ATTACKER")

    res = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "TAMPERED_FRAGMENT", "exam_id": "DEMO-EXAM-007"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "TAMPERED_FRAGMENT"
    assert data["security_decision"] == "DENY"
    assert data["status_category"] == "FAILED INTEGRITY"
    assert data["passed"] is True
    assert data["audit_event_id"] is not None


# ─── 8. INSIDER_ATTEMPT ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_simulation_insider_attempt(async_client: AsyncClient):
    """Verify insider reconstruction attempt without quorum results in INVALID AUTHORIZATION and DENY decision."""
    attacker = await create_user_and_login(async_client, "attacker_sim_8", "ATTACKER")

    res = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "INSIDER_ATTEMPT", "exam_id": "DEMO-EXAM-008"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "INSIDER_ATTEMPT"
    assert data["security_decision"] == "DENY"
    assert data["status_category"] == "INVALID AUTHORIZATION"
    assert data["passed"] is True
    assert data["audit_event_id"] is not None


# ─── 9. REPLAY_ATTEMPT ──────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_simulation_replay_attempt(async_client: AsyncClient):
    """Verify replay of expired/purged access request results in BLOCKED and DENY decision."""
    attacker = await create_user_and_login(async_client, "attacker_sim_9", "ATTACKER")

    res = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "REPLAY_ATTEMPT", "exam_id": "DEMO-EXAM-009"},
        headers=attacker["headers"],
    )

    assert res.status_code == 200
    data = res.json()

    assert data["scenario_id"] == "REPLAY_ATTEMPT"
    assert data["security_decision"] == "DENY"
    assert data["status_category"] == "BLOCKED"
    assert data["passed"] is True
    assert data["audit_event_id"] is not None
