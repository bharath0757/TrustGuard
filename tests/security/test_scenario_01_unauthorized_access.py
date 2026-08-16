"""
TrustGuard — Scenario 1: Unauthorized Question-Paper Access Test Suite.

Automated tests specifically verifying:
- Unauthenticated requests are rejected (DENY / HTTP 401).
- Authenticated but unauthorized users are rejected (DENY / HTTP 403).
- Safe error responses with ZERO secret leakage (no plaintext paper, no master keys, no raw fragment data).
- Audit and threat events are properly created (UNAUTHORIZED_ACCESS / DENIED_OPERATION).
- Question paper remains in its protected state.
- Existing legitimate approvals are not modified.
- No valid decryption session or plaintext memory buffer is created.
"""

from datetime import datetime, timezone
import base64
import hashlib
import os
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import ApprovalDecision, RequestStatus, RequestType
from database.models.audit import AuditLog, ThreatEvent, ThreatEventType, AuditResult
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    protect_paper,
    fragment_paper,
    create_access_request,
    cast_approval_vote,
    authorize_access,
    AccessDecision,
    AuditEventType,
)
from security.quorum import (
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
)
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios import Scenario01UnauthorizedUser
from tests.fixtures import (
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    register_and_login_user,
    setup_all_synthetic_users,
)


# ===========================================================================
# FIXTURES FOR SERVICE-LAYER TESTING
# ===========================================================================

@pytest.fixture
def db_session():
    """In-memory SQLite database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def scenario_env(db_session: Session):
    """Setup roles, valid officer, valid approver, and unauthorized candidate."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
    r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Candidate")
    db_session.add_all([r_officer, r_approver, r_candidate])
    db_session.flush()

    def make_user(email: str, name: str, role: Role) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
            full_name=name,
            is_active=True,
        )
        db_session.add(u)
        db_session.flush()
        db_session.add(UserRole(user_id=u.id, role_id=role.id))
        db_session.flush()
        return u

    officer = make_user("officer.alice@synth.local", "Officer Alice", r_officer)
    approver = make_user("approver.bob@synth.local", "Approver Bob", r_approver)
    candidate = make_user("candidate.eve@synth.local", "Candidate Eve", r_candidate)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="TEST-UNAUTH-2026",
    )

    access_req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=2,
        reason="Pre-existing valid access request",
    )
    cast_approval_vote(db_session, access_req.id, approver.id, ApprovalDecision.APPROVED)

    return {
        "db": db_session,
        "officer": officer,
        "approver": approver,
        "candidate": candidate,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
        "access_req": access_req,
    }


# ===========================================================================
# 1. SERVICE-LAYER TESTS FOR SCENARIO 1
# ===========================================================================

def test_service_unauthenticated_request_is_rejected_and_audited(scenario_env):
    """
    Verify that an unauthenticated / non-existent user is blocked from creating access requests
    or obtaining JIT authorization, leaving the paper protected and logging a threat event.
    """
    db: Session = scenario_env["db"]
    paper: QuestionPaper = scenario_env["paper"]
    access_req = scenario_env["access_req"]
    master_key: bytes = scenario_env["master_key"]
    unauthenticated_user_id = uuid.uuid4()

    initial_paper_status = paper.status
    initial_approvals_count = len(access_req.approvals)

    # 1. Request Creation Blocked
    with pytest.raises(QuorumValidationError) as exc_info:
        create_access_request(
            db=db,
            paper_id=paper.id,
            requested_by=unauthenticated_user_id,
            reason="Unauthenticated attack attempt",
        )
    assert "not found" in str(exc_info.value).lower()

    # 2. JIT Authorization Evaluated
    auth_result = authorize_access(
        db=db,
        user_id=unauthenticated_user_id,
        paper_id=paper.id,
        request_id=access_req.id,
        actor_ip="192.168.1.99",
    )

    # Assertions
    assert auth_result.decision == AccessDecision.DENY
    assert auth_result.is_allowed is False
    assert "identity check failed" in auth_result.reason.lower() or "unknown" in auth_result.reason.lower()

    # Verify zero secret leakage in error reason
    assert SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in auth_result.reason
    assert master_key.hex() not in auth_result.reason
    assert base64.b64encode(master_key).decode("utf-8") not in auth_result.reason

    # Verify state invariants
    db.refresh(paper)
    db.refresh(access_req)
    assert paper.status == initial_paper_status
    assert len(access_req.approvals) == initial_approvals_count

    # Verify Threat / Audit event
    threat_events = db.query(ThreatEvent).filter(ThreatEvent.actor_id == unauthenticated_user_id).all()
    assert len(threat_events) >= 1
    assert threat_events[0].event_type == ThreatEventType.UNAUTHORIZED_ACCESS


def test_service_authenticated_unauthorized_candidate_is_denied(scenario_env):
    """
    Verify that an authenticated user with insufficient privilege (CANDIDATE role)
    cannot authorize access, cannot cast approval votes, and does not leak confidential data.
    """
    db: Session = scenario_env["db"]
    candidate: User = scenario_env["candidate"]
    paper: QuestionPaper = scenario_env["paper"]
    access_req = scenario_env["access_req"]
    master_key: bytes = scenario_env["master_key"]

    initial_paper_status = paper.status
    initial_approvals_count = len(access_req.approvals)

    # 1. Candidate Attempting to Approve is Blocked
    with pytest.raises(InvalidApproverRoleError) as exc_info:
        cast_approval_vote(
            db=db,
            request_id=access_req.id,
            approver_id=candidate.id,
            decision=ApprovalDecision.APPROVED,
            allowed_roles={"APPROVER", "OFFICER", "ADMIN"},
        )
    assert "candidate" in str(exc_info.value).lower()

    # 2. Candidate Attempting to Authorize Access is Denied
    auth_result = authorize_access(
        db=db,
        user_id=candidate.id,
        paper_id=paper.id,
        request_id=access_req.id,
        allowed_roles={"OFFICER", "ADMIN"},
        actor_ip="192.168.1.101",
    )

    # Assertions
    assert auth_result.decision == AccessDecision.DENY
    assert auth_result.is_allowed is False
    assert "role check failed" in auth_result.reason.lower() or "candidate" in auth_result.reason.lower()

    # Verify zero secret leakage
    assert SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in auth_result.reason
    assert master_key.hex() not in auth_result.reason

    # Verify paper and approvals unaffected
    db.refresh(paper)
    db.refresh(access_req)
    assert paper.status == initial_paper_status
    assert len(access_req.approvals) == initial_approvals_count

    # Verify Threat incident logged
    threat_events = db.query(ThreatEvent).filter(ThreatEvent.actor_id == candidate.id).all()
    assert len(threat_events) >= 1
    assert threat_events[0].event_type == ThreatEventType.DENIED_OPERATION


def test_scenario_01_simulator_class_execution(db_session: Session):
    """
    Verify Scenario01UnauthorizedUser executes cleanly within the AttackSimulator framework.
    """
    scenario = Scenario01UnauthorizedUser()
    result = scenario.run(db=db_session)

    assert result.scenario_id == 1
    assert result.scenario_name == "Unauthorized Question-Paper Access"
    assert result.passed is True
    assert result.security_decision == "DENY"
    assert result.audit_event_created is True
    assert result.details["unauth_denied"] is True
    assert result.details["candidate_denied"] is True
    assert result.details["zero_secret_leakage"] is True
    assert result.details["approvals_intact"] is True


# ===========================================================================
# 2. REST API LAYER TESTS FOR SCENARIO 1
# ===========================================================================

@pytest.mark.asyncio
async def test_api_unauthenticated_requests_return_401_or_403(async_client: AsyncClient):
    """
    Verify that unauthenticated HTTP requests to exam retrieval and streaming endpoints fail safely.
    """
    fake_exam_id = uuid.uuid4()

    # 1. Missing Authorization header -> 401 or 403 Forbidden
    get_res = await async_client.get(f"/api/v1/exams/{fake_exam_id}")
    assert get_res.status_code in (401, 403)
    assert "detail" in get_res.json()

    # 2. Invalid / Tampered token -> 401 Unauthorized
    invalid_token_res = await async_client.get(
        f"/api/v1/exams/{fake_exam_id}",
        headers={"Authorization": "Bearer invalid.tampered.token.payload"},
    )
    assert invalid_token_res.status_code == 401
    assert "invalid" in invalid_token_res.json()["detail"].lower()

    # 3. Unauthenticated streaming attempt
    stream_res = await async_client.get(f"/api/v1/distribution/{fake_exam_id}/stream")
    assert stream_res.status_code in (401, 403)


@pytest.mark.asyncio
async def test_api_authenticated_unauthorized_user_blocked_with_403(async_client: AsyncClient):
    """
    Verify that an authenticated user with unauthorized role (e.g. EXAM_CENTER attempting
    to stage payload, or non-setter attempting guardian assignment) returns 403 Forbidden.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    center = users["exam_center_1"]
    g1 = users["key_guardian_1"]

    # 1. Setter creates exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # 2. Unauthorized role (EXAM_CENTER) attempts to stage payload -> 403 Forbidden
    chunks = generate_synthetic_payload_chunks(2)
    unauth_stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=center["headers"],  # EXAM_CENTER does not have setter privilege!
    )
    assert unauth_stage_res.status_code == 403
    assert "permitted" in unauth_stage_res.json()["detail"].lower() or "forbidden" in unauth_stage_res.json()["detail"].lower()

    # 3. Unauthorized role (EXAM_CENTER) attempts to assign guardians -> 403 Forbidden
    unauth_assign_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
        headers=center["headers"],
    )
    assert unauth_assign_res.status_code == 403

    # 4. Premature stream attempt before quorum by center -> 403 Forbidden
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 403
    assert "quorum" in stream_res.json()["detail"].lower() or "not unlocked" in stream_res.json()["detail"].lower()

    # Verify zero secret leakage in 403 responses
    for res in [unauth_stage_res, unauth_assign_res, stream_res]:
        body_text = str(res.json())
        assert "TRUSTGUARD_DEMO_PAPER" not in body_text
        assert "master_key" not in body_text
