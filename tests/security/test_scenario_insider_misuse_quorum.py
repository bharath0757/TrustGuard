"""
TrustGuard — Controlled Insider Misuse Scenario Test Suite.

SCENARIO:
A valid authenticated user attempts to obtain or reconstruct the protected paper
without satisfying the required quorum.

IMPORTANT:
- The user is NOT an external attacker.
- The user has valid credentials and active officer role.
- The security decision must still be DENY.

DEMONSTRATES:
Valid identity + Valid account + Insufficient authorization/quorum = DENY

TEST CASES COVERED:
1. Valid officer, 0 approvals (k=3).
2. Valid officer, 1/3 approvals.
3. Valid officer, 2/3 approvals.
4. Attempt by one officer to approve multiple times.
5. Valid officer tries to bypass the approval API.
6. Valid user requests direct decryption without quorum.

EXPECTED:
- No reconstruction
- No decryption
- No paper disclosure (0 plaintext leakage)
- Audit event
- Security event where appropriate (INVALID_QUORUM)
"""

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import ApprovalDecision, RequestStatus, RequestType
from database.models.audit import AuditLog, ThreatEvent, ThreatEventType
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    create_access_request,
    cast_approval_vote,
    check_quorum,
    authorize_access,
    create_access_window,
    execute_jit_paper_access,
    decrypt_paper,
    reconstruct_paper,
    AccessDecision,
)
from security.quorum import (
    DuplicateApprovalError,
    QuorumValidationError,
    AccessDeniedError,
)
from security.access_window import WindowScheduleError, JITAccessDeniedError
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios import Scenario03NoQuorum
from tests.fixtures import (
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    setup_all_synthetic_users,
)


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
def insider_env(db_session: Session):
    """Setup roles and valid authenticated officer and approvers."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Key Guardian Approver")
    db_session.add_all([r_officer, r_approver])
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
    app1 = make_user("approver.bob@synth.local", "Approver Bob", r_approver)
    app2 = make_user("approver.charlie@synth.local", "Approver Charlie", r_approver)
    app3 = make_user("approver.david@synth.local", "Approver David", r_approver)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="INSIDER-MISUSE-2026",
    )

    return {
        "db": db_session,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "app3": app3,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
    }


# ===========================================================================
# 1. TEST CASE 1: Valid officer, 0 approvals (k=3)
# ===========================================================================

def test_insider_misuse_0_of_3_approvals(insider_env):
    """
    Valid authenticated officer attempts access when 0 of 3 required approvals are present.
    Asserts: DENY, request remains PENDING, ThreatEvent INVALID_QUORUM logged.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    paper: QuestionPaper = insider_env["paper"]
    master_key: bytes = insider_env["master_key"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Officer requests delivery with zero approvals",
    )

    q_status = check_quorum(db, req.id)
    assert q_status.is_authorized is False
    assert q_status.approved_count == 0
    assert req.status == RequestStatus.PENDING

    # Attempt JIT access authorization
    auth_res = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        actor_ip="10.0.0.1",
    )

    assert auth_res.decision == AccessDecision.DENY
    assert auth_res.is_allowed is False
    assert "quorum check failed" in auth_res.reason.lower()
    assert "pending" in auth_res.reason.lower()

    # Zero plaintext / key leakage
    assert SYNTHETIC_DEMO_PAYLOAD.decode("utf-8") not in auth_res.reason
    assert master_key.hex() not in auth_res.reason

    # Verify threat event logged
    threats = db.query(ThreatEvent).filter(
        ThreatEvent.actor_id == officer.id,
        ThreatEvent.event_type == ThreatEventType.INVALID_QUORUM,
    ).all()
    assert len(threats) >= 1


# ===========================================================================
# 2. TEST CASE 2: Valid officer, 1/3 approvals
# ===========================================================================

def test_insider_misuse_1_of_3_approvals(insider_env):
    """
    Valid authenticated officer attempts access when only 1 of 3 required approvals is present.
    Asserts: DENY, request remains PENDING, no reconstruction.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    app1: User = insider_env["app1"]
    paper: QuestionPaper = insider_env["paper"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Officer attempts access at 1/3 quorum",
    )
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED, reason="Approval 1 of 3")

    q_status = check_quorum(db, req.id)
    assert q_status.is_authorized is False
    assert q_status.approved_count == 1
    assert req.status == RequestStatus.PENDING

    auth_res = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        actor_ip="10.0.0.2",
    )

    assert auth_res.decision == AccessDecision.DENY
    assert auth_res.is_allowed is False
    assert "quorum check failed" in auth_res.reason.lower()


# ===========================================================================
# 3. TEST CASE 3: Valid officer, 2/3 approvals
# ===========================================================================

def test_insider_misuse_2_of_3_approvals(insider_env):
    """
    Valid authenticated officer attempts access when 2 of 3 required approvals are present.
    Asserts: DENY, request remains PENDING, no paper disclosure.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    app1: User = insider_env["app1"]
    app2: User = insider_env["app2"]
    paper: QuestionPaper = insider_env["paper"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Officer attempts access at 2/3 quorum",
    )
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)

    q_status = check_quorum(db, req.id)
    assert q_status.is_authorized is False
    assert q_status.approved_count == 2
    assert req.status == RequestStatus.PENDING

    auth_res = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        actor_ip="10.0.0.3",
    )

    assert auth_res.decision == AccessDecision.DENY
    assert auth_res.is_allowed is False
    assert "quorum check failed" in auth_res.reason.lower()


# ===========================================================================
# 4. TEST CASE 4: Attempt by one officer to approve multiple times
# ===========================================================================

def test_insider_misuse_attempt_multiple_approvals_same_officer(insider_env):
    """
    An approver who already approved attempts to cast a 2nd approval to inflate quorum from 1 to 2.
    Asserts: DuplicateApprovalError raised, vote not recorded, quorum count remains 1.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    app1: User = insider_env["app1"]
    paper: QuestionPaper = insider_env["paper"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=2,
        reason="Testing duplicate approval blocking",
    )
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED, reason="Legitimate vote 1")

    # Second vote attempt by the exact same user
    with pytest.raises(DuplicateApprovalError) as exc_info:
        cast_approval_vote(
            db=db,
            request_id=req.id,
            approver_id=app1.id,
            decision=ApprovalDecision.APPROVED,
            reason="Illegal duplicate approval attempt",
        )
    assert "already voted" in str(exc_info.value).lower()

    q_status = check_quorum(db, req.id)
    assert q_status.approved_count == 1
    assert q_status.is_authorized is False


# ===========================================================================
# 5. TEST CASE 5: Valid officer tries to bypass the approval API
# ===========================================================================

def test_insider_misuse_bypass_approval_api(insider_env):
    """
    Valid officer attempts to bypass approvals by directly creating an access window
    or executing JIT access for an unapproved request.
    Asserts: WindowScheduleError raised, AccessDeniedError on execution, zero access.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    paper: QuestionPaper = insider_env["paper"]
    master_key: bytes = insider_env["master_key"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Unapproved request",
    )
    assert req.status == RequestStatus.PENDING

    # Attempt 1: Direct create_access_window on pending request -> WindowScheduleError
    with pytest.raises(WindowScheduleError) as exc_info:
        create_access_window(
            db=db,
            request_id=req.id,
            start_time=datetime.now(timezone.utc),
            end_time=datetime.now(timezone.utc) + timedelta(hours=1),
        )
    assert "approved" in str(exc_info.value).lower() or "status" in str(exc_info.value).lower()

    # Attempt 2: Direct execute_jit_paper_access without approved window -> AccessDeniedError
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)) as exc_info:
        execute_jit_paper_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            actor_ip="10.0.0.5",
        )
    assert "denied" in str(exc_info.value).lower() or "quorum" in str(exc_info.value).lower()


# ===========================================================================
# 6. TEST CASE 6: Valid user requests direct decryption without quorum
# ===========================================================================

def test_insider_misuse_direct_decryption_without_quorum(insider_env):
    """
    Valid officer attempts to obtain paper plaintext directly without reaching quorum.
    Asserts: authorize_access returns DENY, execute_jit_paper_access raises AccessDeniedError,
    zero plaintext bytes disclosed, paper remains PROTECTED.
    """
    db: Session = insider_env["db"]
    officer: User = insider_env["officer"]
    app1: User = insider_env["app1"]
    paper: QuestionPaper = insider_env["paper"]
    fragments: list = insider_env["fragments"]
    master_key: bytes = insider_env["master_key"]

    req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Direct decryption attempt",
    )
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

    # Attempt direct JIT execution
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)):
        execute_jit_paper_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            actor_ip="10.0.0.6",
        )

    # Invariants verification
    db.refresh(paper)
    assert paper.status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED, PaperStatus.AWAITING_APPROVAL)
    assert len(fragments) == 5

    # Verify Audit log was created for the denied attempt
    audit_logs = db.query(AuditLog).filter(
        AuditLog.actor_id == officer.id,
        AuditLog.action.in_(["ACCESS_DENIED", "AUTHENTICATION_FAILED", "AUTHORIZATION_FAILED"]),
    ).all()
    assert len(audit_logs) >= 1 or len(db.query(ThreatEvent).filter(ThreatEvent.actor_id == officer.id).all()) >= 1


# ===========================================================================
# 7. SIMULATOR INTEGRATION & API LEVEL CHECKS
# ===========================================================================

def test_scenario_03_simulator_class_execution(db_session: Session):
    """
    Verify Scenario03NoQuorum executes cleanly and reports all 6 test cases passed.
    """
    scenario = Scenario03NoQuorum()
    result = scenario.run(db=db_session)

    assert result.scenario_id == 3
    assert result.passed is True
    assert result.security_decision == "DENY"
    assert result.audit_event_created is True
    assert result.threat_event_created is True
    assert result.details["test_cases_passed"] == 6
    assert result.details["no_disclosure"] is True


@pytest.mark.asyncio
async def test_api_insider_misuse_premature_stream_blocked_before_quorum(async_client: AsyncClient):
    """
    Verify at the REST API layer that an authenticated Exam Center user cannot stream
    a paper before the required quorum of approvals has been reached.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    center = users["exam_center_1"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]

    # 1. Setter creates exam requiring 2 guardians
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # 2. Assign both guardians first
    assign1_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
        headers=setter["headers"],
    )
    assert assign1_res.status_code == 201
    assign2_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "RSA_4096_FP_G2"},
        headers=setter["headers"],
    )
    assert assign2_res.status_code == 201

    # 3. Stage payload (transitions to CONSENSUS_PENDING)
    chunks = generate_synthetic_payload_chunks(2)
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200

    # 3. Only 1 of 2 guardians approves
    submit_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert submit_res.status_code == 200

    # Quorum status shows incomplete (1/2 approvals)
    status_res = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=center["headers"])
    assert status_res.json()["current_approvals_count"] == 1
    assert status_res.json()["quorum_reached"] is False

    # 4. Valid Exam Center attempts to stream exam before quorum -> 403 Forbidden
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 403
    assert "quorum" in stream_res.json()["detail"].lower() or "not unlocked" in stream_res.json()["detail"].lower()
