"""
TrustGuard — Controlled Replay Simulation Test Suite.

SCENARIO:
A legitimate access request has already been completed or expired.
An attacker attempts to reuse the previous request/authorization information.

TEST CASES:
1. Completed request reused
2. Expired request reused
3. Old approval reused for a new request
4. Old access token / memory context reused where applicable

VERIFIES:
- No decryption
- No unauthorized paper access (0 bytes disclosed)
- Audit / Threat event generated (REPLAY_ATTEMPT)
- Original request remains closed/expired
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import ApprovalDecision, RequestStatus, WindowStatus
from database.models.audit import ThreatEvent, ThreatEventType, ThreatSeverity, AuditLog
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    create_access_request,
    cast_approval_vote,
    create_access_window,
    authorize_access,
    execute_jit_paper_access,
    complete_access,
    expire_access_request,
    check_quorum,
    AccessDecision,
)
from security.access_window import JITAccessDeniedError, WindowScheduleError
from security.quorum import RequestNotPendingError, AccessDeniedError
from security.audit import SecureDecryptedBuffer
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios import Scenario07ReplayCompletedRequest
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
def replay_env(db_session: Session):
    """Setup test fixture with officer, approvers, and protected paper."""
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

    officer = make_user("officer.replay@synth.local", "Officer Alice", r_officer)
    app1 = make_user("approver.replay1@synth.local", "Approver 1", r_approver)
    app2 = make_user("approver.replay2@synth.local", "Approver 2", r_approver)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="REPLAY-SIM-2026",
    )

    return {
        "db": db_session,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
    }


# ===========================================================================
# 1. TEST CASE 1: Completed Request Reused
# ===========================================================================

def test_replay_completed_request_reused(replay_env):
    """
    Test: Attempt to reuse a completed access request.
    Asserts: authorize_access returns DENY citing replay prevention,
    ThreatEvent REPLAY_ATTEMPT recorded, execute_jit_paper_access raises JITAccessDeniedError,
    original request remains EXPIRED/closed.
    """
    db: Session = replay_env["db"]
    officer: User = replay_env["officer"]
    app1: User = replay_env["app1"]
    app2: User = replay_env["app2"]
    paper: QuestionPaper = replay_env["paper"]
    master_key: bytes = replay_env["master_key"]

    now = datetime.now(timezone.utc)

    # 1. Legitimate Request Creation, Approvals, & Access Window
    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    window = create_access_window(
        db=db,
        request_id=req.id,
        start_time=now - timedelta(minutes=5),
        end_time=now + timedelta(minutes=60),
        current_time=now,
    )

    # 2. Legitimate First Access succeeds
    auth_first = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
    assert auth_first.decision == AccessDecision.ALLOW

    # 3. Conclude Session normally
    complete_report = complete_access(
        db=db,
        paper_id=paper.id,
        request_id=req.id,
        actor_id=officer.id,
        reason="Exam concluded normally",
    )
    assert req.status == RequestStatus.EXPIRED
    assert window.status == WindowStatus.CLOSED

    # 4. Replay Attempt: Re-authorize with completed request ID
    replay_auth = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=now,
        actor_ip="10.0.0.66",
    )
    assert replay_auth.decision == AccessDecision.DENY
    assert replay_auth.is_allowed is False
    assert "replay prevented" in replay_auth.reason.lower() or "expired" in replay_auth.reason.lower()

    # 5. Direct execution attempt is blocked with zero plaintext
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)):
        execute_jit_paper_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            current_time=now,
        )

    # 6. Verify ThreatEvent REPLAY_ATTEMPT was recorded in database
    threats = db.query(ThreatEvent).filter(
        ThreatEvent.target_id == paper.id,
        ThreatEvent.event_type == ThreatEventType.REPLAY_ATTEMPT,
    ).all()
    assert len(threats) >= 1
    assert threats[-1].severity == ThreatSeverity.HIGH

    # 7. Original request remains closed/expired
    db.refresh(req)
    assert req.status == RequestStatus.EXPIRED


# ===========================================================================
# 2. TEST CASE 2: Expired Request Reused
# ===========================================================================

def test_replay_expired_request_reused(replay_env):
    """
    Test: Attempt to use an access request that timed out/expired before quorum.
    Asserts: authorize_access returns DENY, window creation fails with WindowScheduleError,
    voting fails with RequestNotPendingError, request remains EXPIRED.
    """
    db: Session = replay_env["db"]
    officer: User = replay_env["officer"]
    app1: User = replay_env["app1"]
    paper: QuestionPaper = replay_env["paper"]
    master_key: bytes = replay_env["master_key"]

    now = datetime.now(timezone.utc)

    # 1. Create request and expire it
    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
    expire_access_request(db, req.id, reason="Timed out before reaching quorum")
    assert req.status == RequestStatus.EXPIRED

    # 2. Replay authorization attempt on expired request -> DENY
    expired_auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
    assert expired_auth.decision == AccessDecision.DENY
    assert expired_auth.is_allowed is False

    # 3. Attempt to schedule window on expired request -> WindowScheduleError
    with pytest.raises(WindowScheduleError):
        create_access_window(
            db=db,
            request_id=req.id,
            start_time=now,
            end_time=now + timedelta(hours=1),
        )

    # 4. Attempt to cast vote on expired request -> RequestNotPendingError
    with pytest.raises(RequestNotPendingError):
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

    # 5. Direct execution -> JITAccessDeniedError
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)):
        execute_jit_paper_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            current_time=now,
        )

    db.refresh(req)
    assert req.status == RequestStatus.EXPIRED


# ===========================================================================
# 3. TEST CASE 3: Old Approval Reused for a New Request
# ===========================================================================

def test_replay_old_approval_reused_for_new_request(replay_env):
    """
    Test: Request 1 completed. User creates Request 2 for the same paper.
    Asserts: Request 2 starts with 0 approvals, is completely isolated from Request 1,
    and cannot be authorized without fresh, distinct approver votes.
    """
    db: Session = replay_env["db"]
    officer: User = replay_env["officer"]
    app1: User = replay_env["app1"]
    app2: User = replay_env["app2"]
    paper: QuestionPaper = replay_env["paper"]

    now = datetime.now(timezone.utc)

    # 1. Complete Request 1
    req1 = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
    cast_approval_vote(db, req1.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req1.id, app2.id, ApprovalDecision.APPROVED)
    create_access_window(db, req1.id, start_time=now - timedelta(minutes=5), end_time=now + timedelta(minutes=30))
    complete_access(db, paper_id=paper.id, request_id=req1.id, actor_id=officer.id)
    assert req1.status == RequestStatus.EXPIRED

    # 2. Create Request 2 for same paper
    req2 = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)

    # 3. Verify Request 2 has 0 approvals and is in PENDING state
    q2_status = check_quorum(db, req2.id)
    assert q2_status.approved_count == 0
    assert q2_status.is_authorized is False
    assert req2.status == RequestStatus.PENDING

    # JIT access on Request 2 is DENIED
    auth2 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req2.id, current_time=now)
    assert auth2.decision == AccessDecision.DENY
    assert auth2.is_allowed is False

    # 4. Fresh votes properly advance Request 2
    cast_approval_vote(db, req2.id, app1.id, ApprovalDecision.APPROVED)
    q2_after_vote = check_quorum(db, req2.id)
    assert q2_after_vote.approved_count == 1
    assert q2_after_vote.is_authorized is False


# ===========================================================================
# 4. TEST CASE 4: Stale Context / Wiped Memory Buffer Reuse
# ===========================================================================

def test_replay_old_access_token_and_context_reused(replay_env):
    """
    Test: Memory wiping of temporary decrypted representation in SecureDecryptedBuffer.
    Asserts: Buffer is wiped upon context exit; subsequent read raises RuntimeError.
    """
    secret_data = b"CONFIDENTIAL_EXAM_PLAIN_BUFFER_CONTENT_12345"

    with SecureDecryptedBuffer(secret_data) as sec_buf:
        # Accessible inside active context
        assert sec_buf.get_data() == secret_data

    # Attempt to access wiped buffer after session context exit -> RuntimeError
    with pytest.raises(RuntimeError) as exc_info:
        _ = sec_buf.get_data()
    assert "wiped" in str(exc_info.value).lower()


# ===========================================================================
# 5. TEST CASE 5: Attack Simulator Scenario 7 Class Execution
# ===========================================================================

def test_scenario_07_simulator_class_execution(db_session: Session):
    """
    Verify Scenario07ReplayCompletedRequest executes cleanly and reports all test cases passed.
    """
    scenario = Scenario07ReplayCompletedRequest()
    result = scenario.run(db=db_session)

    assert result.scenario_id == 7
    assert result.passed is True
    assert result.security_decision == "DENY"
    assert result.threat_event_created is True
    assert result.audit_event_created is True
    assert result.details["test_cases_passed"] == 5
    assert result.details["no_disclosure"] is True
    assert result.details["completed_req_status"] == "EXPIRED"


# ===========================================================================
# 6. TEST CASE 6: REST API Layer Replay Stream After Session Purge
# ===========================================================================

@pytest.mark.asyncio
async def test_api_replay_stream_after_session_purged(async_client: AsyncClient):
    """
    REST API: Streaming an exam payload after purge endpoint returns 410 Gone.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]

    # 1. Create exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # 2. Assign guardians
    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
        headers=setter["headers"],
    )
    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "RSA_4096_FP_G2"},
        headers=setter["headers"],
    )

    # 3. Stage payload
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )

    # 4. Approvers unlock
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX2_{g2['user_id']}"},
        headers=g2["headers"],
    )

    # 5. Legitimate first stream
    stream_res1 = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res1.status_code == 200

    # 6. Purge session / conclude exam
    purge_res = await async_client.post(
        f"/api/v1/distribution/{exam_id}/purge",
        headers=setter["headers"],
    )
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True

    # 7. Replay stream attempt after purge returns 410 Gone
    replay_stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert replay_stream_res.status_code == 410
    assert "distribution closed" in replay_stream_res.json()["detail"].lower() or "completed" in replay_stream_res.json()["detail"].lower()
