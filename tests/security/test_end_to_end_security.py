"""
TrustGuard — End-to-End Security Workflow Integration Tests.

Validates the full Zero-Trust security lifecycle across all 8 mandatory scenarios:
  - Scenario 1: Valid paper, Valid user, No quorum -> DENY
  - Scenario 2: Valid user, Valid quorum, Outside time window -> DENY
  - Scenario 3: Unauthorized user, Valid time window -> DENY
  - Scenario 4: Valid user, Valid quorum, Valid window, Valid fragments -> ALLOW
  - Scenario 5: Valid request, Tampered fragment -> DENY
  - Scenario 6: Completed request replay -> DENY
  - Scenario 7: Duplicate approval -> DENY
  - Scenario 8: Unauthorized approver -> DENY
"""
from datetime import datetime, timedelta, timezone
import os
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import (
    AccessRequest,
    AccessWindow,
    ApprovalDecision,
    RequestStatus,
    WindowStatus,
)
from database.models.audit import (
    AuditLog,
    AuditResult,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment
from database.models.user import User, Role, UserRole

from security.crypto.encryption import encrypt, decrypt
from security.quorum import (
    DuplicateApprovalError,
    InvalidApproverRoleError,
    UnauthorizedApproverError,
)
from security.access_window import (
    AccessDecision,
    JITAccessDeniedError,
)
from security.audit import AuditEventType
from security.service import (
    ingest_and_protect_paper,
    submit_access_request,
    approve_access_request,
    schedule_access_window,
    deliver_question_paper_jit,
    close_and_finalize_session,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def raw_exam_content() -> bytes:
    return (
        b"TRUSTGUARD CONFIDENTIAL EXAMINATION 2026\n"
        b"Paper: Advanced Zero-Trust Cryptography & Multi-Party Systems\n"
        b"Question 1: Demonstrate that a single account cannot access protected papers."
    )


@pytest.fixture
def db_session():
    """In-memory SQLite database session with complete schema."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def e2e_env(db_session: Session, master_key: bytes, raw_exam_content: bytes):
    """
    Sets up a complete production-like security environment:
    - Roles: ADMIN, OFFICER, APPROVER, CANDIDATE
    - Users:
      - Chief Admin (creator)
      - Officer Alice (authorized requester)
      - Officer Bob (authorized approver 1)
      - Officer Charlie (authorized approver 2)
      - Officer Diane (authorized approver 3)
      - Candidate Eve (unauthorized role)
    - Protected & Fragmented Question Paper (5 shards)
    """
    # 1. Create Roles
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Administrator")
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Authorized Approver")
    r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Exam Candidate")
    db_session.add_all([r_admin, r_officer, r_approver, r_candidate])
    db_session.flush()

    # 2. Create Users
    def make_user(email: str, name: str, role: Role, is_active: bool = True) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash="fake_hash",
            full_name=name,
            is_active=is_active,
        )
        db_session.add(u)
        db_session.flush()
        ur = UserRole(user_id=u.id, role_id=role.id)
        db_session.add(ur)
        db_session.flush()
        return u

    admin = make_user("admin@trustguard.org", "Chief Admin", r_admin)
    officer_alice = make_user("alice@trustguard.org", "Officer Alice", r_officer)
    officer_bob = make_user("bob@trustguard.org", "Officer Bob", r_approver)
    officer_charlie = make_user("charlie@trustguard.org", "Officer Charlie", r_approver)
    officer_diane = make_user("diane@trustguard.org", "Officer Diane", r_approver)
    candidate_eve = make_user("eve@trustguard.org", "Candidate Eve", r_candidate)

    # 3. Ingest and Protect Paper
    paper = ingest_and_protect_paper(
        db=db_session,
        exam_identifier="GATE-CS-2026",
        paper_name="Computer Science & Information Technology",
        plaintext_data=raw_exam_content,
        key=master_key,
        creator_id=admin.id,
        num_fragments=5,
        actor_ip="10.0.0.1",
    )
    db_session.commit()

    # Fixed time coordinates
    t0 = datetime(2026, 8, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_start = t0
    t_end = t0 + timedelta(hours=1)

    return {
        "paper": paper,
        "admin": admin,
        "alice": officer_alice,
        "bob": officer_bob,
        "charlie": officer_charlie,
        "diane": officer_diane,
        "eve": candidate_eve,
        "master_key": master_key,
        "raw_exam_content": raw_exam_content,
        "t_start": t_start,
        "t_end": t_end,
    }


# ---------------------------------------------------------------------------
# SCENARIO 1: Valid paper, Valid user, No quorum -> DENY
# ---------------------------------------------------------------------------

def test_scenario_1_valid_paper_valid_user_no_quorum(db_session: Session, e2e_env: dict):
    """
    SCENARIO 1:
    Valid paper
    Valid user
    No quorum (0/3 approvals)
    -> DENY
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    key = e2e_env["master_key"]
    t_start = e2e_env["t_start"]

    # Alice creates a request (required approvals = 3)
    req = submit_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=alice.id,
        required_approvals=3,
        reason="Scenario 1: Testing access with 0/3 approvals",
    )
    db_session.commit()

    # Attempt JIT delivery without approvals
    with pytest.raises(JITAccessDeniedError, match="Quorum check failed"):
        deliver_question_paper_jit(
            db=db_session,
            user_id=alice.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_start,
        )
    db_session.commit()

    # Verify audit trail recorded DENIAL
    denied_log = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.target_id == paper.id,
            AuditLog.action == AuditEventType.ACCESS_DENIED.value,
        )
        .order_by(AuditLog.timestamp.desc())
        .first()
    )
    assert denied_log is not None
    assert denied_log.result == AuditResult.DENIED
    assert "Quorum check failed" in denied_log.reason


# ---------------------------------------------------------------------------
# SCENARIO 2: Valid user, Valid quorum, Outside time window -> DENY
# ---------------------------------------------------------------------------

def test_scenario_2_valid_user_valid_quorum_outside_time_window(db_session: Session, e2e_env: dict):
    """
    SCENARIO 2:
    Valid user
    Valid quorum (3/3 approvals)
    Outside time window (now < start_time)
    -> DENY
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]
    charlie = e2e_env["charlie"]
    diane = e2e_env["diane"]
    key = e2e_env["master_key"]
    t_start = e2e_env["t_start"]
    t_end = e2e_env["t_end"]

    # Submit request and satisfy 3/3 quorum
    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    approve_access_request(db_session, req.id, bob.id)
    approve_access_request(db_session, req.id, charlie.id)
    approve_access_request(db_session, req.id, diane.id)
    schedule_access_window(db_session, req.id, t_start, t_end)
    db_session.commit()

    # Attempt access 30 minutes BEFORE window opens
    t_before = t_start - timedelta(minutes=30)
    with pytest.raises(JITAccessDeniedError, match="BEFORE_WINDOW"):
        deliver_question_paper_jit(
            db=db_session,
            user_id=alice.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_before,
        )
    db_session.commit()

    # Verify audit trail recorded BEFORE_WINDOW denial
    denied_log = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.target_id == paper.id,
            AuditLog.action == AuditEventType.ACCESS_DENIED.value,
        )
        .order_by(AuditLog.timestamp.desc())
        .first()
    )
    assert denied_log is not None
    assert "BEFORE_WINDOW" in denied_log.reason


# ---------------------------------------------------------------------------
# SCENARIO 3: Unauthorized user, Valid time window -> DENY
# ---------------------------------------------------------------------------

def test_scenario_3_unauthorized_user_valid_time_window(db_session: Session, e2e_env: dict):
    """
    SCENARIO 3:
    Unauthorized user (Candidate Eve with non-officer role)
    Valid time window
    -> DENY
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]
    charlie = e2e_env["charlie"]
    diane = e2e_env["diane"]
    eve = e2e_env["eve"]
    key = e2e_env["master_key"]
    t_start = e2e_env["t_start"]
    t_end = e2e_env["t_end"]

    # Window is active for Alice's approved request
    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    approve_access_request(db_session, req.id, bob.id)
    approve_access_request(db_session, req.id, charlie.id)
    approve_access_request(db_session, req.id, diane.id)
    schedule_access_window(db_session, req.id, t_start, t_end)
    db_session.commit()

    t_during = t_start + timedelta(minutes=15)

    # Candidate Eve attempts to access the paper
    with pytest.raises(JITAccessDeniedError, match="Permission check failed"):
        deliver_question_paper_jit(
            db=db_session,
            user_id=eve.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_during,
            actor_ip="192.168.100.44",
        )
    db_session.commit()

    # Verify threat event recorded for unauthorized attempt
    threat = (
        db_session.query(ThreatEvent)
        .filter(
            ThreatEvent.actor_id == eve.id,
            ThreatEvent.event_type == ThreatEventType.DENIED_OPERATION,
        )
        .first()
    )
    assert threat is not None
    assert threat.severity == ThreatSeverity.MEDIUM


# ---------------------------------------------------------------------------
# SCENARIO 4: Valid user, Valid quorum, Valid window, Valid fragments -> ALLOW
# ---------------------------------------------------------------------------

def test_scenario_4_all_security_conditions_valid(db_session: Session, e2e_env: dict):
    """
    SCENARIO 4:
    Valid user
    Valid quorum (3/3)
    Valid window (DURING_WINDOW)
    Valid fragments (5/5 intact shards)
    -> ALLOW
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]
    charlie = e2e_env["charlie"]
    diane = e2e_env["diane"]
    key = e2e_env["master_key"]
    raw_content = e2e_env["raw_exam_content"]
    t_start = e2e_env["t_start"]
    t_end = e2e_env["t_end"]

    # 1. Submit Request
    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    
    # 2. Multi-Party Approvals (3/3)
    approve_access_request(db_session, req.id, bob.id)
    approve_access_request(db_session, req.id, charlie.id)
    approve_access_request(db_session, req.id, diane.id)

    # 3. Schedule Time Window
    schedule_access_window(db_session, req.id, t_start, t_end)
    db_session.commit()

    # 4. Access during active window
    t_during = t_start + timedelta(minutes=20)
    with deliver_question_paper_jit(
        db=db_session,
        user_id=alice.id,
        paper_id=paper.id,
        key=key,
        request_id=req.id,
        current_time=t_during,
        actor_ip="10.0.0.15",
    ) as decrypted_buffer:
        # 5. Assert exact match
        assert decrypted_buffer.get_data() == raw_content

    # 6. Verify buffer was safely wiped
    assert decrypted_buffer._is_wiped

    # 7. Verify complete audit trail
    logs = (
        db_session.query(AuditLog)
        .filter(AuditLog.target_id == paper.id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )
    actions = [l.action for l in logs]
    assert AuditEventType.ACCESS_GRANTED.value in actions
    assert AuditEventType.DECRYPTION_STARTED.value in actions
    assert AuditEventType.DECRYPTION_COMPLETED.value in actions


# ---------------------------------------------------------------------------
# SCENARIO 5: Valid request, Tampered fragment -> DENY
# ---------------------------------------------------------------------------

def test_scenario_5_tampered_fragment_denies_access(db_session: Session, e2e_env: dict):
    """
    SCENARIO 5:
    Valid request & quorum
    Valid window
    Tampered fragment in database
    -> DENY (Integrity check failure)
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]
    charlie = e2e_env["charlie"]
    diane = e2e_env["diane"]
    key = e2e_env["master_key"]
    t_start = e2e_env["t_start"]
    t_end = e2e_env["t_end"]

    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    approve_access_request(db_session, req.id, bob.id)
    approve_access_request(db_session, req.id, charlie.id)
    approve_access_request(db_session, req.id, diane.id)
    schedule_access_window(db_session, req.id, t_start, t_end)

    # Tamper with shard index 3
    frag3 = (
        db_session.query(PaperFragment)
        .filter(
            PaperFragment.paper_id == paper.id,
            PaperFragment.fragment_index == 3,
        )
        .first()
    )
    tampered = bytearray(frag3.fragment_data)
    tampered[2] ^= 0xFF
    frag3.fragment_data = bytes(tampered)
    db_session.commit()

    t_during = t_start + timedelta(minutes=10)
    with pytest.raises(JITAccessDeniedError, match="Integrity check failed"):
        deliver_question_paper_jit(
            db=db_session,
            user_id=alice.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_during,
        )
    db_session.commit()

    # Verify critical threat event recorded
    threat = (
        db_session.query(ThreatEvent)
        .filter(
            ThreatEvent.target_id == paper.id,
            ThreatEvent.event_type == ThreatEventType.INTEGRITY_FAILURE,
        )
        .first()
    )
    assert threat is not None
    assert threat.severity == ThreatSeverity.CRITICAL


# ---------------------------------------------------------------------------
# SCENARIO 6: Completed request replay -> DENY
# ---------------------------------------------------------------------------

def test_scenario_6_completed_request_replay_denied(db_session: Session, e2e_env: dict):
    """
    SCENARIO 6:
    Session completed and finalized
    Attempted replay with same request
    -> DENY (Replay protection active)
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]
    charlie = e2e_env["charlie"]
    diane = e2e_env["diane"]
    key = e2e_env["master_key"]
    t_start = e2e_env["t_start"]
    t_end = e2e_env["t_end"]

    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    approve_access_request(db_session, req.id, bob.id)
    approve_access_request(db_session, req.id, charlie.id)
    approve_access_request(db_session, req.id, diane.id)
    schedule_access_window(db_session, req.id, t_start, t_end)
    db_session.commit()

    # 1. Complete and finalize session
    close_and_finalize_session(
        db=db_session,
        paper_id=paper.id,
        request_id=req.id,
        actor_id=alice.id,
        reason="Exam delivery finished successfully",
    )
    db_session.commit()

    # 2. Attempt replay during original time window
    t_during = t_start + timedelta(minutes=45)
    with pytest.raises(JITAccessDeniedError, match="replay prevented"):
        deliver_question_paper_jit(
            db=db_session,
            user_id=alice.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_during,
        )
    db_session.commit()

    # 3. Verify REPLAY_ATTEMPT threat event logged
    threat = (
        db_session.query(ThreatEvent)
        .filter(ThreatEvent.event_type == ThreatEventType.REPLAY_ATTEMPT)
        .first()
    )
    assert threat is not None
    assert threat.severity == ThreatSeverity.HIGH


# ---------------------------------------------------------------------------
# SCENARIO 7: Duplicate approval -> DENY
# ---------------------------------------------------------------------------

def test_scenario_7_duplicate_approval_denied(db_session: Session, e2e_env: dict):
    """
    SCENARIO 7:
    Approver attempts to vote twice on same request
    -> DENY (Duplicate vote rejected with error)
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    bob = e2e_env["bob"]

    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    
    # First vote from Bob succeeds
    approve_access_request(db_session, req.id, bob.id)
    db_session.commit()

    # Duplicate vote from Bob fails
    with pytest.raises(DuplicateApprovalError, match="already voted"):
        approve_access_request(db_session, req.id, bob.id)


# ---------------------------------------------------------------------------
# SCENARIO 8: Unauthorized approver -> DENY
# ---------------------------------------------------------------------------

def test_scenario_8_unauthorized_approver_denied(db_session: Session, e2e_env: dict):
    """
    SCENARIO 8:
    User without authorized approver role (Candidate Eve) attempts to approve request
    -> DENY (InvalidApproverRoleError)
    """
    paper = e2e_env["paper"]
    alice = e2e_env["alice"]
    eve = e2e_env["eve"]

    req = submit_access_request(db_session, paper.id, alice.id, required_approvals=3)
    db_session.commit()

    # Candidate Eve tries to vote
    with pytest.raises(InvalidApproverRoleError, match="requires one of"):
        approve_access_request(db_session, req.id, eve.id)
