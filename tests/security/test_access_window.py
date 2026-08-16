"""
TrustGuard — Just-In-Time (JIT) Access Validation & Access Window Tests.

Comprehensive security test suite verifying:
  1. Before window (now < start_time) -> DENY
  2. Exact start (now == start_time) -> ALLOW
  3. During window (start_time < now < end_time) -> ALLOW
  4. Exact end (now == end_time) -> ALLOW (inclusive boundary)
  5. After window (now > end_time) -> DENY
  6. Valid user but no quorum -> DENY
  7. Valid quorum but invalid time -> DENY
  8. Invalid role during window -> DENY
  9. Tampered fragment during valid window -> DENY (Integrity failure)
  10. End-to-end JIT execution gateway (decrypts on ALLOW, raises JITAccessDeniedError on DENY)
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
    RequestType,
    WindowStatus,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment
from database.models.user import User, Role, UserRole
from security.crypto.encryption import encrypt, decrypt
from security.crypto.fragmentation import protect_and_fragment_paper
from security.quorum import (
    create_access_request,
    cast_approval_vote,
)
from security.access_window import (
    AccessDecision,
    WindowTimeState,
    WindowScheduleError,
    JITAccessDeniedError,
    create_access_window,
    evaluate_window_time,
    sync_window_status,
    validate_jit_access,
    execute_jit_paper_access,
)


# ---------------------------------------------------------------------------
# Fixtures & Test Setup
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def exam_plaintext() -> bytes:
    return b"CONFIDENTIAL EXAM 2026: Quantum Computing Final Paper"


@pytest.fixture
def db_session():
    """In-memory SQLite database session with fresh schema for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def jit_setup(db_session: Session, master_key: bytes, exam_plaintext: bytes):
    """
    Sets up a fully configured environment:
    - User/Roles:
      - Officer (requester & accessor)
      - Approver 1, Approver 2, Approver 3
      - Candidate / Auditor (invalid role for access)
    - Protected & Fragmented Question Paper (5 shards)
    - Approved AccessRequest (3/3 quorum reached)
    - AccessWindow defined around T0: [T0, T0 + 1 hour]
    """
    # 1. Create Roles
    role_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    role_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
    role_auditor = Role(id=uuid.uuid4(), name="AUDITOR", description="Auditor")
    db_session.add_all([role_officer, role_approver, role_auditor])
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

    officer = make_user("officer@trustguard.org", "Exam Officer Dave", role_officer)
    app1 = make_user("app1@trustguard.org", "Approver One", role_approver)
    app2 = make_user("app2@trustguard.org", "Approver Two", role_approver)
    app3 = make_user("app3@trustguard.org", "Approver Three", role_approver)
    auditor = make_user("auditor@trustguard.org", "Auditor Dan", role_auditor)

    # 3. Create, Protect, and Fragment QuestionPaper
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="QC-FINAL-2026",
        paper_name="Quantum Computing and Cryptanalysis",
        status=PaperStatus.CREATED,
    )
    db_session.add(paper)
    db_session.flush()

    protect_and_fragment_paper(
        db=db_session,
        paper=paper,
        plaintext_data=exam_plaintext,
        key=master_key,
        num_fragments=5,
    )

    # 4. Create Access Request & Satisfy Quorum (3/3)
    req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Scheduled exam delivery session",
    )
    db_session.flush()

    cast_approval_vote(db_session, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, app3.id, ApprovalDecision.APPROVED)
    db_session.flush()

    assert req.status == RequestStatus.APPROVED

    # 5. Define Time Anchors
    t0 = datetime(2026, 6, 15, 10, 0, 0, tzinfo=timezone.utc)
    t_start = t0
    t_end = t0 + timedelta(hours=1)  # 10:00 to 11:00 UTC

    window = create_access_window(
        db=db_session,
        request_id=req.id,
        start_time=t_start,
        end_time=t_end,
        current_time=t0 - timedelta(minutes=30),  # scheduled before start
    )
    db_session.commit()

    return {
        "paper": paper,
        "officer": officer,
        "auditor": auditor,
        "request": req,
        "window": window,
        "t_start": t_start,
        "t_end": t_end,
        "master_key": master_key,
        "exam_plaintext": exam_plaintext,
    }


# ---------------------------------------------------------------------------
# 1. Before Window (now < start_time) -> DENY
# ---------------------------------------------------------------------------

def test_before_window_access_denied(db_session: Session, jit_setup: dict):
    """Test 1: Access attempted before the window opens (now < start_time) is DENIED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]

    # 15 minutes before window opens
    t_before = t_start - timedelta(minutes=15)

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_before,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert res.window_state == WindowTimeState.BEFORE_WINDOW
    assert "BEFORE_WINDOW" in res.reason


# ---------------------------------------------------------------------------
# 2. Exact Start (now == start_time) -> ALLOW
# ---------------------------------------------------------------------------

def test_exact_start_window_access_allowed(db_session: Session, jit_setup: dict):
    """Test 2: Access attempted exactly at window start timestamp (now == start_time) is ALLOWED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_start,
    )

    assert res.decision == AccessDecision.ALLOW
    assert res.is_allowed
    assert res.window_state == WindowTimeState.DURING_WINDOW
    assert all(res.checks.values())


# ---------------------------------------------------------------------------
# 3. During Window (start_time < now < end_time) -> ALLOW
# ---------------------------------------------------------------------------

def test_during_window_access_allowed(db_session: Session, jit_setup: dict):
    """Test 3: Access attempted midway through the active window is ALLOWED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]

    # 30 minutes into the 1-hour window
    t_during = t_start + timedelta(minutes=30)

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_during,
    )

    assert res.decision == AccessDecision.ALLOW
    assert res.is_allowed
    assert res.window_state == WindowTimeState.DURING_WINDOW


# ---------------------------------------------------------------------------
# 4. Exact End (now == end_time) -> ALLOW (Inclusive boundary)
# ---------------------------------------------------------------------------

def test_exact_end_window_access_allowed(db_session: Session, jit_setup: dict):
    """Test 4: Access attempted exactly at window end boundary (now == end_time) is ALLOWED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_end = jit_setup["t_end"]

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_end,
    )

    assert res.decision == AccessDecision.ALLOW
    assert res.is_allowed
    assert res.window_state == WindowTimeState.DURING_WINDOW


# ---------------------------------------------------------------------------
# 5. After Window (now > end_time) -> DENY
# ---------------------------------------------------------------------------

def test_after_window_access_denied(db_session: Session, jit_setup: dict):
    """Test 5: Access attempted after the window has closed (now > end_time) is DENIED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_end = jit_setup["t_end"]

    # 1 second after window closure
    t_after = t_end + timedelta(seconds=1)

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_after,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert res.window_state == WindowTimeState.AFTER_WINDOW
    assert "AFTER_WINDOW" in res.reason


# ---------------------------------------------------------------------------
# 6. Valid User But No Quorum -> DENY
# ---------------------------------------------------------------------------

def test_valid_user_no_quorum_access_denied(db_session: Session, jit_setup: dict):
    """Test 6: Valid officer with an active time window but unmet quorum is DENIED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    t_start = jit_setup["t_start"]
    t_during = t_start + timedelta(minutes=20)

    # Create a brand new request with 0 approvals
    unapproved_req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Second unapproved request",
    )
    db_session.commit()

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=unapproved_req.id,
        current_time=t_during,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert "Quorum check failed" in res.reason


# ---------------------------------------------------------------------------
# 7. Valid Quorum But Invalid Time -> DENY
# ---------------------------------------------------------------------------

def test_valid_quorum_invalid_time_access_denied(db_session: Session, jit_setup: dict):
    """Test 7: Full 3/3 quorum satisfied, but accessing 2 hours before window opens is DENIED."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]

    t_invalid = t_start - timedelta(hours=2)

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_invalid,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert not res.checks["time_window_valid"]


# ---------------------------------------------------------------------------
# 8. Invalid Role During Window -> DENY
# ---------------------------------------------------------------------------

def test_invalid_role_during_window_access_denied(db_session: Session, jit_setup: dict):
    """Test 8: User with unauthorized role (e.g. AUDITOR) accessing during window is DENIED."""
    paper = jit_setup["paper"]
    auditor = jit_setup["auditor"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]
    t_during = t_start + timedelta(minutes=15)

    res = validate_jit_access(
        db=db_session,
        user_id=auditor.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_during,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert "Permission check failed" in res.reason


# ---------------------------------------------------------------------------
# 9. Tampered Fragment During Valid Window -> DENY (Integrity Failure)
# ---------------------------------------------------------------------------

def test_tampered_fragment_during_window_access_denied(db_session: Session, jit_setup: dict):
    """Test 9: All identity, quorum, and time conditions pass, but tampered shard causes DENY."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    t_start = jit_setup["t_start"]
    t_during = t_start + timedelta(minutes=25)

    # Tamper with fragment 2 in database
    frag2 = (
        db_session.query(PaperFragment)
        .filter(
            PaperFragment.paper_id == paper.id,
            PaperFragment.fragment_index == 2,
        )
        .first()
    )
    tampered_bytes = bytearray(frag2.fragment_data)
    tampered_bytes[0] ^= 0xFF
    frag2.fragment_data = bytes(tampered_bytes)
    db_session.commit()

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_during,
    )

    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert not res.checks["integrity_valid"]
    assert "Integrity check failed" in res.reason


# ---------------------------------------------------------------------------
# 10. End-to-End JIT Gateway Execution
# ---------------------------------------------------------------------------

def test_execute_jit_paper_access_success(db_session: Session, jit_setup: dict):
    """Test 10: End-to-end execution gatekeeper decrypts paper when ALL security conditions pass."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    master_key = jit_setup["master_key"]
    exam_plaintext = jit_setup["exam_plaintext"]
    t_start = jit_setup["t_start"]
    t_during = t_start + timedelta(minutes=10)

    decrypted = execute_jit_paper_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        key=master_key,
        request_id=req.id,
        current_time=t_during,
    )

    assert decrypted == exam_plaintext


def test_execute_jit_paper_access_outside_window_raises_error(db_session: Session, jit_setup: dict):
    """Test 10b: End-to-end execution raises JITAccessDeniedError outside the window without exposing data."""
    paper = jit_setup["paper"]
    officer = jit_setup["officer"]
    req = jit_setup["request"]
    master_key = jit_setup["master_key"]
    t_end = jit_setup["t_end"]
    t_after = t_end + timedelta(minutes=5)

    with pytest.raises(JITAccessDeniedError, match="AFTER_WINDOW"):
        execute_jit_paper_access(
            db=db_session,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            current_time=t_after,
        )
