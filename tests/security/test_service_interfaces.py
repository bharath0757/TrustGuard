"""
TrustGuard — Security Service Interfaces Test Suite.

Unit tests specifically validating the 11 clean service interfaces exposed to the backend developer:
1.  protect_paper()
2.  fragment_paper()
3.  validate_fragments()
4.  create_access_request()
5.  check_quorum()
6.  is_access_window_valid()
7.  authorize_access()
8.  reconstruct_paper()
9.  decrypt_paper()
10. complete_access()
11. create_audit_event()
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
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    protect_paper,
    fragment_paper,
    validate_fragments,
    create_access_request,
    check_quorum,
    is_access_window_valid,
    authorize_access,
    reconstruct_paper,
    decrypt_paper,
    complete_access,
    create_audit_event,
    WindowTimeState,
    AccessDecision,
    AuditEventType,
)
from security.crypto.fragmentation import FragmentValidationError, FragmentIntegrityError
from security.crypto.encryption import DecryptionFailedError


@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def test_payload() -> bytes:
    return b"CONFIDENTIAL QUESTION PAPER CONTENT 2026"


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
def service_env(db_session: Session, master_key: bytes, test_payload: bytes):
    """Sets up roles, users, and a paper record."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
    db_session.add_all([r_officer, r_approver])
    db_session.flush()

    def make_user(email: str, name: str, role: Role) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash="fake_hash",
            full_name=name,
            is_active=True,
        )
        db_session.add(u)
        db_session.flush()
        ur = UserRole(user_id=u.id, role_id=role.id)
        db_session.add(ur)
        db_session.flush()
        return u

    officer = make_user("officer@trustguard.org", "Officer One", r_officer)
    app1 = make_user("app1@trustguard.org", "Approver One", r_approver)
    app2 = make_user("app2@trustguard.org", "Approver Two", r_approver)
    app3 = make_user("app3@trustguard.org", "Approver Three", r_approver)

    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="EXAM-2026-CS",
        paper_name="Computer Networks",
        status=PaperStatus.CREATED,
        created_by=officer.id,
    )
    db_session.add(paper)
    db_session.commit()

    return {
        "paper": paper,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "app3": app3,
        "master_key": master_key,
        "test_payload": test_payload,
    }


# ---------------------------------------------------------------------------
# Tests for Service Interfaces 1 & 2: protect_paper & fragment_paper
# ---------------------------------------------------------------------------

def test_protect_and_fragment_paper(db_session: Session, service_env: dict):
    """Verify protect_paper() and fragment_paper() service boundaries."""
    paper = service_env["paper"]
    officer = service_env["officer"]
    key = service_env["master_key"]
    payload = service_env["test_payload"]

    # 1. Protect Paper
    protected = protect_paper(
        db=db_session,
        paper_id=paper.id,
        plaintext_data=payload,
        key=key,
        actor_id=officer.id,
    )
    db_session.commit()

    assert protected.status == PaperStatus.PROTECTED
    assert protected.integrity_hash is not None
    assert protected.protected_at is not None

    # 2. Fragment Paper
    fragments = fragment_paper(
        db=db_session,
        paper_id=paper.id,
        num_fragments=5,
        actor_id=officer.id,
    )
    db_session.commit()

    assert len(fragments) == 5
    assert paper.status == PaperStatus.FRAGMENTED
    assert paper.total_fragments == 5
    for idx, frag in enumerate(fragments):
        assert frag.fragment_index == idx
        assert frag.paper_id == paper.id
        assert frag.status == FragmentStatus.STORED


# ---------------------------------------------------------------------------
# Test for Service Interface 3: validate_fragments
# ---------------------------------------------------------------------------

def test_validate_fragments_interface(db_session: Session, service_env: dict):
    """Verify validate_fragments() sorts and validates shard arrays."""
    paper = service_env["paper"]
    key = service_env["master_key"]
    payload = service_env["test_payload"]

    protect_paper(db_session, paper.id, payload, key)
    fragments = fragment_paper(db_session, paper.id, num_fragments=4)
    db_session.commit()

    # Pass in shuffled fragments
    shuffled = [fragments[2], fragments[0], fragments[3], fragments[1]]
    validated = validate_fragments(shuffled, expected_paper_id=paper.id, expected_count=4)

    assert len(validated) == 4
    assert [f.fragment_index for f in validated] == [0, 1, 2, 3]


# ---------------------------------------------------------------------------
# Tests for Service Interfaces 4 & 5: create_access_request & check_quorum
# ---------------------------------------------------------------------------

def test_access_request_and_check_quorum(db_session: Session, service_env: dict):
    """Verify create_access_request() and check_quorum() interfaces."""
    paper = service_env["paper"]
    officer = service_env["officer"]
    app1 = service_env["app1"]
    app2 = service_env["app2"]
    app3 = service_env["app3"]

    # 4. Create Access Request
    req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Scheduled exam session",
    )
    db_session.commit()

    assert req.status == RequestStatus.PENDING
    assert req.paper_id == paper.id
    assert req.required_approvals == 3

    # 5. Check Quorum initial state
    q_initial = check_quorum(db_session, req.id)
    assert not q_initial.is_authorized
    assert q_initial.approved_count == 0
    assert q_initial.required_approvals == 3

    # Cast votes and check quorum progression
    from security import approve_access_request
    approve_access_request(db_session, req.id, app1.id)
    approve_access_request(db_session, req.id, app2.id)
    q_progress = check_quorum(db_session, req.id)
    assert not q_progress.is_authorized
    assert q_progress.approved_count == 2

    approve_access_request(db_session, req.id, app3.id)
    q_final = check_quorum(db_session, req.id)
    assert q_final.is_authorized
    assert q_final.approved_count == 3
    assert req.status == RequestStatus.APPROVED


# ---------------------------------------------------------------------------
# Test for Service Interface 6: is_access_window_valid
# ---------------------------------------------------------------------------

def test_is_access_window_valid_interface(db_session: Session, service_env: dict):
    """Verify is_access_window_valid() reports temporal states accurately."""
    paper = service_env["paper"]
    officer = service_env["officer"]
    app1 = service_env["app1"]
    app2 = service_env["app2"]
    app3 = service_env["app3"]

    req = create_access_request(db_session, paper.id, officer.id, required_approvals=3)
    from security import approve_access_request, schedule_access_window
    approve_access_request(db_session, req.id, app1.id)
    approve_access_request(db_session, req.id, app2.id)
    approve_access_request(db_session, req.id, app3.id)

    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    t_start = t0
    t_end = t0 + timedelta(hours=2)

    window = schedule_access_window(db_session, req.id, t_start, t_end)
    db_session.commit()

    # Before window
    is_valid, state = is_access_window_valid(db_session, window.id, current_time=t0 - timedelta(minutes=15))
    assert not is_valid
    assert state == WindowTimeState.BEFORE_WINDOW

    # During window
    is_valid, state = is_access_window_valid(db_session, window.id, current_time=t0 + timedelta(minutes=30))
    assert is_valid
    assert state == WindowTimeState.DURING_WINDOW

    # After window
    is_valid, state = is_access_window_valid(db_session, window.id, current_time=t_end + timedelta(minutes=5))
    assert not is_valid
    assert state == WindowTimeState.AFTER_WINDOW


# ---------------------------------------------------------------------------
# Test for Service Interface 7: authorize_access
# ---------------------------------------------------------------------------

def test_authorize_access_interface(db_session: Session, service_env: dict):
    """Verify authorize_access() 6-factor JIT evaluation."""
    paper = service_env["paper"]
    officer = service_env["officer"]
    app1 = service_env["app1"]
    app2 = service_env["app2"]
    app3 = service_env["app3"]
    key = service_env["master_key"]
    payload = service_env["test_payload"]

    protect_paper(db_session, paper.id, payload, key)
    fragment_paper(db_session, paper.id, num_fragments=3)

    req = create_access_request(db_session, paper.id, officer.id, required_approvals=3)
    from security import approve_access_request, schedule_access_window
    approve_access_request(db_session, req.id, app1.id)
    approve_access_request(db_session, req.id, app2.id)
    approve_access_request(db_session, req.id, app3.id)

    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    schedule_access_window(db_session, req.id, t0, t0 + timedelta(hours=1))
    db_session.commit()

    # Authorize access during window
    res = authorize_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t0 + timedelta(minutes=10),
    )

    assert res.decision == AccessDecision.ALLOW
    assert res.is_allowed
    assert res.checks["identity_valid"]
    assert res.checks["permission_valid"]
    assert res.checks["request_valid"]
    assert res.checks["quorum_valid"]
    assert res.checks["time_window_valid"]
    assert res.checks["integrity_valid"]


# ---------------------------------------------------------------------------
# Tests for Service Interfaces 8 & 9: reconstruct_paper & decrypt_paper
# ---------------------------------------------------------------------------

def test_reconstruct_and_decrypt_paper(db_session: Session, service_env: dict):
    """Verify reconstruct_paper() and decrypt_paper() service boundaries."""
    paper = service_env["paper"]
    key = service_env["master_key"]
    payload = service_env["test_payload"]

    protect_paper(db_session, paper.id, payload, key)
    fragment_paper(db_session, paper.id, num_fragments=5)
    db_session.commit()

    # 8. Reconstruct Paper
    reconstructed_ciphertext = reconstruct_paper(db_session, paper.id)
    assert isinstance(reconstructed_ciphertext, bytes)
    assert len(reconstructed_ciphertext) > len(payload)

    # 9. Decrypt Paper
    decrypted_content = decrypt_paper(
        ciphertext_payload=reconstructed_ciphertext,
        key=key,
        expected_manifest_hash=paper.integrity_hash,
    )
    assert decrypted_content == payload

    # Decrypt with wrong key fails safely
    wrong_key = os.urandom(32)
    with pytest.raises(DecryptionFailedError):
        decrypt_paper(reconstructed_ciphertext, key=wrong_key)


# ---------------------------------------------------------------------------
# Tests for Service Interfaces 10 & 11: complete_access & create_audit_event
# ---------------------------------------------------------------------------

def test_complete_access_and_create_audit_event(db_session: Session, service_env: dict):
    """Verify complete_access() and create_audit_event() service interfaces."""
    paper = service_env["paper"]
    officer = service_env["officer"]
    app1 = service_env["app1"]
    app2 = service_env["app2"]
    app3 = service_env["app3"]

    req = create_access_request(db_session, paper.id, officer.id, required_approvals=3)
    from security import approve_access_request, schedule_access_window
    approve_access_request(db_session, req.id, app1.id)
    approve_access_request(db_session, req.id, app2.id)
    approve_access_request(db_session, req.id, app3.id)

    t0 = datetime(2026, 9, 1, 10, 0, 0, tzinfo=timezone.utc)
    window = schedule_access_window(db_session, req.id, t0, t0 + timedelta(hours=1))
    db_session.commit()

    # 10. Complete Access
    report = complete_access(
        db=db_session,
        paper_id=paper.id,
        request_id=req.id,
        actor_id=officer.id,
        reason="Exam session finished",
    )
    db_session.commit()

    assert report["session_state"] == "session closed"
    assert report["access_state"] == "access expired"
    assert report["replay_protection"] == "active"
    assert window.status == WindowStatus.CLOSED
    assert req.status == RequestStatus.EXPIRED
    assert paper.status == PaperStatus.COMPLETED

    # 11. Create Audit Event
    audit_entry = create_audit_event(
        db=db_session,
        action="CUSTOM_ADMIN_OPERATION",
        result=AuditResult.SUCCESS,
        actor_id=officer.id,
        target_type="question_paper",
        target_id=paper.id,
        reason="Admin performed verified action",
        extra_data={"flag": True},
    )
    db_session.commit()

    assert audit_entry.id is not None
    assert audit_entry.action == "CUSTOM_ADMIN_OPERATION"
    assert audit_entry.result == AuditResult.SUCCESS
    assert audit_entry.actor_id == officer.id
