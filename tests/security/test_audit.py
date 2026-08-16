"""
TrustGuard — Security Audit & Lifecycle Completion Tests.

Comprehensive security test suite verifying:
  1. Successful access generates structured audit records (ACCESS_GRANTED, DECRYPTION_STARTED, DECRYPTION_COMPLETED).
  2. Denied access generates audit records (ACCESS_DENIED) and corresponding threat events.
  3. Integrity failure generates audit records (INTEGRITY_FAILURE) and critical threat events.
  4. Expired access cannot be reused.
  5. Completed request cannot be replayed (triggers REPLAY_ATTEMPT audit and threat events).
  6. Sensitive data (passwords, keys, tokens, plaintext exam papers) is NEVER written to audit records or metadata.
  7. SecureDecryptedBuffer actively clears and zeroes out temporary in-memory plaintext.
  8. Recursive metadata sanitization engine scrubs sensitive dictionary keys.
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
from security.crypto.fragmentation import protect_and_fragment_paper
from security.quorum import (
    create_access_request,
    cast_approval_vote,
)
from security.access_window import (
    AccessDecision,
    create_access_window,
    validate_jit_access,
    execute_jit_paper_access,
    JITAccessDeniedError,
)
from security.audit import (
    AuditEventType,
    sanitize_audit_metadata,
    log_security_event,
    record_threat_incident,
    SecureDecryptedBuffer,
    complete_access_session,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    return os.urandom(32)


@pytest.fixture
def secret_plaintext() -> bytes:
    return b"TOP_SECRET_EXAM_PAPER_2026: National Cybersecurity Board Questions"


@pytest.fixture
def db_session():
    """In-memory SQLite database session with fresh schema."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def audit_test_setup(db_session: Session, master_key: bytes, secret_plaintext: bytes):
    """
    Sets up a fully configured environment:
    - Officer user
    - Approvers (App1, App2, App3)
    - Fragmented QuestionPaper (5 shards)
    - Approved AccessRequest (3/3 quorum)
    - Active AccessWindow: [T0, T0 + 1 hour]
    """
    # 1. Create Roles
    role_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Officer")
    role_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Approver")
    db_session.add_all([role_officer, role_approver])
    db_session.flush()

    # 2. Create Users
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

    officer = make_user("officer@trustguard.org", "Exam Officer", role_officer)
    app1 = make_user("app1@trustguard.org", "Approver 1", role_approver)
    app2 = make_user("app2@trustguard.org", "Approver 2", role_approver)
    app3 = make_user("app3@trustguard.org", "Approver 3", role_approver)

    # 3. Create, Protect, and Fragment Paper
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="CYBER-FINAL-2026",
        paper_name="Advanced Cryptography",
        status=PaperStatus.CREATED,
    )
    db_session.add(paper)
    db_session.flush()

    protect_and_fragment_paper(
        db=db_session,
        paper=paper,
        plaintext_data=secret_plaintext,
        key=master_key,
        num_fragments=5,
    )

    # 4. Request and Quorum
    req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=officer.id,
        required_approvals=3,
        reason="Scheduled test session",
    )
    db_session.flush()

    cast_approval_vote(db_session, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, app3.id, ApprovalDecision.APPROVED)
    db_session.flush()

    # 5. Access Window
    t0 = datetime(2026, 7, 1, 9, 0, 0, tzinfo=timezone.utc)
    t_start = t0
    t_end = t0 + timedelta(hours=2)

    window = create_access_window(
        db=db_session,
        request_id=req.id,
        start_time=t_start,
        end_time=t_end,
        current_time=t0,
    )
    db_session.commit()

    return {
        "paper": paper,
        "officer": officer,
        "request": req,
        "window": window,
        "t_start": t_start,
        "t_end": t_end,
        "master_key": master_key,
        "secret_plaintext": secret_plaintext,
    }


# ---------------------------------------------------------------------------
# 1. Successful Access Generates Audit Records
# ---------------------------------------------------------------------------

def test_successful_access_generates_audit(db_session: Session, audit_test_setup: dict):
    """Test 1: Successful paper access generates ACCESS_GRANTED, DECRYPTION_STARTED, DECRYPTION_COMPLETED logs."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    req = audit_test_setup["request"]
    key = audit_test_setup["master_key"]
    t_during = audit_test_setup["t_start"] + timedelta(minutes=15)

    initial_audit_count = db_session.query(AuditLog).count()

    decrypted = execute_jit_paper_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        key=key,
        request_id=req.id,
        current_time=t_during,
        actor_ip="192.168.1.50",
    )
    db_session.commit()

    assert decrypted == audit_test_setup["secret_plaintext"]

    # Verify audit logs created
    audit_logs = (
        db_session.query(AuditLog)
        .filter(AuditLog.target_id == paper.id)
        .order_by(AuditLog.timestamp.asc())
        .all()
    )
    actions = [log.action for log in audit_logs]
    
    assert AuditEventType.ACCESS_GRANTED.value in actions
    assert AuditEventType.DECRYPTION_STARTED.value in actions
    assert AuditEventType.DECRYPTION_COMPLETED.value in actions

    # Verify log captures WHO, WHAT, WHEN, WHICH RESOURCE, WHAT RESULT, WHY
    completion_log = [l for l in audit_logs if l.action == AuditEventType.DECRYPTION_COMPLETED.value][0]
    assert completion_log.actor_id == officer.id
    assert completion_log.actor_ip == "192.168.1.50"
    assert completion_log.target_type == "question_paper"
    assert completion_log.target_id == paper.id
    assert completion_log.result == AuditResult.SUCCESS
    assert "completed successfully" in completion_log.reason
    assert completion_log.timestamp is not None


# ---------------------------------------------------------------------------
# 2. Denied Access Generates Audit Records and Threat Events
# ---------------------------------------------------------------------------

def test_denied_access_generates_audit_and_threat_event(db_session: Session, audit_test_setup: dict):
    """Test 2: Access denied outside window generates ACCESS_DENIED audit log and threat record."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    req = audit_test_setup["request"]
    key = audit_test_setup["master_key"]
    t_before = audit_test_setup["t_start"] - timedelta(hours=1)

    with pytest.raises(JITAccessDeniedError, match="BEFORE_WINDOW"):
        execute_jit_paper_access(
            db=db_session,
            user_id=officer.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_before,
            actor_ip="10.0.0.1",
        )
    db_session.commit()

    # Verify ACCESS_DENIED audit record exists
    denied_log = (
        db_session.query(AuditLog)
        .filter(
            AuditLog.target_id == paper.id,
            AuditLog.action == AuditEventType.ACCESS_DENIED.value,
        )
        .first()
    )
    assert denied_log is not None
    assert denied_log.result == AuditResult.DENIED
    assert denied_log.actor_id == officer.id
    assert denied_log.actor_ip == "10.0.0.1"
    assert "BEFORE_WINDOW" in denied_log.reason


# ---------------------------------------------------------------------------
# 3. Integrity Failure Generates Critical Audit and Threat Event
# ---------------------------------------------------------------------------

def test_integrity_failure_generates_audit_and_critical_threat(db_session: Session, audit_test_setup: dict):
    """Test 3: Tampered shard triggers INTEGRITY_FAILURE audit log and CRITICAL ThreatEvent."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    req = audit_test_setup["request"]
    key = audit_test_setup["master_key"]
    t_during = audit_test_setup["t_start"] + timedelta(minutes=10)

    # Corrupt shard 1
    frag1 = (
        db_session.query(PaperFragment)
        .filter(
            PaperFragment.paper_id == paper.id,
            PaperFragment.fragment_index == 1,
        )
        .first()
    )
    corrupted_data = bytearray(frag1.fragment_data)
    corrupted_data[5] ^= 0xAA
    frag1.fragment_data = bytes(corrupted_data)
    db_session.commit()

    with pytest.raises(JITAccessDeniedError, match="Integrity check failed"):
        execute_jit_paper_access(
            db=db_session,
            user_id=officer.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_during,
            actor_ip="192.168.1.100",
        )
    db_session.commit()

    # Verify INTEGRITY_FAILURE audit log
    audit_log = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == AuditEventType.INTEGRITY_FAILURE.value)
        .first()
    )
    assert audit_log is not None
    assert audit_log.result == AuditResult.DENIED
    assert "Integrity check failed" in audit_log.reason

    # Verify CRITICAL ThreatEvent
    threat = (
        db_session.query(ThreatEvent)
        .filter(ThreatEvent.event_type == ThreatEventType.INTEGRITY_FAILURE)
        .first()
    )
    assert threat is not None
    assert threat.severity == ThreatSeverity.CRITICAL
    assert threat.target_id == paper.id
    assert not threat.resolved


# ---------------------------------------------------------------------------
# 4. Expired Access Cannot Be Reused
# ---------------------------------------------------------------------------

def test_expired_access_cannot_be_reused(db_session: Session, audit_test_setup: dict):
    """Test 4: Once access window expires, subsequent access attempts are DENIED."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    req = audit_test_setup["request"]
    key = audit_test_setup["master_key"]
    t_after = audit_test_setup["t_end"] + timedelta(seconds=10)

    res = validate_jit_access(
        db=db_session,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=t_after,
    )
    assert res.decision == AccessDecision.DENY
    assert not res.is_allowed
    assert "AFTER_WINDOW" in res.reason


# ---------------------------------------------------------------------------
# 5. Completed Request Cannot Be Replayed
# ---------------------------------------------------------------------------

def test_completed_request_cannot_be_replayed(db_session: Session, audit_test_setup: dict):
    """Test 5: Completed access session expires request and blocks replay attempts with REPLAY_ATTEMPT logs."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    req = audit_test_setup["request"]
    key = audit_test_setup["master_key"]
    t_during = audit_test_setup["t_start"] + timedelta(minutes=30)

    # 1. Complete session normally
    completion_report = complete_access_session(
        db=db_session,
        paper_id=paper.id,
        request_id=req.id,
        actor_id=officer.id,
        reason="Exam administration concluded",
    )
    db_session.commit()

    assert completion_report["session_state"] == "session closed"
    assert completion_report["access_state"] == "access expired"
    assert completion_report["replay_protection"] == "active"
    assert paper.status == PaperStatus.COMPLETED

    # 2. Attempt replay access using the completed request
    with pytest.raises(JITAccessDeniedError, match="replay prevented"):
        execute_jit_paper_access(
            db=db_session,
            user_id=officer.id,
            paper_id=paper.id,
            key=key,
            request_id=req.id,
            current_time=t_during,
        )
    db_session.commit()

    # 3. Verify REPLAY_ATTEMPT audit log and ThreatEvent
    replay_log = (
        db_session.query(AuditLog)
        .filter(AuditLog.action == AuditEventType.REPLAY_ATTEMPT.value)
        .first()
    )
    assert replay_log is not None
    assert replay_log.result == AuditResult.DENIED

    replay_threat = (
        db_session.query(ThreatEvent)
        .filter(ThreatEvent.event_type == ThreatEventType.REPLAY_ATTEMPT)
        .first()
    )
    assert replay_threat is not None
    assert replay_threat.severity == ThreatSeverity.HIGH


# ---------------------------------------------------------------------------
# 6. Sensitive Data is Never Written to Logs
# ---------------------------------------------------------------------------

def test_sensitive_data_not_written_to_audit_logs(db_session: Session, audit_test_setup: dict):
    """Test 6: Raw passwords, keys, tokens, and exam content are never persisted in audit logs or metadata."""
    paper = audit_test_setup["paper"]
    officer = audit_test_setup["officer"]
    key = audit_test_setup["master_key"]
    secret_text = audit_test_setup["secret_plaintext"]

    # Log an event with potentially sensitive dictionary fields
    raw_metadata = {
        "user_password": "PlaintextPassword123!",
        "jwt_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
        "master_key": key.hex(),
        "exam_content": secret_text.decode("utf-8"),
        "safe_metric": 42,
        "nested": {
            "secret_key": "SuperSecretKey999",
            "safe_description": "Standard audit payload",
        },
    }

    log_entry = log_security_event(
        db=db_session,
        action=AuditEventType.PAPER_ENCRYPTED,
        result=AuditResult.SUCCESS,
        actor_id=officer.id,
        target_type="question_paper",
        target_id=paper.id,
        reason="Encrypted paper manifest",
        extra_data=raw_metadata,
    )
    db_session.commit()

    # Verify sensitive fields are redacted in DB
    retrieved = db_session.get(AuditLog, log_entry.id)
    extra = retrieved.extra_data

    assert extra["user_password"] == "[REDACTED]"
    assert extra["jwt_token"] == "[REDACTED]"
    assert extra["master_key"] == "[REDACTED]"
    assert extra["exam_content"] == "[REDACTED]"
    assert extra["safe_metric"] == 42
    assert extra["nested"]["secret_key"] == "[REDACTED]"
    assert extra["nested"]["safe_description"] == "Standard audit payload"

    # Search entire database for secrets
    all_logs = db_session.query(AuditLog).all()
    for entry in all_logs:
        str_repr = f"{entry.reason} {entry.extra_data}"
        assert "PlaintextPassword123!" not in str_repr
        assert key.hex() not in str_repr
        assert secret_text.decode("utf-8") not in str_repr


# ---------------------------------------------------------------------------
# 7. SecureDecryptedBuffer Memory Wiping
# ---------------------------------------------------------------------------

def test_secure_decrypted_buffer_wipes_memory():
    """Test 7: SecureDecryptedBuffer zeroes out temporary representation upon context exit."""
    raw_secret = b"HIGHLY_CONFIDENTIAL_EXAM_BUFFER_DATA"

    with SecureDecryptedBuffer(raw_secret) as buf:
        assert buf.get_data() == raw_secret
        assert not buf._is_wiped

    # After exit, buffer is actively wiped
    assert buf._is_wiped
    with pytest.raises(RuntimeError, match="temporary representation removed"):
        buf.get_data()


# ---------------------------------------------------------------------------
# 8. Metadata Sanitization Engine Unit Test
# ---------------------------------------------------------------------------

def test_metadata_sanitization_engine():
    """Test 8: sanitize_audit_metadata recursively scrubs keys and binary payloads."""
    payload = {
        "API_SECRET": "abc123secret",
        "nested_dict": {
            "user_token": "token_val",
            "regular_info": "visible",
        },
        "items": [
            {"password_hash": "$2b$12$..."},
            {"status": "ok"},
        ],
        "binary": b"\x00\x01\x02\x03\x04",
    }

    sanitized = sanitize_audit_metadata(payload)

    assert sanitized["API_SECRET"] == "[REDACTED]"
    assert sanitized["nested_dict"]["user_token"] == "[REDACTED]"
    assert sanitized["nested_dict"]["regular_info"] == "visible"
    assert sanitized["items"][0]["password_hash"] == "[REDACTED]"
    assert sanitized["items"][1]["status"] == "ok"
    assert sanitized["binary"] == "<5 bytes binary payload>"
