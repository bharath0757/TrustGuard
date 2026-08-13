"""
TrustGuard — database model tests.

Validates the ORM schema using an in-memory SQLite database.
No running PostgreSQL instance is required.

Test coverage:
  TC-01  All 10 tables created by create_all()
  TC-02  All ENUM values accepted on INSERT
  TC-03  UNIQUE constraint: duplicate user email raises IntegrityError
  TC-04  UNIQUE constraint: duplicate (paper_id, fragment_index) raises IntegrityError
  TC-05  UNIQUE constraint: duplicate approver vote raises IntegrityError
  TC-06  UNIQUE constraint: second access window for the same request raises IntegrityError
  TC-07  CHECK constraint: access_window end_time <= start_time raises IntegrityError
  TC-08  FK cascade: deleting a QuestionPaper removes its PaperFragment rows
  TC-09  Relationship traversal: User → UserRole → Role round-trip
  TC-10  Relationship traversal: QuestionPaper → PaperFragment
  TC-11  Relationship traversal: AccessRequest → Approvals
  TC-12  audit_logs has NO updated_at column (immutability by construction)
  TC-13  Quorum calculation via SQL COUNT on approvals
  TC-14  PaperFragment.fragment_data accepts raw bytes (BYTEA / BLOB)
  TC-15  All 10 table names exist in Base.metadata
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy import event as sa_event

from database.base import Base
from database.models import (
    User,
    Role,
    UserRole,
    QuestionPaper,
    PaperStatus,
    PaperFragment,
    FragmentStatus,
    AccessRequest,
    RequestType,
    RequestStatus,
    Approval,
    ApprovalDecision,
    AccessWindow,
    WindowStatus,
    AuditLog,
    AuditResult,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def engine():
    """
    In-memory SQLite engine with FK enforcement enabled.
    Created once per test session; all tables are created on first use.
    """
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    # SQLite requires explicit PRAGMA to honour FK constraints.
    @sa_event.listens_for(_engine, "connect")
    def _enable_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(_engine)
    yield _engine
    Base.metadata.drop_all(_engine)
    _engine.dispose()


@pytest.fixture
def db(engine):
    """
    Function-scoped session.  Rolls back after every test so each test
    starts with a clean slate.
    """
    session = Session(engine)
    yield session
    session.rollback()
    session.close()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_user(email: str = None, *, is_system: bool = False) -> User:
    uid = uuid.uuid4()
    return User(
        id=uid,
        email=email or f"user-{uid}@example.com",
        password_hash="$argon2id$...",
        full_name="Test User",
        is_active=True,
        is_system=is_system,
    )


def make_paper(creator_id=None) -> QuestionPaper:
    return QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="GATE-2026-CS",
        paper_name="Computer Science Paper I",
        status=PaperStatus.CREATED,
        created_by=creator_id,
    )


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# TC-01  All 10 tables created
# ---------------------------------------------------------------------------

EXPECTED_TABLES = {
    "users", "roles", "user_roles",
    "question_papers", "paper_fragments",
    "access_requests", "approvals", "access_windows",
    "audit_logs", "threat_events",
}


def test_all_tables_in_metadata():
    """TC-01a: Base.metadata knows all 10 table names."""
    assert EXPECTED_TABLES.issubset(set(Base.metadata.tables.keys())), (
        f"Missing tables: {EXPECTED_TABLES - set(Base.metadata.tables.keys())}"
    )


def test_all_tables_exist_in_db(engine):
    """TC-01b: All 10 tables exist in the SQLite schema."""
    inspector = inspect(engine)
    existing = set(inspector.get_table_names())
    missing = EXPECTED_TABLES - existing
    assert not missing, f"Tables missing from DB: {missing}"


# ---------------------------------------------------------------------------
# TC-02  ENUM values accepted
# ---------------------------------------------------------------------------

def test_paper_status_enum_values(db):
    """TC-02a: All PaperStatus values are accepted by SQLite."""
    user = make_user()
    db.add(user)
    db.flush()

    for status in PaperStatus:
        paper = QuestionPaper(
            id=uuid.uuid4(),
            exam_identifier=f"EXAM-{status.value}",
            paper_name="Test Paper",
            status=status,
            created_by=user.id,
        )
        db.add(paper)
    db.flush()


def test_fragment_status_enum_values(db):
    """TC-02b: All FragmentStatus values are accepted."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    for idx, status in enumerate(FragmentStatus):
        frag = PaperFragment(
            id=uuid.uuid4(),
            paper_id=paper.id,
            fragment_index=idx,
            fragment_data=b"ciphertext",
            integrity_hash="abc123",
            status=status,
        )
        db.add(frag)
    db.flush()


def test_threat_event_enum_values(db):
    """TC-02c: All ThreatEventType and ThreatSeverity values are accepted."""
    user = make_user()
    db.add(user)
    db.flush()

    for et in ThreatEventType:
        for sev in ThreatSeverity:
            te = ThreatEvent(
                id=uuid.uuid4(),
                event_type=et,
                severity=sev,
                description=f"{et.value} at {sev.value}",
                resolved=False,
            )
            db.add(te)
    db.flush()


# ---------------------------------------------------------------------------
# TC-03  UNIQUE: duplicate email
# ---------------------------------------------------------------------------

def test_duplicate_email_raises(db):
    """TC-03: Inserting two users with the same email must raise IntegrityError."""
    u1 = make_user(email="duplicate@example.com")
    u2 = make_user(email="duplicate@example.com")
    db.add(u1)
    db.flush()
    db.add(u2)
    with pytest.raises(IntegrityError):
        db.flush()


# ---------------------------------------------------------------------------
# TC-04  UNIQUE: duplicate (paper_id, fragment_index)
# ---------------------------------------------------------------------------

def test_duplicate_fragment_index_raises(db):
    """TC-04: Two fragments with the same (paper_id, index) must fail."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    f1 = PaperFragment(
        id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
        fragment_data=b"abc", integrity_hash="h1", status=FragmentStatus.STORED,
    )
    f2 = PaperFragment(
        id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,  # duplicate index
        fragment_data=b"xyz", integrity_hash="h2", status=FragmentStatus.STORED,
    )
    db.add(f1)
    db.flush()
    db.add(f2)
    with pytest.raises(IntegrityError):
        db.flush()


# ---------------------------------------------------------------------------
# TC-05  UNIQUE: duplicate approver vote
# ---------------------------------------------------------------------------

def test_duplicate_approver_vote_raises(db):
    """TC-05: The same approver cannot vote twice on the same request."""
    requester = make_user()
    approver = make_user()
    db.add_all([requester, approver])
    db.flush()

    paper = make_paper(requester.id)
    db.add(paper)
    db.flush()

    req = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper.id,
        requested_by=requester.id,
        request_type=RequestType.RECONSTRUCT,
        status=RequestStatus.PENDING,
        required_approvals=2,
        reason="Exam day reconstruction",
    )
    db.add(req)
    db.flush()

    vote1 = Approval(
        id=uuid.uuid4(),
        request_id=req.id,
        approved_by=approver.id,
        decision=ApprovalDecision.APPROVED,
        created_at=utcnow(),
    )
    vote2 = Approval(
        id=uuid.uuid4(),
        request_id=req.id,
        approved_by=approver.id,  # same approver — duplicate
        decision=ApprovalDecision.REJECTED,
        created_at=utcnow(),
    )
    db.add(vote1)
    db.flush()
    db.add(vote2)
    with pytest.raises(IntegrityError):
        db.flush()


# ---------------------------------------------------------------------------
# TC-06  UNIQUE: second access window for same request
# ---------------------------------------------------------------------------

def test_duplicate_access_window_raises(db):
    """TC-06: Two access windows for the same request must fail."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    req = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper.id,
        requested_by=user.id,
        request_type=RequestType.VIEW,
        status=RequestStatus.APPROVED,
        required_approvals=1,
        reason="Viewing metadata",
    )
    db.add(req)
    db.flush()

    now = utcnow()
    w1 = AccessWindow(
        id=uuid.uuid4(),
        paper_id=paper.id,
        request_id=req.id,
        start_time=now,
        end_time=now + timedelta(hours=2),
        status=WindowStatus.SCHEDULED,
    )
    w2 = AccessWindow(
        id=uuid.uuid4(),
        paper_id=paper.id,
        request_id=req.id,  # same request — duplicate
        start_time=now,
        end_time=now + timedelta(hours=3),
        status=WindowStatus.SCHEDULED,
    )
    db.add(w1)
    db.flush()
    db.add(w2)
    with pytest.raises(IntegrityError):
        db.flush()


# ---------------------------------------------------------------------------
# TC-07  CHECK: end_time must be after start_time
# ---------------------------------------------------------------------------

def test_access_window_end_before_start_raises(db):
    """TC-07: end_time <= start_time must fail the CHECK constraint."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    req = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper.id,
        requested_by=user.id,
        request_type=RequestType.VIEW,
        status=RequestStatus.APPROVED,
        required_approvals=1,
        reason="Test",
    )
    db.add(req)
    db.flush()

    now = utcnow()
    bad_window = AccessWindow(
        id=uuid.uuid4(),
        paper_id=paper.id,
        request_id=req.id,
        start_time=now,
        end_time=now - timedelta(hours=1),  # end BEFORE start — invalid
        status=WindowStatus.SCHEDULED,
    )
    db.add(bad_window)
    with pytest.raises(IntegrityError):
        db.flush()


# ---------------------------------------------------------------------------
# TC-08  FK cascade: deleting paper removes fragments
# ---------------------------------------------------------------------------

def test_cascade_delete_paper_removes_fragments(db):
    """TC-08: Deleting a QuestionPaper must cascade-delete its PaperFragments."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    for i in range(3):
        frag = PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=i,
            fragment_data=b"data", integrity_hash=f"h{i}", status=FragmentStatus.STORED,
        )
        db.add(frag)
    db.flush()

    paper_id = paper.id
    db.delete(paper)
    db.flush()

    remaining = db.query(PaperFragment).filter_by(paper_id=paper_id).count()
    assert remaining == 0, "Cascade delete failed — fragments remain after paper deletion"


# ---------------------------------------------------------------------------
# TC-09  Relationship traversal: User → UserRole → Role
# ---------------------------------------------------------------------------

def test_user_role_relationship_traversal(db):
    """TC-09: ORM relationship User → UserRole → Role is traversable."""
    user = make_user()
    role = Role(id=uuid.uuid4(), name="APPROVER", description="Can approve requests")
    db.add_all([user, role])
    db.flush()

    user_role = UserRole(
        user_id=user.id,
        role_id=role.id,
        granted_by=None,
    )
    db.add(user_role)
    db.flush()
    db.expire_all()

    loaded_user = db.get(User, user.id)
    assert len(loaded_user.user_roles) == 1
    assert loaded_user.user_roles[0].role.name == "APPROVER"


# ---------------------------------------------------------------------------
# TC-10  Relationship traversal: QuestionPaper → PaperFragment
# ---------------------------------------------------------------------------

def test_paper_fragments_relationship_traversal(db):
    """TC-10: ORM relationship QuestionPaper → PaperFragment is traversable."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    for i in range(3):
        db.add(PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=i,
            fragment_data=b"data", integrity_hash=f"h{i}", status=FragmentStatus.STORED,
        ))
    db.flush()
    db.expire_all()

    loaded = db.get(QuestionPaper, paper.id)
    assert len(loaded.fragments) == 3
    indices = sorted(f.fragment_index for f in loaded.fragments)
    assert indices == [0, 1, 2]


# ---------------------------------------------------------------------------
# TC-11  Relationship traversal: AccessRequest → Approvals
# ---------------------------------------------------------------------------

def test_access_request_approvals_traversal(db):
    """TC-11: ORM relationship AccessRequest → Approvals is traversable."""
    requester = make_user()
    approver1 = make_user()
    approver2 = make_user()
    db.add_all([requester, approver1, approver2])
    db.flush()

    paper = make_paper(requester.id)
    db.add(paper)
    db.flush()

    req = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper.id,
        requested_by=requester.id,
        request_type=RequestType.RECONSTRUCT,
        status=RequestStatus.PENDING,
        required_approvals=2,
        reason="Exam reconstruction",
    )
    db.add(req)
    db.flush()

    for approver in [approver1, approver2]:
        db.add(Approval(
            id=uuid.uuid4(),
            request_id=req.id,
            approved_by=approver.id,
            decision=ApprovalDecision.APPROVED,
            created_at=utcnow(),
        ))
    db.flush()
    db.expire_all()

    loaded_req = db.get(AccessRequest, req.id)
    assert len(loaded_req.approvals) == 2
    assert all(a.decision == ApprovalDecision.APPROVED for a in loaded_req.approvals)


# ---------------------------------------------------------------------------
# TC-12  audit_logs has NO updated_at column
# ---------------------------------------------------------------------------

def test_audit_log_has_no_updated_at(engine):
    """TC-12: audit_logs must not have an updated_at column — immutability by design."""
    inspector = inspect(engine)
    col_names = {col["name"] for col in inspector.get_columns("audit_logs")}
    assert "updated_at" not in col_names, (
        "audit_logs.updated_at must NOT exist — the table is append-only"
    )
    assert "timestamp" in col_names, "audit_logs must have a 'timestamp' column"


# ---------------------------------------------------------------------------
# TC-13  Quorum calculation via SQL COUNT
# ---------------------------------------------------------------------------

def test_quorum_calculation(db):
    """TC-13: Security layer quorum logic (COUNT approvals >= required_approvals)."""
    requester = make_user()
    approver1 = make_user()
    approver2 = make_user()
    db.add_all([requester, approver1, approver2])
    db.flush()

    paper = make_paper(requester.id)
    db.add(paper)
    db.flush()

    req = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper.id,
        requested_by=requester.id,
        request_type=RequestType.RECONSTRUCT,
        status=RequestStatus.PENDING,
        required_approvals=2,
        reason="Quorum test",
    )
    db.add(req)
    db.flush()

    # Before any votes — quorum not met
    approved_count = (
        db.query(Approval)
        .filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        )
        .count()
    )
    assert approved_count < req.required_approvals

    # Add first vote
    db.add(Approval(
        id=uuid.uuid4(), request_id=req.id,
        approved_by=approver1.id, decision=ApprovalDecision.APPROVED,
        created_at=utcnow(),
    ))
    db.flush()

    approved_count = (
        db.query(Approval)
        .filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        )
        .count()
    )
    assert approved_count == 1
    assert approved_count < req.required_approvals  # quorum not yet met

    # Add second vote — quorum reached
    db.add(Approval(
        id=uuid.uuid4(), request_id=req.id,
        approved_by=approver2.id, decision=ApprovalDecision.APPROVED,
        created_at=utcnow(),
    ))
    db.flush()

    approved_count = (
        db.query(Approval)
        .filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        )
        .count()
    )
    assert approved_count >= req.required_approvals, "Quorum should be met after 2 approvals"


# ---------------------------------------------------------------------------
# TC-14  PaperFragment stores raw bytes
# ---------------------------------------------------------------------------

def test_fragment_data_stores_bytes(db):
    """TC-14: fragment_data column accepts and round-trips raw bytes."""
    user = make_user()
    db.add(user)
    db.flush()
    paper = make_paper(user.id)
    db.add(paper)
    db.flush()

    ciphertext = bytes(range(256))  # 256 raw bytes
    frag = PaperFragment(
        id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
        fragment_data=ciphertext, integrity_hash="deadbeef",
        status=FragmentStatus.STORED,
    )
    db.add(frag)
    db.flush()
    db.expire(frag)

    loaded = db.get(PaperFragment, frag.id)
    assert loaded.fragment_data == ciphertext, "fragment_data round-trip failed"


# ---------------------------------------------------------------------------
# TC-15  All 10 table names in Base.metadata
# ---------------------------------------------------------------------------

def test_all_expected_tables_in_metadata():
    """TC-15: Base.metadata contains exactly the 10 expected table names."""
    for table_name in EXPECTED_TABLES:
        assert table_name in Base.metadata.tables, (
            f"Table '{table_name}' missing from Base.metadata"
        )
