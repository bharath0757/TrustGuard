"""
TrustGuard — comprehensive database model and seed data tests.

All tests run against an in-memory SQLite database — no PostgreSQL required.

Test coverage:
  ── Schema tests ──
  TC-01  All 10 tables created by create_all()
  TC-02  All 10 table names exist in Base.metadata
  TC-03  All ENUM values accepted on INSERT
  TC-04  audit_logs has NO updated_at column (immutability by construction)

  ── User & Role tests ──
  TC-10  User creation with all fields
  TC-11  Role creation and uniqueness
  TC-12  Role assignment via UserRole
  TC-13  Relationship traversal: User → UserRole → Role round-trip
  TC-14  UNIQUE: duplicate user email raises IntegrityError
  TC-15  User deactivation (is_active flag)

  ── Paper & Fragment tests ──
  TC-20  Paper creation with all lifecycle statuses
  TC-21  Fragment creation with BYTEA data
  TC-22  Fragment data round-trips raw bytes
  TC-23  UNIQUE: duplicate (paper_id, fragment_index) raises IntegrityError
  TC-24  FK cascade: deleting QuestionPaper removes PaperFragments
  TC-25  Relationship traversal: QuestionPaper → PaperFragment

  ── Access & Approval tests ──
  TC-30  AccessRequest creation with required fields
  TC-31  Approval creation with decision
  TC-32  UNIQUE: duplicate approver vote raises IntegrityError
  TC-33  Quorum calculation via SQL COUNT
  TC-34  AccessWindow creation with time bounds
  TC-35  UNIQUE: duplicate access window per request raises IntegrityError
  TC-36  CHECK: end_time <= start_time raises IntegrityError
  TC-37  Relationship traversal: AccessRequest → Approvals
  TC-38  Relationship traversal: AccessRequest → AccessWindow

  ── Audit & Threat tests ──
  TC-40  AuditLog creation (immutable append-only)
  TC-41  ThreatEvent creation with all fields
  TC-42  ThreatEvent resolution workflow

  ── Foreign key tests ──
  TC-50  Invalid FK: fragment with nonexistent paper_id
  TC-51  Invalid FK: access_request with nonexistent paper_id
  TC-52  Invalid FK: approval with nonexistent request_id

  ── Seed data tests ──
  TC-60  Seed data creates all expected records
  TC-61  Seed data is idempotent (second call skips)
  TC-62  Seed data uses fake passwords (no real credentials)
  TC-63  Seed data fragment content is not plaintext
"""
import uuid
from datetime import datetime, timezone, timedelta

import pytest
from sqlalchemy import create_engine, inspect
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
from database.seed import seed_development_data, FAKE_HASH


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(scope="session")
def engine():
    """In-memory SQLite engine with FK enforcement. Created once per session."""
    _engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )

    @sa_event.listens_for(_engine, "connect")
    def _enable_fk(dbapi_conn, _):
        dbapi_conn.execute("PRAGMA foreign_keys = ON")

    Base.metadata.create_all(_engine)
    yield _engine
    Base.metadata.drop_all(_engine)
    _engine.dispose()


@pytest.fixture
def db(engine):
    """Function-scoped session with automatic rollback."""
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
        email=email or f"user-{uid}@test.dev",
        password_hash="$argon2id$v=19$m=65536,t=3,p=4$TESTONLY",
        full_name="Test User",
        is_active=True,
        is_system=is_system,
    )


def make_paper(creator_id=None) -> QuestionPaper:
    return QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier=f"TEST-{uuid.uuid4().hex[:8]}",
        paper_name="Test Paper",
        status=PaperStatus.CREATED,
        created_by=creator_id,
    )


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ===========================================================================
# Schema tests
# ===========================================================================

EXPECTED_TABLES = {
    "users", "roles", "user_roles",
    "question_papers", "paper_fragments",
    "access_requests", "approvals", "access_windows",
    "audit_logs", "threat_events",
}


class TestSchema:
    """TC-01..04: Schema-level validation."""

    def test_all_tables_exist_in_db(self, engine):
        """TC-01: All 10 tables exist in the SQLite schema."""
        inspector = inspect(engine)
        existing = set(inspector.get_table_names())
        missing = EXPECTED_TABLES - existing
        assert not missing, f"Tables missing from DB: {missing}"

    def test_all_tables_in_metadata(self):
        """TC-02: Base.metadata knows all 10 table names."""
        assert EXPECTED_TABLES.issubset(set(Base.metadata.tables.keys()))

    def test_paper_status_enum_values(self, db):
        """TC-03a: All PaperStatus values are accepted."""
        user = make_user()
        db.add(user)
        db.flush()
        for status in PaperStatus:
            paper = QuestionPaper(
                id=uuid.uuid4(),
                exam_identifier=f"ENUM-{status.value}",
                paper_name="Enum Test",
                status=status,
                created_by=user.id,
            )
            db.add(paper)
        db.flush()

    def test_fragment_status_enum_values(self, db):
        """TC-03b: All FragmentStatus values are accepted."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()
        for idx, status in enumerate(FragmentStatus):
            db.add(PaperFragment(
                id=uuid.uuid4(), paper_id=paper.id, fragment_index=idx,
                fragment_data=b"test", integrity_hash="h", status=status,
            ))
        db.flush()

    def test_threat_event_enum_values(self, db):
        """TC-03c: All ThreatEventType and ThreatSeverity values are accepted."""
        for et in ThreatEventType:
            for sev in ThreatSeverity:
                db.add(ThreatEvent(
                    id=uuid.uuid4(), event_type=et, severity=sev,
                    description="enum test", resolved=False,
                ))
        db.flush()

    def test_audit_log_no_updated_at(self, engine):
        """TC-04: audit_logs must not have an updated_at column."""
        inspector = inspect(engine)
        col_names = {col["name"] for col in inspector.get_columns("audit_logs")}
        assert "updated_at" not in col_names
        assert "timestamp" in col_names


# ===========================================================================
# User & Role tests
# ===========================================================================

class TestUserRole:
    """TC-10..15: User and role operations."""

    def test_user_creation(self, db):
        """TC-10: User can be created with all fields."""
        user = User(
            id=uuid.uuid4(),
            email="tc10@test.dev",
            password_hash="$argon2id$test",
            full_name="Test User TC10",
            is_active=True,
            is_system=False,
        )
        db.add(user)
        db.flush()

        loaded = db.get(User, user.id)
        assert loaded.email == "tc10@test.dev"
        assert loaded.full_name == "Test User TC10"
        assert loaded.is_active is True
        assert loaded.is_system is False

    def test_role_creation_and_uniqueness(self, db):
        """TC-11: Role created and name is unique."""
        role = Role(id=uuid.uuid4(), name="UNIQUE_ROLE_TC11", description="Test")
        db.add(role)
        db.flush()

        dup = Role(id=uuid.uuid4(), name="UNIQUE_ROLE_TC11", description="Dup")
        db.add(dup)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_role_assignment(self, db):
        """TC-12: UserRole assignment works."""
        user = make_user()
        role = Role(id=uuid.uuid4(), name=f"ROLE-{uuid.uuid4().hex[:6]}", description="Test")
        db.add_all([user, role])
        db.flush()

        user_role = UserRole(user_id=user.id, role_id=role.id, granted_by=None)
        db.add(user_role)
        db.flush()

        loaded = db.get(User, user.id)
        assert len(loaded.user_roles) == 1

    def test_user_role_traversal(self, db):
        """TC-13: User → UserRole → Role relationship round-trip."""
        user = make_user()
        role = Role(id=uuid.uuid4(), name=f"TRAV-{uuid.uuid4().hex[:6]}", description="Test")
        db.add_all([user, role])
        db.flush()

        db.add(UserRole(user_id=user.id, role_id=role.id, granted_by=None))
        db.flush()
        db.expire_all()

        loaded = db.get(User, user.id)
        assert loaded.user_roles[0].role.name == role.name

    def test_duplicate_email_raises(self, db):
        """TC-14: Duplicate email raises IntegrityError."""
        u1 = make_user(email="dup-tc14@test.dev")
        u2 = make_user(email="dup-tc14@test.dev")
        db.add(u1)
        db.flush()
        db.add(u2)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_user_deactivation(self, db):
        """TC-15: User.is_active can be set to False."""
        user = make_user()
        user.is_active = False
        db.add(user)
        db.flush()

        loaded = db.get(User, user.id)
        assert loaded.is_active is False


# ===========================================================================
# Paper & Fragment tests
# ===========================================================================

class TestPaperFragment:
    """TC-20..25: Paper and fragment operations."""

    def test_paper_creation_all_statuses(self, db):
        """TC-20: Papers can be created with any lifecycle status."""
        user = make_user()
        db.add(user)
        db.flush()
        for status in PaperStatus:
            paper = QuestionPaper(
                id=uuid.uuid4(),
                exam_identifier=f"TC20-{status.value}",
                paper_name=f"Paper {status.value}",
                status=status,
                created_by=user.id,
            )
            db.add(paper)
        db.flush()

    def test_fragment_creation_with_bytea(self, db):
        """TC-21: Fragment stores BYTEA data."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()

        frag = PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
            fragment_data=b"\xDE\xAD\xBE\xEF" * 32,
            integrity_hash="deadbeef", status=FragmentStatus.STORED,
        )
        db.add(frag)
        db.flush()
        assert frag.fragment_data is not None

    def test_fragment_data_roundtrip(self, db):
        """TC-22: Fragment data round-trips raw bytes."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()

        ciphertext = bytes(range(256))
        frag = PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
            fragment_data=ciphertext, integrity_hash="h",
            status=FragmentStatus.STORED,
        )
        db.add(frag)
        db.flush()
        db.expire(frag)
        loaded = db.get(PaperFragment, frag.id)
        assert loaded.fragment_data == ciphertext

    def test_duplicate_fragment_index_raises(self, db):
        """TC-23: Duplicate (paper_id, fragment_index) raises IntegrityError."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()

        f1 = PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
            fragment_data=b"a", integrity_hash="h1", status=FragmentStatus.STORED,
        )
        f2 = PaperFragment(
            id=uuid.uuid4(), paper_id=paper.id, fragment_index=0,
            fragment_data=b"b", integrity_hash="h2", status=FragmentStatus.STORED,
        )
        db.add(f1)
        db.flush()
        db.add(f2)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_cascade_delete_removes_fragments(self, db):
        """TC-24: Deleting QuestionPaper cascade-deletes its PaperFragments."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()

        for i in range(3):
            db.add(PaperFragment(
                id=uuid.uuid4(), paper_id=paper.id, fragment_index=i,
                fragment_data=b"d", integrity_hash=f"h{i}",
                status=FragmentStatus.STORED,
            ))
        db.flush()

        paper_id = paper.id
        db.delete(paper)
        db.flush()

        remaining = db.query(PaperFragment).filter_by(paper_id=paper_id).count()
        assert remaining == 0

    def test_paper_fragment_traversal(self, db):
        """TC-25: QuestionPaper → PaperFragment relationship."""
        user = make_user()
        db.add(user)
        db.flush()
        paper = make_paper(user.id)
        db.add(paper)
        db.flush()

        for i in range(3):
            db.add(PaperFragment(
                id=uuid.uuid4(), paper_id=paper.id, fragment_index=i,
                fragment_data=b"d", integrity_hash=f"h{i}",
                status=FragmentStatus.STORED,
            ))
        db.flush()
        db.expire_all()

        loaded = db.get(QuestionPaper, paper.id)
        assert len(loaded.fragments) == 3
        indices = sorted(f.fragment_index for f in loaded.fragments)
        assert indices == [0, 1, 2]


# ===========================================================================
# Access & Approval tests
# ===========================================================================

class TestAccessApproval:
    """TC-30..38: Access request, approval, and window operations."""

    def _make_request(self, db) -> tuple:
        """Helper: create user + paper + access request."""
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
            request_type=RequestType.RECONSTRUCT,
            status=RequestStatus.PENDING,
            required_approvals=2,
            reason="Test request",
        )
        db.add(req)
        db.flush()
        return user, paper, req

    def test_access_request_creation(self, db):
        """TC-30: AccessRequest with all required fields."""
        user, paper, req = self._make_request(db)
        loaded = db.get(AccessRequest, req.id)
        assert loaded.request_type == RequestType.RECONSTRUCT
        assert loaded.required_approvals == 2
        assert loaded.reason == "Test request"

    def test_approval_creation(self, db):
        """TC-31: Approval with decision."""
        user, paper, req = self._make_request(db)
        approver = make_user()
        db.add(approver)
        db.flush()

        approval = Approval(
            id=uuid.uuid4(),
            request_id=req.id,
            approved_by=approver.id,
            decision=ApprovalDecision.APPROVED,
            created_at=utcnow(),
        )
        db.add(approval)
        db.flush()

        loaded = db.get(Approval, approval.id)
        assert loaded.decision == ApprovalDecision.APPROVED

    def test_duplicate_approver_vote_raises(self, db):
        """TC-32: Same approver cannot vote twice on the same request."""
        user, paper, req = self._make_request(db)
        approver = make_user()
        db.add(approver)
        db.flush()

        v1 = Approval(
            id=uuid.uuid4(), request_id=req.id, approved_by=approver.id,
            decision=ApprovalDecision.APPROVED, created_at=utcnow(),
        )
        v2 = Approval(
            id=uuid.uuid4(), request_id=req.id, approved_by=approver.id,
            decision=ApprovalDecision.REJECTED, created_at=utcnow(),
        )
        db.add(v1)
        db.flush()
        db.add(v2)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_quorum_calculation(self, db):
        """TC-33: Quorum logic (COUNT approved >= required_approvals)."""
        user, paper, req = self._make_request(db)
        approver1 = make_user()
        approver2 = make_user()
        db.add_all([approver1, approver2])
        db.flush()

        # 0 approvals — quorum not met
        count = db.query(Approval).filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        ).count()
        assert count < req.required_approvals

        # 1 approval
        db.add(Approval(
            id=uuid.uuid4(), request_id=req.id, approved_by=approver1.id,
            decision=ApprovalDecision.APPROVED, created_at=utcnow(),
        ))
        db.flush()
        count = db.query(Approval).filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        ).count()
        assert count == 1

        # 2 approvals — quorum met
        db.add(Approval(
            id=uuid.uuid4(), request_id=req.id, approved_by=approver2.id,
            decision=ApprovalDecision.APPROVED, created_at=utcnow(),
        ))
        db.flush()
        count = db.query(Approval).filter(
            Approval.request_id == req.id,
            Approval.decision == ApprovalDecision.APPROVED,
        ).count()
        assert count >= req.required_approvals

    def test_access_window_creation(self, db):
        """TC-34: AccessWindow with time bounds."""
        user, paper, req = self._make_request(db)
        req.status = RequestStatus.APPROVED
        db.flush()

        now = utcnow()
        window = AccessWindow(
            id=uuid.uuid4(),
            paper_id=paper.id,
            request_id=req.id,
            start_time=now,
            end_time=now + timedelta(hours=2),
            status=WindowStatus.SCHEDULED,
        )
        db.add(window)
        db.flush()

        loaded = db.get(AccessWindow, window.id)
        assert loaded.status == WindowStatus.SCHEDULED
        assert loaded.end_time > loaded.start_time

    def test_duplicate_access_window_raises(self, db):
        """TC-35: Two access windows for the same request must fail."""
        user, paper, req = self._make_request(db)
        now = utcnow()
        w1 = AccessWindow(
            id=uuid.uuid4(), paper_id=paper.id, request_id=req.id,
            start_time=now, end_time=now + timedelta(hours=2),
            status=WindowStatus.SCHEDULED,
        )
        w2 = AccessWindow(
            id=uuid.uuid4(), paper_id=paper.id, request_id=req.id,
            start_time=now, end_time=now + timedelta(hours=3),
            status=WindowStatus.SCHEDULED,
        )
        db.add(w1)
        db.flush()
        db.add(w2)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_end_before_start_raises(self, db):
        """TC-36: end_time <= start_time must fail CHECK constraint."""
        user, paper, req = self._make_request(db)
        now = utcnow()
        bad = AccessWindow(
            id=uuid.uuid4(), paper_id=paper.id, request_id=req.id,
            start_time=now, end_time=now - timedelta(hours=1),
            status=WindowStatus.SCHEDULED,
        )
        db.add(bad)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_request_approvals_traversal(self, db):
        """TC-37: AccessRequest → Approvals relationship."""
        user, paper, req = self._make_request(db)
        a1 = make_user()
        a2 = make_user()
        db.add_all([a1, a2])
        db.flush()

        for approver in [a1, a2]:
            db.add(Approval(
                id=uuid.uuid4(), request_id=req.id, approved_by=approver.id,
                decision=ApprovalDecision.APPROVED, created_at=utcnow(),
            ))
        db.flush()
        db.expire_all()

        loaded = db.get(AccessRequest, req.id)
        assert len(loaded.approvals) == 2

    def test_request_window_traversal(self, db):
        """TC-38: AccessRequest → AccessWindow (one-to-one) relationship."""
        user, paper, req = self._make_request(db)
        now = utcnow()
        window = AccessWindow(
            id=uuid.uuid4(), paper_id=paper.id, request_id=req.id,
            start_time=now, end_time=now + timedelta(hours=1),
            status=WindowStatus.ACTIVE,
        )
        db.add(window)
        db.flush()
        db.expire_all()

        loaded = db.get(AccessRequest, req.id)
        assert loaded.access_window is not None
        assert loaded.access_window.id == window.id


# ===========================================================================
# Audit & Threat tests
# ===========================================================================

class TestAuditThreat:
    """TC-40..42: Audit and threat event operations."""

    def test_audit_log_creation(self, db):
        """TC-40: AuditLog creation (immutable, append-only)."""
        user = make_user()
        db.add(user)
        db.flush()

        log = AuditLog(
            id=uuid.uuid4(),
            timestamp=utcnow(),
            actor_id=user.id,
            action="test.action",
            target_type="user",
            target_id=user.id,
            result=AuditResult.SUCCESS,
            reason="TC-40 test",
        )
        db.add(log)
        db.flush()

        loaded = db.get(AuditLog, log.id)
        assert loaded.action == "test.action"
        assert loaded.result == AuditResult.SUCCESS
        # Verify there is no updated_at attribute
        assert not hasattr(loaded, "updated_at") or "updated_at" not in loaded.__table__.columns

    def test_threat_event_creation(self, db):
        """TC-41: ThreatEvent with all fields."""
        threat = ThreatEvent(
            id=uuid.uuid4(),
            timestamp=utcnow(),
            event_type=ThreatEventType.BRUTE_FORCE,
            severity=ThreatSeverity.CRITICAL,
            actor_ip="10.0.0.1",
            target_type="user",
            target_id=uuid.uuid4(),
            description="TC-41 test event",
            extra_data={"test": True},
            resolved=False,
        )
        db.add(threat)
        db.flush()

        loaded = db.get(ThreatEvent, threat.id)
        assert loaded.event_type == ThreatEventType.BRUTE_FORCE
        assert loaded.severity == ThreatSeverity.CRITICAL
        assert loaded.resolved is False

    def test_threat_event_resolution(self, db):
        """TC-42: ThreatEvent resolution workflow."""
        resolver = make_user()
        db.add(resolver)
        db.flush()

        threat = ThreatEvent(
            id=uuid.uuid4(),
            timestamp=utcnow(),
            event_type=ThreatEventType.UNAUTHORIZED_ACCESS,
            severity=ThreatSeverity.HIGH,
            description="TC-42 unresolved",
            resolved=False,
        )
        db.add(threat)
        db.flush()

        # Resolve
        threat.resolved = True
        threat.resolved_at = utcnow()
        threat.resolved_by = resolver.id
        db.flush()

        loaded = db.get(ThreatEvent, threat.id)
        assert loaded.resolved is True
        assert loaded.resolved_by == resolver.id
        assert loaded.resolved_at is not None


# ===========================================================================
# Foreign key tests
# ===========================================================================

class TestForeignKeys:
    """TC-50..52: Invalid foreign key references."""

    def test_fragment_with_nonexistent_paper(self, db):
        """TC-50: Fragment referencing nonexistent paper_id raises IntegrityError."""
        frag = PaperFragment(
            id=uuid.uuid4(),
            paper_id=uuid.uuid4(),  # does not exist
            fragment_index=0,
            fragment_data=b"test",
            integrity_hash="h",
            status=FragmentStatus.STORED,
        )
        db.add(frag)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_access_request_with_nonexistent_paper(self, db):
        """TC-51: AccessRequest referencing nonexistent paper_id raises IntegrityError."""
        user = make_user()
        db.add(user)
        db.flush()

        req = AccessRequest(
            id=uuid.uuid4(),
            paper_id=uuid.uuid4(),  # does not exist
            requested_by=user.id,
            request_type=RequestType.VIEW,
            status=RequestStatus.PENDING,
            required_approvals=1,
            reason="TC-51 test",
        )
        db.add(req)
        with pytest.raises(IntegrityError):
            db.flush()

    def test_approval_with_nonexistent_request(self, db):
        """TC-52: Approval referencing nonexistent request_id raises IntegrityError."""
        user = make_user()
        db.add(user)
        db.flush()

        approval = Approval(
            id=uuid.uuid4(),
            request_id=uuid.uuid4(),  # does not exist
            approved_by=user.id,
            decision=ApprovalDecision.APPROVED,
            created_at=utcnow(),
        )
        db.add(approval)
        with pytest.raises(IntegrityError):
            db.flush()


# ===========================================================================
# Seed data tests
# ===========================================================================

class TestSeedData:
    """TC-60..63: Development seed data validation."""

    @pytest.fixture
    def seeded_db(self, engine):
        """
        A fresh session with seed data applied.
        Uses a nested transaction so seed data is rolled back after each test.
        """
        session = Session(engine)
        result = seed_development_data(session)
        yield session, result
        session.rollback()
        session.close()

    def test_seed_creates_all_records(self, seeded_db):
        """TC-60: Seed data creates the expected number of each entity."""
        session, result = seeded_db
        assert result["status"] == "created"
        assert result["users"] == 7
        assert result["roles"] == 5
        assert result["user_roles"] == 7
        assert result["papers"] == 2
        assert result["fragments"] == 5
        assert result["access_requests"] == 1
        assert result["approvals"] == 2
        assert result["access_windows"] == 1
        assert result["audit_logs"] == 3
        assert result["threat_events"] == 1

    def test_seed_is_idempotent(self, seeded_db):
        """TC-61: Second call to seed_development_data is a no-op."""
        session, _ = seeded_db
        result2 = seed_development_data(session)
        assert result2["status"] == "skipped"

    def test_seed_uses_fake_passwords(self, seeded_db):
        """TC-62: All seed users have clearly fake password hashes."""
        session, _ = seeded_db
        users = session.query(User).all()
        for user in users:
            assert "FAKE" in user.password_hash or "NOT_A_REAL" in user.password_hash, (
                f"User {user.email} has a password_hash that doesn't look fake: "
                f"{user.password_hash[:40]}"
            )

    def test_seed_fragments_not_plaintext(self, seeded_db):
        """TC-63: Seed fragment data is not human-readable plaintext."""
        session, _ = seeded_db
        fragments = session.query(PaperFragment).all()
        for frag in fragments:
            # Try to decode as UTF-8 — should fail or look non-sensical
            try:
                text = frag.fragment_data.decode("utf-8")
                # Even if it decodes, it should not look like English text
                assert not any(word in text.lower() for word in [
                    "question", "answer", "exam", "marks", "section",
                ]), f"Fragment {frag.id} contains plaintext exam content"
            except UnicodeDecodeError:
                pass  # Expected: raw bytes can't be decoded as text
