"""
TrustGuard — development-only seed data.

Populates a clean database with sample users, roles, question papers,
fragments, access requests, approvals, access windows, audit logs, and
threat events.

**Security**:
- No real passwords or credentials.
- No real examination content.
- ``password_hash`` values are clearly marked as non-functional placeholders.
- Fragment data is random bytes, not real question-paper content.

Usage::

    # Requires DATABASE_URL to be set in the environment.
    python -m database.seed

    # Or import and call in tests / scripts:
    from database.seed import seed_development_data
    seed_development_data(session)
"""
import os
import sys
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Ensure the project root is on sys.path when run as a script.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

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
# Deterministic UUIDs (reproducible across runs)
# ---------------------------------------------------------------------------

def _uuid(n: int) -> uuid.UUID:
    """Generate a deterministic UUID from an integer seed."""
    return uuid.UUID(f"00000000-0000-4000-a000-{n:012d}")


# User IDs
ADMIN_ID = _uuid(1)
OFFICER_A_ID = _uuid(2)
OFFICER_B_ID = _uuid(3)
APPROVER_A_ID = _uuid(4)
APPROVER_B_ID = _uuid(5)
AUDITOR_ID = _uuid(6)
SYSTEM_ID = _uuid(7)

# Role IDs
ROLE_ADMIN_ID = _uuid(101)
ROLE_OFFICER_ID = _uuid(102)
ROLE_APPROVER_ID = _uuid(103)
ROLE_AUDITOR_ID = _uuid(104)
ROLE_SYSTEM_ID = _uuid(105)

# Paper / Fragment IDs
PAPER_A_ID = _uuid(201)
PAPER_B_ID = _uuid(202)
FRAG_A0_ID = _uuid(301)
FRAG_A1_ID = _uuid(302)
FRAG_A2_ID = _uuid(303)
FRAG_B0_ID = _uuid(304)
FRAG_B1_ID = _uuid(305)

# Access IDs
REQUEST_A_ID = _uuid(401)
APPROVAL_A1_ID = _uuid(501)
APPROVAL_A2_ID = _uuid(502)
WINDOW_A_ID = _uuid(601)

# Audit / threat IDs
AUDIT_1_ID = _uuid(701)
AUDIT_2_ID = _uuid(702)
AUDIT_3_ID = _uuid(703)
THREAT_1_ID = _uuid(801)


# ---------------------------------------------------------------------------
# Placeholder password hash (NOT a real hash — clearly marked as fake)
# ---------------------------------------------------------------------------

FAKE_HASH = "$argon2id$v=19$m=65536,t=3,p=4$FAKE_DEV_SEED_NOT_A_REAL_HASH"


# ---------------------------------------------------------------------------
# Seed function
# ---------------------------------------------------------------------------

def seed_development_data(session: Session) -> dict:
    """
    Insert sample development data into the database.

    Returns a dict summarising what was created.
    This function is idempotent — it skips creation if the admin user
    already exists.
    """
    # Idempotency guard: if the admin user already exists, skip.
    existing = session.get(User, ADMIN_ID)
    if existing is not None:
        return {"status": "skipped", "reason": "Seed data already present"}

    now = datetime.now(timezone.utc)

    # ── 1. Users ──────────────────────────────────────────────────────────
    users = [
        User(
            id=ADMIN_ID,
            email="admin@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Dev Admin",
            is_active=True,
            is_system=False,
        ),
        User(
            id=OFFICER_A_ID,
            email="officer.a@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Officer Alpha",
            is_active=True,
            is_system=False,
        ),
        User(
            id=OFFICER_B_ID,
            email="officer.b@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Officer Bravo",
            is_active=True,
            is_system=False,
        ),
        User(
            id=APPROVER_A_ID,
            email="approver.a@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Approver Alpha",
            is_active=True,
            is_system=False,
        ),
        User(
            id=APPROVER_B_ID,
            email="approver.b@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Approver Bravo",
            is_active=True,
            is_system=False,
        ),
        User(
            id=AUDITOR_ID,
            email="auditor@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="Dev Auditor",
            is_active=True,
            is_system=False,
        ),
        User(
            id=SYSTEM_ID,
            email="system@trustguard.dev",
            password_hash=FAKE_HASH,
            full_name="System Service Account",
            is_active=True,
            is_system=True,
        ),
    ]
    session.add_all(users)
    session.flush()

    # ── 2. Roles ──────────────────────────────────────────────────────────
    roles = [
        Role(id=ROLE_ADMIN_ID, name="ADMIN", description="Full system administrator"),
        Role(id=ROLE_OFFICER_ID, name="OFFICER", description="Creates and manages question papers"),
        Role(id=ROLE_APPROVER_ID, name="APPROVER", description="Reviews and approves access requests"),
        Role(id=ROLE_AUDITOR_ID, name="AUDITOR", description="Read-only access to audit logs"),
        Role(id=ROLE_SYSTEM_ID, name="SYSTEM", description="Non-human service account role"),
    ]
    session.add_all(roles)
    session.flush()

    # ── 3. Role assignments ───────────────────────────────────────────────
    user_roles = [
        UserRole(user_id=ADMIN_ID, role_id=ROLE_ADMIN_ID, granted_by=None),
        UserRole(user_id=OFFICER_A_ID, role_id=ROLE_OFFICER_ID, granted_by=ADMIN_ID),
        UserRole(user_id=OFFICER_B_ID, role_id=ROLE_OFFICER_ID, granted_by=ADMIN_ID),
        UserRole(user_id=APPROVER_A_ID, role_id=ROLE_APPROVER_ID, granted_by=ADMIN_ID),
        UserRole(user_id=APPROVER_B_ID, role_id=ROLE_APPROVER_ID, granted_by=ADMIN_ID),
        UserRole(user_id=AUDITOR_ID, role_id=ROLE_AUDITOR_ID, granted_by=ADMIN_ID),
        UserRole(user_id=SYSTEM_ID, role_id=ROLE_SYSTEM_ID, granted_by=ADMIN_ID),
    ]
    session.add_all(user_roles)
    session.flush()

    # ── 4. Question papers ────────────────────────────────────────────────
    papers = [
        QuestionPaper(
            id=PAPER_A_ID,
            exam_identifier="DEV-EXAM-2026-CS",
            paper_name="[DEV] Sample Computer Science Paper I",
            status=PaperStatus.FRAGMENTED,
            created_by=OFFICER_A_ID,
            protected_at=now - timedelta(days=10),
            fragmented_at=now - timedelta(days=9),
            integrity_hash="sha256:dev_fake_hash_aaaaaaaabbbbbbbbcccccccc",
            total_fragments=3,
        ),
        QuestionPaper(
            id=PAPER_B_ID,
            exam_identifier="DEV-EXAM-2026-MATH",
            paper_name="[DEV] Sample Mathematics Paper II",
            status=PaperStatus.PROTECTED,
            created_by=OFFICER_B_ID,
            protected_at=now - timedelta(days=5),
            integrity_hash="sha256:dev_fake_hash_ddddddddeeeeeeeeffffffff",
            total_fragments=None,
        ),
    ]
    session.add_all(papers)
    session.flush()

    # ── 5. Paper fragments ────────────────────────────────────────────────
    # These are random bytes, NOT real question-paper content.
    fragments = [
        PaperFragment(
            id=FRAG_A0_ID,
            paper_id=PAPER_A_ID,
            fragment_index=0,
            fragment_data=b"\x00\x01\x02\x03" * 64,  # 256 bytes of fake ciphertext
            integrity_hash="sha256:frag_a0_dev_hash",
            status=FragmentStatus.STORED,
        ),
        PaperFragment(
            id=FRAG_A1_ID,
            paper_id=PAPER_A_ID,
            fragment_index=1,
            fragment_data=b"\x10\x11\x12\x13" * 64,
            integrity_hash="sha256:frag_a1_dev_hash",
            status=FragmentStatus.STORED,
        ),
        PaperFragment(
            id=FRAG_A2_ID,
            paper_id=PAPER_A_ID,
            fragment_index=2,
            fragment_data=b"\x20\x21\x22\x23" * 64,
            integrity_hash="sha256:frag_a2_dev_hash",
            status=FragmentStatus.STORED,
        ),
        PaperFragment(
            id=FRAG_B0_ID,
            paper_id=PAPER_B_ID,
            fragment_index=0,
            fragment_data=b"\x30\x31\x32\x33" * 64,
            integrity_hash="sha256:frag_b0_dev_hash",
            status=FragmentStatus.PENDING,
        ),
        PaperFragment(
            id=FRAG_B1_ID,
            paper_id=PAPER_B_ID,
            fragment_index=1,
            fragment_data=b"\x40\x41\x42\x43" * 64,
            integrity_hash="sha256:frag_b1_dev_hash",
            status=FragmentStatus.PENDING,
        ),
    ]
    session.add_all(fragments)
    session.flush()

    # ── 6. Access request ─────────────────────────────────────────────────
    access_request = AccessRequest(
        id=REQUEST_A_ID,
        paper_id=PAPER_A_ID,
        requested_by=OFFICER_A_ID,
        request_type=RequestType.RECONSTRUCT,
        status=RequestStatus.APPROVED,
        required_approvals=2,
        reason="[DEV] Scheduled reconstruction for exam day rehearsal",
        decided_at=now - timedelta(days=1),
    )
    session.add(access_request)
    session.flush()

    # ── 7. Approvals ──────────────────────────────────────────────────────
    approvals = [
        Approval(
            id=APPROVAL_A1_ID,
            request_id=REQUEST_A_ID,
            approved_by=APPROVER_A_ID,
            decision=ApprovalDecision.APPROVED,
            reason="Approved — quorum vote 1 of 2",
            created_at=now - timedelta(days=2),
        ),
        Approval(
            id=APPROVAL_A2_ID,
            request_id=REQUEST_A_ID,
            approved_by=APPROVER_B_ID,
            decision=ApprovalDecision.APPROVED,
            reason="Approved — quorum vote 2 of 2",
            created_at=now - timedelta(days=1, hours=12),
        ),
    ]
    session.add_all(approvals)
    session.flush()

    # ── 8. Access window ──────────────────────────────────────────────────
    access_window = AccessWindow(
        id=WINDOW_A_ID,
        paper_id=PAPER_A_ID,
        request_id=REQUEST_A_ID,
        start_time=now - timedelta(hours=6),
        end_time=now + timedelta(hours=2),
        status=WindowStatus.ACTIVE,
    )
    session.add(access_window)
    session.flush()

    # ── 9. Audit logs ─────────────────────────────────────────────────────
    audit_logs = [
        AuditLog(
            id=AUDIT_1_ID,
            timestamp=now - timedelta(days=10),
            actor_id=OFFICER_A_ID,
            action="paper.created",
            target_type="question_paper",
            target_id=PAPER_A_ID,
            result=AuditResult.SUCCESS,
            reason="Officer created exam paper",
        ),
        AuditLog(
            id=AUDIT_2_ID,
            timestamp=now - timedelta(days=1),
            actor_id=APPROVER_B_ID,
            action="request.quorum_met",
            target_type="access_request",
            target_id=REQUEST_A_ID,
            result=AuditResult.SUCCESS,
            reason="Quorum reached: 2/2 approvals",
        ),
        AuditLog(
            id=AUDIT_3_ID,
            timestamp=now - timedelta(hours=6),
            actor_id=None,  # system action
            action="window.activated",
            target_type="access_window",
            target_id=WINDOW_A_ID,
            result=AuditResult.SUCCESS,
            reason="Access window opened automatically",
        ),
    ]
    session.add_all(audit_logs)
    session.flush()

    # ── 10. Threat event ──────────────────────────────────────────────────
    threat = ThreatEvent(
        id=THREAT_1_ID,
        timestamp=now - timedelta(hours=3),
        event_type=ThreatEventType.UNAUTHORIZED_ACCESS,
        severity=ThreatSeverity.HIGH,
        actor_id=None,
        actor_ip="192.168.1.100",
        target_type="question_paper",
        target_id=PAPER_A_ID,
        description=(
            "[DEV] Simulated unauthorized access attempt detected "
            "from unknown IP during active access window"
        ),
        extra_data={
            "simulated": True,
            "source": "dev_seed",
            "method": "direct_fragment_read",
        },
        resolved=False,
    )
    session.add(threat)
    session.flush()

    session.commit()

    return {
        "status": "created",
        "users": len(users),
        "roles": len(roles),
        "user_roles": len(user_roles),
        "papers": len(papers),
        "fragments": len(fragments),
        "access_requests": 1,
        "approvals": len(approvals),
        "access_windows": 1,
        "audit_logs": len(audit_logs),
        "threat_events": 1,
    }


# ---------------------------------------------------------------------------
# CLI entrypoint: python -m database.seed
# ---------------------------------------------------------------------------

def main() -> None:
    """Run seed from the command line."""
    url = os.environ.get("DATABASE_URL")
    if not url:
        print("ERROR: DATABASE_URL environment variable is not set.")
        print("       Set it in .env or export it before running this script.")
        sys.exit(1)

    engine = create_engine(url)
    _SessionLocal = sessionmaker(bind=engine)
    session = _SessionLocal()

    try:
        result = seed_development_data(session)
        print(f"Seed result: {result}")
    except Exception as exc:
        session.rollback()
        print(f"ERROR: Seed failed: {exc}")
        sys.exit(1)
    finally:
        session.close()
        engine.dispose()


if __name__ == "__main__":
    main()
