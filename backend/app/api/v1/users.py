"""User management and demo-seeding API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.security import hash_password
from app.db.database import get_db
from app.db.models import User
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/users", tags=["Users"])


def get_demo_user_definitions():
    """Return the predefined demo users for TrustGuard with configurable demo password."""
    demo_pw = settings.DEMO_PASSWORD
    return [
        {
            "username": "admin",
            "email": "admin@trustguard.demo",
            "password": demo_pw,
            "role": "ADMIN",
        },
        {
            "username": "guardian1",
            "email": "guardian1@trustguard.demo",
            "password": demo_pw,
            "role": "KEY_GUARDIAN",
        },
        {
            "username": "guardian2",
            "email": "guardian2@trustguard.demo",
            "password": demo_pw,
            "role": "KEY_GUARDIAN",
        },
        {
            "username": "guardian3",
            "email": "guardian3@trustguard.demo",
            "password": demo_pw,
            "role": "KEY_GUARDIAN",
        },
        {
            "username": "student1",
            "email": "student1@trustguard.demo",
            "password": demo_pw,
            "role": "STUDENT",
        },
        {
            "username": "student2",
            "email": "student2@trustguard.demo",
            "password": demo_pw,
            "role": "STUDENT",
        },
        {
            "username": "attacker",
            "email": "attacker@trustguard.demo",
            "password": demo_pw,
            "role": "ATTACKER",
        },
        {
            "username": "examcenter",
            "email": "examcenter@trustguard.demo",
            "password": demo_pw,
            "role": "EXAM_CENTER",
        },
    ]


@router.post(
    "/seed",
    status_code=status.HTTP_200_OK,
    summary="Seed demo users for TrustGuard demonstration",
)
async def seed_demo_users(db: AsyncSession = Depends(get_db)):
    """
    Creates predefined demo users if they don't already exist.
    Passwords are securely hashed with PBKDF2 before storage.
    Idempotent — safe to call multiple times.
    """
    created = []
    skipped = []
    demo_users = get_demo_user_definitions()

    for user_data in demo_users:
        stmt = select(User).where(User.username == user_data["username"])
        result = await db.execute(stmt)
        existing = result.scalar_one_or_none()

        if existing:
            skipped.append(user_data["username"])
            continue

        db_user = User(
            username=user_data["username"],
            email=user_data["email"],
            hashed_password=hash_password(user_data["password"]),
            role=user_data["role"],
        )
        db.add(db_user)
        created.append(user_data["username"])

    await db.commit()

    # Seed demonstration examinations if they don't exist
    from datetime import datetime, timedelta, timezone
    import hashlib
    from app.db.models import Exam, ExamStudent, KeyGuardianAssignment, ConsensusApproval, UploadedPaper
    from app.services.student_service import StudentService

    admin_res = await db.execute(select(User).where(User.username == "admin"))
    admin_user = admin_res.scalar_one_or_none()
    creator_id = admin_user.id if admin_user else "admin-seed-id"

    g1_res = await db.execute(select(User).where(User.username == "guardian1"))
    g1 = g1_res.scalar_one_or_none()
    g2_res = await db.execute(select(User).where(User.username == "guardian2"))
    g2 = g2_res.scalar_one_or_none()
    g3_res = await db.execute(select(User).where(User.username == "guardian3"))
    g3 = g3_res.scalar_one_or_none()

    s1_res = await db.execute(select(User).where(User.username == "student1"))
    s1 = s1_res.scalar_one_or_none()
    s2_res = await db.execute(select(User).where(User.username == "student2"))
    s2 = s2_res.scalar_one_or_none()

    now = datetime.now(timezone.utc)

    # 1. LIVE Exam: Cybersecurity Fundamentals (CS-SEC-2026)
    exam_stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
    exam_res = await db.execute(exam_stmt)
    demo_exam = exam_res.scalar_one_or_none()

    if not demo_exam:
        paper = UploadedPaper(
            paper_name="Cybersecurity Fundamentals Final Paper",
            original_filename="cybersecurity_fundamentals_paper.pdf",
            file_size=24580,
            file_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            encryption_status="ENCRYPTED",
            integrity_status="VERIFIED",
            fragment_status="FRAGMENTED",
            protection_status="PROTECTED",
            integrity_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            total_fragments=3,
            status="RELEASED",
            created_by=creator_id,
        )
        db.add(paper)
        await db.commit()
        await db.refresh(paper)

        demo_exam = Exam(
            title="Cybersecurity Fundamentals",
            course_code="CS-SEC-2026",
            description="Secure final examination covering cryptographic primitives, zero persistence, and threshold consensus.",
            scheduled_start=now - timedelta(minutes=5),
            scheduled_end=now + timedelta(hours=2),
            duration_minutes=30,
            required_quorum=3,
            total_guardians=3,
            created_by=creator_id,
            paper_id=paper.id,
            status="LIVE",
            started_at=now - timedelta(minutes=1),
        )
        db.add(demo_exam)
        await db.commit()
        await db.refresh(demo_exam)

        # Assign guardians
        if g1:
            db.add(KeyGuardianAssignment(exam_id=demo_exam.id, guardian_id=g1.id, public_key_fingerprint=hashlib.sha256(b"g1_pubkey").hexdigest()[:16]))
            db.add(ConsensusApproval(exam_id=demo_exam.id, guardian_id=g1.id, approval_hash=hashlib.sha256(b"g1_approval").hexdigest()))
        if g2:
            db.add(KeyGuardianAssignment(exam_id=demo_exam.id, guardian_id=g2.id, public_key_fingerprint=hashlib.sha256(b"g2_pubkey").hexdigest()[:16]))
            db.add(ConsensusApproval(exam_id=demo_exam.id, guardian_id=g2.id, approval_hash=hashlib.sha256(b"g2_approval").hexdigest()))
        if g3:
            db.add(KeyGuardianAssignment(exam_id=demo_exam.id, guardian_id=g3.id, public_key_fingerprint=hashlib.sha256(b"g3_pubkey").hexdigest()[:16]))
            db.add(ConsensusApproval(exam_id=demo_exam.id, guardian_id=g3.id, approval_hash=hashlib.sha256(b"g3_approval").hexdigest()))

        # Register students
        if s1:
            db.add(ExamStudent(exam_id=demo_exam.id, student_id=s1.id, registration_status="REGISTERED"))
        if s2:
            db.add(ExamStudent(exam_id=demo_exam.id, student_id=s2.id, registration_status="REGISTERED"))
        await db.commit()

        # Seed standard 20 cybersecurity questions
        await StudentService.ensure_exam_questions_seeded(db, demo_exam.id)

    # 2. READY Exam: Advanced Cryptography & Systems (JEE-ADV-2026) for testing approvals from scratch
    ready_stmt = select(Exam).where(Exam.course_code == "JEE-ADV-2026")
    ready_res = await db.execute(ready_stmt)
    ready_exam = ready_res.scalar_one_or_none()

    if not ready_exam:
        ready_paper = UploadedPaper(
            paper_name="JEE Advanced 2026 Paper 1 (Physics & Cryptography)",
            original_filename="jee_advanced_crypto_paper.pdf",
            file_size=31200,
            file_hash="a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            encryption_status="ENCRYPTED",
            integrity_status="VERIFIED",
            fragment_status="FRAGMENTED",
            protection_status="PROTECTED",
            integrity_hash="a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0",
            total_fragments=3,
            status="STAGED",
            created_by=creator_id,
        )
        db.add(ready_paper)
        await db.commit()
        await db.refresh(ready_paper)

        ready_exam = Exam(
            title="Advanced Cryptography & Systems",
            course_code="JEE-ADV-2026",
            description="Institutional exam staged for multi-guardian quorum approval and zero-trust paper release.",
            scheduled_start=now - timedelta(minutes=10),
            scheduled_end=now + timedelta(hours=3),
            duration_minutes=60,
            required_quorum=3,
            total_guardians=3,
            created_by=creator_id,
            paper_id=ready_paper.id,
            status="READY",
        )
        db.add(ready_exam)
        await db.commit()
        await db.refresh(ready_exam)

        if g1:
            db.add(KeyGuardianAssignment(exam_id=ready_exam.id, guardian_id=g1.id, public_key_fingerprint=hashlib.sha256(b"g1_pubkey_ready").hexdigest()[:16]))
        if g2:
            db.add(KeyGuardianAssignment(exam_id=ready_exam.id, guardian_id=g2.id, public_key_fingerprint=hashlib.sha256(b"g2_pubkey_ready").hexdigest()[:16]))
        if g3:
            db.add(KeyGuardianAssignment(exam_id=ready_exam.id, guardian_id=g3.id, public_key_fingerprint=hashlib.sha256(b"g3_pubkey_ready").hexdigest()[:16]))

        if s1:
            db.add(ExamStudent(exam_id=ready_exam.id, student_id=s1.id, registration_status="REGISTERED"))
        if s2:
            db.add(ExamStudent(exam_id=ready_exam.id, student_id=s2.id, registration_status="REGISTERED"))
        await db.commit()

        await StudentService.ensure_exam_questions_seeded(db, ready_exam.id)

    return {
        "message": f"Seeded {len(created)} users, skipped {len(skipped)} existing",
        "created": created,
        "skipped": skipped,
    }


@router.get(
    "/",
    response_model=List[UserResponse],
    summary="List all users",
)
async def list_users(
    role: Optional[str] = None,
    db: AsyncSession = Depends(get_db),
):
    """List all registered users, optionally filtered by role."""
    stmt = select(User).order_by(User.created_at)
    if role:
        stmt = stmt.where(User.role == role.upper())
    result = await db.execute(stmt)
    return result.scalars().all()
