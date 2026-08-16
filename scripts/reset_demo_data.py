"""
TrustGuard — Demo & Local Test Data Reset Utility.

CRITICAL SAFETY RULE:
- NEVER run in production environment.
- Only resets synthetic local development / test databases (trustguard.db).
- All payloads, question papers, and users created are purely synthetic mock fixtures.

Usage:
    python scripts/reset_demo_data.py
"""

import os
import sys
import asyncio
import hashlib
from pathlib import Path
from datetime import datetime, timedelta, timezone

PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "backend"))

try:
    from backend.app.core.config import settings
    from backend.app.core.security import hash_password
    from backend.app.db.database import engine, AsyncSessionLocal, init_db
    from backend.app.db.models import Base, User, Exam, KeyGuardianAssignment, ConsensusApproval, AuditEvent
except ImportError:
    from app.core.config import settings  # type: ignore
    from app.core.security import hash_password  # type: ignore
    from app.db.database import engine, AsyncSessionLocal, init_db  # type: ignore
    from app.db.models import Base, User, Exam, KeyGuardianAssignment, ConsensusApproval, AuditEvent  # type: ignore


DEMO_USERS = [
    {
        "username": "admin",
        "email": "admin@trustguard.synth.org",
        "password": "AdminPassword2026!",
        "role": "ADMIN",
    },
    {
        "username": "exam_setter",
        "email": "setter@trustguard.synth.org",
        "password": "SetterPassword2026!",
        "role": "EXAM_SETTER",
    },
    {
        "username": "guardian_alpha",
        "email": "guardian1@trustguard.synth.org",
        "password": "GuardianPassword1!",
        "role": "KEY_GUARDIAN",
    },
    {
        "username": "guardian_beta",
        "email": "guardian2@trustguard.synth.org",
        "password": "GuardianPassword2!",
        "role": "KEY_GUARDIAN",
    },
    {
        "username": "guardian_gamma",
        "email": "guardian3@trustguard.synth.org",
        "password": "GuardianPassword3!",
        "role": "KEY_GUARDIAN",
    },
    {
        "username": "center_north",
        "email": "center.north@trustguard.synth.org",
        "password": "CenterPassword2026!",
        "role": "EXAM_CENTER",
    },
    {
        "username": "auditor",
        "email": "auditor@trustguard.synth.org",
        "password": "AuditorPassword2026!",
        "role": "AUDITOR",
    },
]


async def reset_demo_database():
    """Reset and re-populate the TrustGuard development database with clean demonstration fixtures."""
    # Safety Check: Prevent accidental execution in production
    app_env = os.environ.get("ENVIRONMENT", os.environ.get("APP_ENV", "development")).lower()
    if app_env in ["prod", "production"]:
        print("[!] ERROR: Refusing to reset database in PRODUCTION environment!")
        sys.exit(1)

    print("=" * 70)
    print("TrustGuard SIH Demonstration Data Reset")
    print("=" * 70)
    print(f"[*] Environment: {app_env}")
    print(f"[*] Database URL: {settings.DATABASE_URL}")

    # 1. Reset FastAPI Backend DB Schema
    print("\n[*] Resetting backend database schema...")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(Base.metadata.create_all)
    print("    [OK] Backend tables dropped and recreated cleanly.")

    # 2. Seed Default Demo Users
    print("\n[*] Seeding 7 synthetic demonstration personas across all 5 RBAC roles...")
    async with AsyncSessionLocal() as session:
        for u_data in DEMO_USERS:
            user = User(
                username=u_data["username"],
                email=u_data["email"],
                hashed_password=hash_password(u_data["password"]),
                role=u_data["role"],
            )
            session.add(user)
        await session.commit()
    print("    [OK] 7 Demo personas created with active authentication credentials:")
    for u in DEMO_USERS:
        print(f"        * {u['role']:<14} | User: {u['username']:<15} | Pass: {u['password']}")

    # 3. Seed Sample Staged Examination
    print("\n[*] Initializing sample staged examination fixture...")
    now = datetime.now(timezone.utc)
    async with AsyncSessionLocal() as session:
        # Fetch setter and guardians
        from sqlalchemy import select
        setter_res = await session.execute(select(User).where(User.username == "exam_setter"))
        setter = setter_res.scalar_one()

        g1_res = await session.execute(select(User).where(User.username == "guardian_alpha"))
        g1 = g1_res.scalar_one()

        g2_res = await session.execute(select(User).where(User.username == "guardian_beta"))
        g2 = g2_res.scalar_one()

        g3_res = await session.execute(select(User).where(User.username == "guardian_gamma"))
        g3 = g3_res.scalar_one()

        sample_exam = Exam(
            id="demo-exam-jee-adv-2026",
            title="National Competitive Exam 2026 - Mathematics Paper 1",
            course_code="MATH-JEE-ADV-2026",
            status="DRAFT",
            scheduled_start=now - timedelta(minutes=15),
            scheduled_end=now + timedelta(hours=3),
            required_quorum=2,
            total_guardians=3,
            created_by=setter.id,
        )
        session.add(sample_exam)
        await session.flush()

        # Assign guardians
        session.add_all([
            KeyGuardianAssignment(exam_id=sample_exam.id, guardian_id=g1.id, public_key_fingerprint="RSA_4096_FP_ALPHA_DEMO"),
            KeyGuardianAssignment(exam_id=sample_exam.id, guardian_id=g2.id, public_key_fingerprint="RSA_4096_FP_BETA_DEMO"),
            KeyGuardianAssignment(exam_id=sample_exam.id, guardian_id=g3.id, public_key_fingerprint="RSA_4096_FP_GAMMA_DEMO"),
        ])

        import json
        session.add(AuditEvent(
            exam_id=sample_exam.id,
            actor_id=setter.id,
            action="EXAM_CREATED",
            details_json=json.dumps({"title": sample_exam.title, "required_quorum": 2, "total_guardians": 3}),
        ))
        await session.commit()
    print("    [OK] Demo exam 'demo-exam-jee-adv-2026' created in DRAFT state.")

    print("\n" + "=" * 70)
    print("[SUCCESS] TrustGuard demonstration data is ready for SIH evaluation.")
    print("=" * 70 + "\n")


if __name__ == "__main__":
    asyncio.run(reset_demo_database())
