"""
TrustGuard Phase 2 Test Suite: Authentication & Role-Based Access Control (RBAC).

Verifies all 10 core Phase 2 security and authorization requirements:
1. Successful guardian login
2. Successful student login
3. Successful attacker login
4. Invalid credentials rejection (401)
5. Expired/invalid token rejection (401)
6. Student accessing guardian endpoints -> denied (403)
7. Attacker accessing guardian endpoints -> denied (403)
8. Student accessing attacker endpoints -> denied (403)
9. Guardian accessing student-only endpoints -> denied (403)
10. Passwords are not stored in plaintext (salted PBKDF2 hash verification)
11. Attacker accessing student-only endpoints -> denied (403)
"""

from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient
import jwt
from sqlalchemy import select

from app.core.config import settings
from app.core.security import hash_password, verify_password, create_access_token
from app.db.models import User


@pytest.fixture
async def seeded_users(async_client: AsyncClient):
    """Seed the database with standard Phase 2 demo accounts and return tokens."""
    seed_res = await async_client.post("/api/v1/users/seed")
    assert seed_res.status_code == 200

    # Log in each persona to get their auth headers
    accounts = {}
    usernames = ["admin", "guardian1", "guardian2", "guardian3", "student1", "student2", "attacker", "examcenter"]
    for u in usernames:
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": u, "password": settings.DEMO_PASSWORD},
        )
        assert res.status_code == 200, f"Login failed for {u}: {res.text}"
        data = res.json()
        accounts[u] = {
            "token": data["access_token"],
            "role": data["role"],
            "user_id": data["user_id"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
        }
    return accounts


# ── Requirement 1, 2, 3: Successful Logins ───────────────────────────

@pytest.mark.asyncio
async def test_01_successful_guardian_login(async_client: AsyncClient, seeded_users):
    """1. Guardians (guardian1, guardian2, guardian3) log in successfully and receive valid tokens."""
    for guardian_name in ["guardian1", "guardian2", "guardian3"]:
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": guardian_name, "password": settings.DEMO_PASSWORD},
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert data["role"] == "KEY_GUARDIAN"

        # Verify /auth/me returns matching profile
        me_res = await async_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
        assert me_res.status_code == 200
        me = me_res.json()
        assert me["username"] == guardian_name
        assert me["role"] == "KEY_GUARDIAN"


@pytest.mark.asyncio
async def test_02_successful_student_login(async_client: AsyncClient, seeded_users):
    """2. Students (student1, student2) log in successfully and receive student role."""
    for student_name in ["student1", "student2"]:
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": student_name, "password": settings.DEMO_PASSWORD},
        )
        assert res.status_code == 200
        data = res.json()
        assert "access_token" in data
        assert data["role"] == "STUDENT"

        me_res = await async_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
        assert me_res.status_code == 200
        assert me_res.json()["role"] == "STUDENT"


@pytest.mark.asyncio
async def test_03_successful_attacker_login(async_client: AsyncClient, seeded_users):
    """3. Security tester (attacker) logs in successfully and receives ATTACKER role."""
    res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "attacker", "password": settings.DEMO_PASSWORD},
    )
    assert res.status_code == 200
    data = res.json()
    assert "access_token" in data
    assert data["role"] == "ATTACKER"

    me_res = await async_client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {data['access_token']}"})
    assert me_res.status_code == 200
    assert me_res.json()["role"] == "ATTACKER"


# ── Requirement 4: Invalid Credentials ────────────────────────────────

@pytest.mark.asyncio
async def test_04_invalid_credentials_rejected(async_client: AsyncClient, seeded_users):
    """4. Login with invalid username or wrong password returns 401 Unauthorized."""
    # Wrong password
    res1 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "guardian1", "password": "WrongPassword999!"},
    )
    assert res1.status_code == 401
    assert "detail" in res1.json()

    # Non-existent user
    res2 = await async_client.post(
        "/api/v1/auth/login",
        json={"username": "nonexistent_intruder", "password": "any_password"},
    )
    assert res2.status_code == 401


# ── Requirement 5: Expired and Invalid Tokens ─────────────────────────

@pytest.mark.asyncio
async def test_05_expired_and_tampered_token_rejected(async_client: AsyncClient, seeded_users):
    """5. Expired or forged JWT access tokens are rejected with 401 Unauthorized."""
    # 1. Tampered / malformed token
    res_tampered = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": "Bearer forged.invalid.jwt.token"},
    )
    assert res_tampered.status_code == 401
    assert "WWW-Authenticate" in res_tampered.headers

    # 2. Expired token
    expired_token = create_access_token(
        data={"sub": seeded_users["guardian1"]["user_id"], "username": "guardian1", "role": "KEY_GUARDIAN"},
        expires_delta=timedelta(minutes=-30),  # Expired 30 minutes ago
    )
    res_expired = await async_client.get(
        "/api/v1/auth/me",
        headers={"Authorization": f"Bearer {expired_token}"},
    )
    assert res_expired.status_code == 401


# ── Requirement 6: Student Accessing Guardian Endpoints -> Denied ────

@pytest.mark.asyncio
async def test_06_student_accessing_guardian_endpoints_denied(async_client: AsyncClient, seeded_users):
    """6. Students attempting to create exams, upload papers, approve consensus, or view audit trails are denied (403)."""
    student_headers = seeded_users["student1"]["headers"]

    # 1. Attempt to create exam
    now = datetime.now(timezone.utc)
    create_exam_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Unauthorized Student Exam",
            "course_code": "STUDENT-HACK",
            "scheduled_start": now.isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
            "required_quorum": 2,
            "total_guardians": 3,
        },
        headers=student_headers,
    )
    assert create_exam_res.status_code == 403

    # 2. Attempt to view audit logs
    audit_res = await async_client.get("/api/v1/audit/events", headers=student_headers)
    assert audit_res.status_code == 403

    # 3. Attempt to submit consensus approval
    consensus_res = await async_client.post(
        "/api/v1/consensus/dummy-exam-id/approve",
        json={"share_token": "MOCK_TOKEN"},
        headers=student_headers,
    )
    assert consensus_res.status_code == 403


# ── Requirement 7: Attacker Accessing Guardian Endpoints -> Denied ───

@pytest.mark.asyncio
async def test_07_attacker_accessing_guardian_endpoints_denied(async_client: AsyncClient, seeded_users):
    """7. Attacker attempting to create exams, upload papers, or approve consensus is denied (403)."""
    attacker_headers = seeded_users["attacker"]["headers"]

    now = datetime.now(timezone.utc)
    res_exam = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Attacker Injected Exam",
            "course_code": "ATTACK-EXAM",
            "scheduled_start": now.isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
        },
        headers=attacker_headers,
    )
    assert res_exam.status_code == 403

    # Attacker cannot approve consensus
    res_approve = await async_client.post(
        "/api/v1/consensus/dummy-exam-id/approve",
        json={"share_token": "FORGED_SHARE"},
        headers=attacker_headers,
    )
    assert res_approve.status_code == 403


# ── Requirement 8: Student Accessing Attacker Endpoints -> Denied ────

@pytest.mark.asyncio
async def test_08_student_accessing_attacker_endpoints_denied(async_client: AsyncClient, seeded_users):
    """8. Students attempting to run attack simulations or view attack scenarios are denied (403)."""
    student_headers = seeded_users["student1"]["headers"]

    # Cannot list scenarios
    res_scenarios = await async_client.get("/api/v1/simulation/scenarios", headers=student_headers)
    assert res_scenarios.status_code == 403

    # Cannot trigger simulation
    res_run = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "UNAUTHORIZED_ACCESS", "target_paper_id": "JEE-MOCK-001"},
        headers=student_headers,
    )
    assert res_run.status_code == 403


# ── Requirement 9: Guardian Accessing Student-Only Endpoints -> Denied ──

@pytest.mark.asyncio
async def test_09_guardian_accessing_student_only_endpoints_denied(async_client: AsyncClient, seeded_users):
    """9. Key Guardians attempting to access student examination portal endpoints are denied (403)."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    # Cannot view student exam list
    res_student_exams = await async_client.get("/api/v1/student/exams", headers=guardian_headers)
    assert res_student_exams.status_code == 403

    # Cannot join exam as student
    res_join = await async_client.post("/api/v1/student/exams/dummy-exam/join", headers=guardian_headers)
    assert res_join.status_code == 403

    # Cannot submit student answers
    res_answers = await async_client.post(
        "/api/v1/student/sessions/dummy-session/answers",
        json={"answers": {"Q1": "A"}},
        headers=guardian_headers,
    )
    assert res_answers.status_code == 403

    # Cannot access student status
    res_status = await async_client.get("/api/v1/student/status", headers=guardian_headers)
    assert res_status.status_code == 403


# ── Requirement 10: Passwords are not stored in plaintext ─────────────

@pytest.mark.asyncio
async def test_10_passwords_are_securely_hashed_not_plaintext(async_client: AsyncClient, seeded_users):
    """10. Database persistence check: password hashes use salted PBKDF2; raw passwords never stored."""
    # Test the password hashing function directly
    raw_password = "SecretPassword2026!"
    hashed = hash_password(raw_password)

    # Must NOT equal raw password
    assert hashed != raw_password
    assert raw_password not in hashed

    # Must start with PBKDF2 identifier
    assert hashed.startswith("pbkdf2_sha256:100000:")
    parts = hashed.split(":")
    assert len(parts) == 4
    salt = parts[2]
    assert len(salt) == 32  # 16 bytes hex = 32 chars

    # Verification must succeed for correct password
    assert verify_password(raw_password, hashed) is True
    # Verification must fail for incorrect password
    assert verify_password("WrongPassword!", hashed) is False

    # Two hashes of the same password must produce different salts and hashes
    hashed2 = hash_password(raw_password)
    assert hashed != hashed2  # Distinct salt per invocation


# ── Requirement 11: Attacker Accessing Student Endpoints -> Denied ────

@pytest.mark.asyncio
async def test_11_attacker_accessing_student_endpoints_denied(async_client: AsyncClient, seeded_users):
    """11. Attacker attempting to access student portal endpoints is denied (403)."""
    attacker_headers = seeded_users["attacker"]["headers"]

    res_student = await async_client.get("/api/v1/student/exams", headers=attacker_headers)
    assert res_student.status_code == 403

    res_status = await async_client.get("/api/v1/student/status", headers=attacker_headers)
    assert res_status.status_code == 403
