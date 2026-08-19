"""
TrustGuard Phase 5 Test Suite: Real Student Examination Workflow.

Verifies all 10 core Phase 5 requirements:
1. Student can join authorized exam.
2. Student cannot join unauthorized exam.
3. Student cannot access another student's session.
4. Correct answer never appears in API response.
5. Timer survives refresh.
6. Expired session cannot submit.
7. Duplicate submission handled safely.
8. Student cannot use guardian endpoint.
9. Student cannot use attacker endpoint.
10. Two students can independently take the same exam.
"""

import io
from datetime import datetime, timedelta, timezone
import json
import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.db.models import Exam, ExamStudent, Question, StudentExamSession, User


@pytest.fixture
async def seeded_users(async_client: AsyncClient):
    """Seed demo accounts and return auth headers for all roles."""
    await async_client.post("/api/v1/users/seed")

    accounts = {}
    usernames = ["admin", "guardian1", "guardian2", "guardian3", "student1", "student2", "attacker"]
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


async def create_and_authorize_exam(async_client: AsyncClient, seeded_users: dict, duration_minutes: int = 15) -> dict:
    """Helper to create an exam, register student1 & student2, and unlock it to LIVE status with full consensus."""
    admin_headers = seeded_users["admin"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals",
            "course_code": f"SEC-{now.microsecond}",
            "description": "Comprehensive security and cryptography final examination.",
            "scheduled_start": (now - timedelta(minutes=2)).isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
            "duration_minutes": duration_minutes,
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]

    # 2. Upload Paper
    fake_pdf = b"%PDF-1.4 Cybersecurity Fundamentals Question Paper"
    files = {"file": ("Cybersecurity_Exam_Paper.pdf", io.BytesIO(fake_pdf), "application/pdf")}
    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Cybersecurity Paper", "description": "Official Paper"},
        files=files,
        headers=admin_headers,
    )
    assert upload_res.status_code == 201
    paper_id = upload_res.json()["id"]

    # 3. Assign 3 Key Guardians
    for g_key in ["guardian1", "guardian2", "guardian3"]:
        g = seeded_users[g_key]
        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g["user_id"], "public_key_fingerprint": f"RSA_4096_{g_key.upper()}"},
            headers=admin_headers,
        )
        assert assign_res.status_code == 201

    # 4. Register student1 and student2
    students_to_register = [seeded_users["student1"]["user_id"], seeded_users["student2"]["user_id"]]
    reg_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/students",
        json={"student_user_ids": students_to_register},
        headers=admin_headers,
    )
    assert reg_res.status_code == 201

    # 5. Stage paper
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 3600},
        headers=admin_headers,
    )
    assert stage_res.status_code == 200

    # 6. Guardians 1, 2, 3 approve
    for idx, g_key in enumerate(["guardian1", "guardian2", "guardian3"]):
        g = seeded_users[g_key]
        token = f"MOCK_SHARE_TOKEN_K3_N3_{idx+1}_{g['user_id']}"
        app_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": token},
            headers=g["headers"],
        )
        assert app_res.status_code == 200

    # 6. Start exam (LIVE)
    start_res = await async_client.post(
        f"/api/v1/exam-lifecycle/{exam_id}/start",
        headers=admin_headers,
    )
    assert start_res.status_code == 200

    return exam


# ── TEST 1: Student Can Join Authorized Exam ─────────────────────────────

@pytest.mark.asyncio
async def test_01_student_can_join_authorized_exam(async_client: AsyncClient, seeded_users):
    """1. Student 1 can join an authorized exam and receives valid session with questions."""
    exam = await create_and_authorize_exam(async_client, seeded_users, duration_minutes=15)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Student 1 joins
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200, f"Join failed: {join_res.text}"

    data = join_res.json()
    assert data["exam_id"] == exam_id
    assert data["student_id"] == seeded_users["student1"]["user_id"]
    assert data["student_username"] == "student1"
    assert data["status"] == "IN_PROGRESS"
    assert data["started_at"] is not None
    assert data["expires_at"] is not None
    assert data["remaining_seconds"] > 0
    assert data["duration_minutes"] == 15

    # Verify questions list
    questions = data["questions"]
    assert len(questions) >= 20
    q1 = questions[0]
    assert "id" in q1
    assert "question_number" in q1
    assert "question_text" in q1
    assert "options" in q1
    assert len(q1["options"]) == 4


# ── TEST 2: Student Cannot Join Unauthorized Exam ─────────────────────────

@pytest.mark.asyncio
async def test_02_student_cannot_join_unauthorized_exam(async_client: AsyncClient, seeded_users):
    """2. Student cannot join an exam that is in DRAFT, STAGED, or AWAITING_APPROVAL status."""
    admin_headers = seeded_users["admin"]["headers"]
    s1_headers = seeded_users["student1"]["headers"]
    now = datetime.now(timezone.utc)

    # Create exam in DRAFT state
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Unreleased Draft Exam",
            "course_code": "DRAFT-101",
            "scheduled_start": now.isoformat(),
            "scheduled_end": (now + timedelta(hours=1)).isoformat(),
            "duration_minutes": 30,
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 201
    draft_exam_id = create_res.json()["id"]

    # Register student1
    await async_client.post(
        f"/api/v1/exams/{draft_exam_id}/students",
        json={"student_user_ids": [seeded_users["student1"]["user_id"]]},
        headers=admin_headers,
    )

    # Student 1 attempts to join DRAFT exam
    join_res = await async_client.post(f"/api/v1/student/exams/{draft_exam_id}/join", headers=s1_headers)
    assert join_res.status_code in [400, 403]
    assert "authorized" in join_res.text.lower() or "draft" in join_res.text.lower()

    # Also test an unregistered student trying to join authorized exam
    authorized_exam = await create_and_authorize_exam(async_client, seeded_users)
    
    # Create an unassigned student
    unassigned_res = await async_client.post(
        "/api/v1/auth/register",
        json={
            "username": f"unassigned_{now.microsecond}",
            "email": f"unassigned_{now.microsecond}@test.org",
            "password": "Password123!",
            "role": "STUDENT",
        },
    )
    assert unassigned_res.status_code == 201
    login_res = await async_client.post(
        "/api/v1/auth/login",
        json={"username": unassigned_res.json()["username"], "password": "Password123!"},
    )
    unassigned_headers = {"Authorization": f"Bearer {login_res.json()['access_token']}"}

    # Unassigned student tries to join authorized exam -> 403 Forbidden
    unassigned_join = await async_client.post(
        f"/api/v1/student/exams/{authorized_exam['id']}/join",
        headers=unassigned_headers,
    )
    assert unassigned_join.status_code == 403
    assert "not registered" in unassigned_join.text.lower() or "access denied" in unassigned_join.text.lower()


# ── TEST 3: Student Cannot Access Another Student's Session ───────────────

@pytest.mark.asyncio
async def test_03_student_cannot_access_other_student_session(async_client: AsyncClient, seeded_users):
    """3. Student 1 cannot view, save answers to, or submit Student 2's session."""
    exam = await create_and_authorize_exam(async_client, seeded_users)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]
    s2_headers = seeded_users["student2"]["headers"]

    # Student 1 & 2 join
    s1_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    s2_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s2_headers)
    assert s1_join.status_code == 200
    assert s2_join.status_code == 200

    s1_session_id = s1_join.json()["session_id"]
    s2_session_id = s2_join.json()["session_id"]
    assert s1_session_id != s2_session_id

    q1_id = s1_join.json()["questions"][0]["id"]

    # Student 1 tries to save answers to Student 2's session ID -> 403 Forbidden
    tamper_answers = await async_client.post(
        f"/api/v1/student/sessions/{s2_session_id}/answers",
        json={"answers": {q1_id: "A"}},
        headers=s1_headers,
    )
    assert tamper_answers.status_code == 403
    assert "access denied" in tamper_answers.text.lower() or "cannot modify" in tamper_answers.text.lower()

    # Student 1 tries to submit Student 2's session -> 403 Forbidden
    tamper_submit = await async_client.post(
        f"/api/v1/student/sessions/{s2_session_id}/submit",
        json={"answers": {q1_id: "A"}},
        headers=s1_headers,
    )
    assert tamper_submit.status_code == 403


# ── TEST 4: Correct Answer Never Appears in API Response ──────────────────

@pytest.mark.asyncio
async def test_04_correct_answer_never_appears_in_api_response(async_client: AsyncClient, seeded_users):
    """4. Correct answer is NEVER serialized or sent to the student browser."""
    exam = await create_and_authorize_exam(async_client, seeded_users)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Check join response
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200
    raw_join_text = join_res.text

    assert "correct_answer" not in raw_join_text
    assert "correctAnswer" not in raw_join_text

    # Check session endpoint
    sess_res = await async_client.get(f"/api/v1/student/exams/{exam_id}/session", headers=s1_headers)
    assert sess_res.status_code == 200
    assert "correct_answer" not in sess_res.text
    assert "correctAnswer" not in sess_res.text

    # Check questions endpoint
    q_res = await async_client.get(f"/api/v1/student/exams/{exam_id}/questions", headers=s1_headers)
    assert q_res.status_code == 200
    assert "correct_answer" not in q_res.text

    # Inspect question objects in parsed JSON
    for q in q_res.json()["questions"]:
        assert "correct_answer" not in q
        assert "correct" not in q


# ── TEST 5: Timer Survives Refresh ────────────────────────────────────────

@pytest.mark.asyncio
async def test_05_timer_survives_refresh(async_client: AsyncClient, seeded_users):
    """5. Reloading the page or calling session endpoint preserves server-authoritative timer."""
    exam = await create_and_authorize_exam(async_client, seeded_users, duration_minutes=20)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Initial join
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200
    initial_data = join_res.json()
    started_at = initial_data["started_at"]
    expires_at = initial_data["expires_at"]
    session_id = initial_data["session_id"]
    q1_id = initial_data["questions"][0]["id"]

    # Save an answer
    await async_client.post(
        f"/api/v1/student/sessions/{session_id}/answers",
        json={"answers": {q1_id: "B"}},
        headers=s1_headers,
    )

    # Refresh 1: GET /student/exams/{exam_id}/session
    refresh_res = await async_client.get(f"/api/v1/student/exams/{exam_id}/session", headers=s1_headers)
    assert refresh_res.status_code == 200
    refreshed_data = refresh_res.json()

    assert refreshed_data["session_id"] == session_id
    assert refreshed_data["started_at"] == started_at
    assert refreshed_data["expires_at"] == expires_at
    assert refreshed_data["status"] == "IN_PROGRESS"
    assert refreshed_data["saved_answers"].get(q1_id) == "B"
    assert refreshed_data["remaining_seconds"] > 0

    # Refresh 2: POST /student/exams/{exam_id}/join (idempotent resume)
    rejoin_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert rejoin_res.status_code == 200
    rejoin_data = rejoin_res.json()
    assert rejoin_data["session_id"] == session_id
    assert rejoin_data["expires_at"] == expires_at
    assert rejoin_data["saved_answers"].get(q1_id) == "B"


# ── TEST 6: Expired Session Cannot Submit ─────────────────────────────────

@pytest.mark.asyncio
async def test_06_expired_session_cannot_submit(async_client: AsyncClient, seeded_users):
    """6. When server timer reaches zero / expired, session is EXPIRED and submissions are blocked."""
    exam = await create_and_authorize_exam(async_client, seeded_users, duration_minutes=1)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Join
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200
    session_id = join_res.json()["session_id"]
    q1_id = join_res.json()["questions"][0]["id"]

    # Manually expire the session in the test database
    from tests.conftest import TestingSessionLocal
    from sqlalchemy import select
    async with TestingSessionLocal() as db:
        res = await db.execute(select(StudentExamSession).where(StudentExamSession.id == session_id))
        sess = res.scalar_one()
        sess.expires_at = datetime.now(timezone.utc) - timedelta(minutes=5)
        sess.status = "EXPIRED"
        await db.commit()

    # Attempt to save answers to expired session -> 400 Bad Request
    save_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/answers",
        json={"answers": {q1_id: "A"}},
        headers=s1_headers,
    )
    assert save_res.status_code == 400
    assert "expired" in save_res.text.lower()

    # Attempt to submit expired session -> 400 Bad Request
    submit_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/submit",
        json={"answers": {q1_id: "A"}},
        headers=s1_headers,
    )
    assert submit_res.status_code == 400
    assert "expired" in submit_res.text.lower()


# ── TEST 7: Duplicate Submission Handled Safely ───────────────────────────

@pytest.mark.asyncio
async def test_07_duplicate_submission_handled_safely(async_client: AsyncClient, seeded_users):
    """7. Re-submitting an already-submitted exam returns successful idempotent receipt without duplicating."""
    exam = await create_and_authorize_exam(async_client, seeded_users, duration_minutes=15)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Join & save answers
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200
    session_id = join_res.json()["session_id"]
    q1 = join_res.json()["questions"][0]

    # First Submission
    sub1_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/submit",
        json={"answers": {q1["id"]: "A"}},
        headers=s1_headers,
    )
    assert sub1_res.status_code == 200
    sub1_data = sub1_res.json()
    assert sub1_data["status"] == "SUBMITTED"
    assert sub1_data["score"] is not None

    # Second Duplicate Submission
    sub2_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/submit",
        json={"answers": {q1["id"]: "B"}},
        headers=s1_headers,
    )
    assert sub2_res.status_code == 200
    sub2_data = sub2_res.json()
    assert sub2_data["status"] == "SUBMITTED"
    assert sub2_data["score"] == sub1_data["score"]
    assert "already submitted" in sub2_data["message"].lower()


# ── TEST 8: Student Cannot Use Guardian Endpoint ──────────────────────────

@pytest.mark.asyncio
async def test_08_student_cannot_use_guardian_endpoint(async_client: AsyncClient, seeded_users):
    """8. Students cannot approve papers, create exams, or access guardian operations."""
    s1_headers = seeded_users["student1"]["headers"]
    exam = await create_and_authorize_exam(async_client, seeded_users)
    exam_id = exam["id"]

    # 1. Student attempts to approve consensus -> 403 Forbidden
    app_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": "MALICIOUS_STUDENT_TOKEN"},
        headers=s1_headers,
    )
    assert app_res.status_code == 403

    # 2. Student attempts to create exam -> 403 Forbidden
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Illegal Student Exam",
            "course_code": "HACK-101",
            "scheduled_start": datetime.now(timezone.utc).isoformat(),
            "scheduled_end": (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
            "duration_minutes": 30,
            "required_quorum": 2,
            "total_guardians": 2,
        },
        headers=s1_headers,
    )
    assert create_res.status_code == 403

    # 3. Student attempts to stage paper -> 403 Forbidden
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"ttl_seconds": 3600},
        headers=s1_headers,
    )
    assert stage_res.status_code == 403

    # 4. Student attempts to view raw audit trail -> 403 Forbidden
    audit_res = await async_client.get("/api/v1/audit/events", headers=s1_headers)
    assert audit_res.status_code == 403


# ── TEST 9: Student Cannot Use Attacker Endpoint & Attacker Cannot Join Exam

@pytest.mark.asyncio
async def test_09_student_cannot_use_attacker_endpoint(async_client: AsyncClient, seeded_users):
    """9. Student cannot trigger attack simulator; Attacker cannot join exam as student."""
    s1_headers = seeded_users["student1"]["headers"]
    attacker_headers = seeded_users["attacker"]["headers"]
    exam = await create_and_authorize_exam(async_client, seeded_users)
    exam_id = exam["id"]

    # Student cannot run attack simulations -> 403 Forbidden
    sim_res = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "UNAUTHORIZED_ACCESS", "exam_id": exam_id},
        headers=s1_headers,
    )
    assert sim_res.status_code == 403

    # Attacker cannot join exam portal as student -> 403 Forbidden
    attacker_join = await async_client.post(
        f"/api/v1/student/exams/{exam_id}/join",
        headers=attacker_headers,
    )
    assert attacker_join.status_code == 403


# ── TEST 10: Two Students Independently Take the Same Exam ────────────────

@pytest.mark.asyncio
async def test_10_two_students_independently_take_same_exam(async_client: AsyncClient, seeded_users):
    """10. student1 and student2 take the same live exam simultaneously with independent sessions and metrics."""
    admin_headers = seeded_users["admin"]["headers"]
    exam = await create_and_authorize_exam(async_client, seeded_users, duration_minutes=30)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]
    s2_headers = seeded_users["student2"]["headers"]

    # Initial Guardian Stats: Registered: 2, Writing: 0, Submitted: 0
    stats1 = await async_client.get(f"/api/v1/exams/{exam_id}/student-stats", headers=admin_headers)
    assert stats1.status_code == 200
    d1 = stats1.json()
    assert d1["registered_count"] == 2
    assert d1["currently_writing"] == 0
    assert d1["submitted_count"] == 0

    # Student 1 joins
    s1_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert s1_join.status_code == 200
    s1_sess_id = s1_join.json()["session_id"]
    questions = s1_join.json()["questions"]
    q1_id = questions[0]["id"]
    q2_id = questions[1]["id"]

    # Student 2 joins
    s2_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s2_headers)
    assert s2_join.status_code == 200
    s2_sess_id = s2_join.json()["session_id"]

    assert s1_sess_id != s2_sess_id

    # Guardian Stats after both join: Registered: 2, Writing: 2, Submitted: 0
    stats2 = await async_client.get(f"/api/v1/exams/{exam_id}/student-stats", headers=admin_headers)
    assert stats2.status_code == 200
    d2 = stats2.json()
    assert d2["registered_count"] == 2
    assert d2["currently_writing"] == 2
    assert d2["submitted_count"] == 0

    # Student 1 answers Q1="A", Q2="B"
    await async_client.post(
        f"/api/v1/student/sessions/{s1_sess_id}/answers",
        json={"answers": {q1_id: "A", q2_id: "B"}},
        headers=s1_headers,
    )

    # Student 2 answers Q1="C", Q2="D" (distinct answers)
    await async_client.post(
        f"/api/v1/student/sessions/{s2_sess_id}/answers",
        json={"answers": {q1_id: "C", q2_id: "D"}},
        headers=s2_headers,
    )

    # Student 1 submits
    s1_sub = await async_client.post(
        f"/api/v1/student/sessions/{s1_sess_id}/submit",
        headers=s1_headers,
    )
    assert s1_sub.status_code == 200

    # Guardian Stats: Registered: 2, Writing: 1, Submitted: 1
    stats3 = await async_client.get(f"/api/v1/exams/{exam_id}/student-stats", headers=admin_headers)
    assert stats3.status_code == 200
    d3 = stats3.json()
    assert d3["registered_count"] == 2
    assert d3["currently_writing"] == 1
    assert d3["submitted_count"] == 1

    # Student 2 submits
    s2_sub = await async_client.post(
        f"/api/v1/student/sessions/{s2_sess_id}/submit",
        headers=s2_headers,
    )
    assert s2_sub.status_code == 200

    # Final Guardian Stats: Registered: 2, Writing: 0, Submitted: 2
    stats4 = await async_client.get(f"/api/v1/exams/{exam_id}/student-stats", headers=admin_headers)
    assert stats4.status_code == 200
    d4 = stats4.json()
    assert d4["registered_count"] == 2
    assert d4["currently_writing"] == 0
    assert d4["submitted_count"] == 2

    # Assert student details in guardian report
    students_data = {s["username"]: s for s in d4["students"]}
    assert "student1" in students_data
    assert "student2" in students_data
    assert students_data["student1"]["status"] == "SUBMITTED"
    assert students_data["student2"]["status"] == "SUBMITTED"
