"""Unit and API integration tests for Phase 5 Student Examination Portal."""

from datetime import datetime, timedelta, timezone
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
        assert res.status_code == 200
        data = res.json()
        accounts[u] = {
            "token": data["access_token"],
            "role": data["role"],
            "user_id": data["user_id"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
        }
    return accounts


async def setup_live_exam(async_client: AsyncClient, seeded_users: dict, duration_minutes: int = 10) -> dict:
    """Helper to set up an authorized live exam with registered students."""
    admin_headers = seeded_users["admin"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals",
            "course_code": f"SEC-UNIT-{now.microsecond}",
            "description": "Final test",
            "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
            "scheduled_end": (now + timedelta(hours=1)).isoformat(),
            "duration_minutes": duration_minutes,
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]

    # 2. Assign guardians
    for g_key in ["guardian1", "guardian2", "guardian3"]:
        await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": seeded_users[g_key]["user_id"], "public_key_fingerprint": f"FP_{g_key}"},
            headers=admin_headers,
        )

    # 3. Register students
    await async_client.post(
        f"/api/v1/exams/{exam_id}/students",
        json={"student_user_ids": [seeded_users["student1"]["user_id"], seeded_users["student2"]["user_id"]]},
        headers=admin_headers,
    )

    # 4. Stage paper
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"ttl_seconds": 3600},
        headers=admin_headers,
    )

    # 5. Approvals
    for idx, g_key in enumerate(["guardian1", "guardian2", "guardian3"]):
        await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": f"TOKEN_{idx+1}"},
            headers=seeded_users[g_key]["headers"],
        )

    # 6. Start exam
    await async_client.post(
        f"/api/v1/exam-lifecycle/{exam_id}/start",
        headers=admin_headers,
    )

    return exam


@pytest.mark.asyncio
async def test_student_list_exams(async_client: AsyncClient, seeded_users):
    """Verify student can list assigned examinations."""
    exam = await setup_live_exam(async_client, seeded_users)
    s1_headers = seeded_users["student1"]["headers"]

    res = await async_client.get("/api/v1/student/exams", headers=s1_headers)
    assert res.status_code == 200
    exams = res.json()
    assert len(exams) >= 1
    found = [e for e in exams if e["id"] == exam["id"]]
    assert len(found) == 1
    assert found[0]["session_status"] == "NOT_STARTED"
    assert found[0]["is_joinable"] is True


@pytest.mark.asyncio
async def test_student_exam_complete_flow(async_client: AsyncClient, seeded_users):
    """Verify full end-to-end flow: join -> answer -> submit -> verify score."""
    exam = await setup_live_exam(async_client, seeded_users, duration_minutes=15)
    exam_id = exam["id"]
    s1_headers = seeded_users["student1"]["headers"]

    # Join
    join_res = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    assert join_res.status_code == 200
    session_data = join_res.json()
    session_id = session_data["session_id"]
    questions = session_data["questions"]

    # Answer questions
    answers_to_submit = {}
    for q in questions[:5]:
        answers_to_submit[q["id"]] = "A"

    save_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/answers",
        json={"answers": answers_to_submit},
        headers=s1_headers,
    )
    assert save_res.status_code == 200
    assert save_res.json()["saved_answers"] == answers_to_submit

    # Submit
    submit_res = await async_client.post(
        f"/api/v1/student/sessions/{session_id}/submit",
        headers=s1_headers,
    )
    assert submit_res.status_code == 200
    result = submit_res.json()
    assert result["status"] == "SUBMITTED"
    assert result["answers_recorded"] == 5
    assert result["score"] is not None
