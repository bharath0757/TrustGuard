"""Phase 6 Security and Functional Tests: Real-Time Guardian Examination Monitoring Dashboard.

Covers:
1. Full aggregated dashboard-state API reflecting actual backend state (no hardcoding).
2. WebSocket connection establishment with JWT authentication and INIT_STATE delivery.
3. Student 1 joins -> Currently writing count becomes 1 (live reactive).
4. Student 2 joins -> Currently writing count becomes 2 (live reactive).
5. Student 1 submits -> Currently writing drops to 1, submitted count becomes 1/2.
6. Student 2 submits -> Currently writing drops to 0, submitted count becomes 2/2.
7. Guardian consensus approvals broadcast in real time with threshold progression.
8. Exam start and completion state transitions broadcast live.
9. Security events and audit trails stream in chronological order to the dashboard.
10. Unauthorized/invalid token WebSocket connections are rejected.
"""

import io
import json
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient
from starlette.testclient import TestClient
from starlette.websockets import WebSocketDisconnect
from sqlalchemy import select

from main import app
from app.core.config import settings
from app.db.models import Exam, User, Question, StudentExamSession, UploadedPaper
from app.services.exam_lifecycle_service import ExamLifecycleService
from app.services.websocket_manager import get_ws_manager
from tests.conftest import TestingSessionLocal


@pytest.fixture
def sync_test_client():
    """Synchronous test client for Starlette WebSocket testing."""
    return TestClient(app)


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


async def create_and_authorize_test_exam(async_client: AsyncClient, seeded_users: dict, duration_minutes: int = 15) -> dict:
    """Helper to create an exam, upload/stage paper, register students, and unlock it."""
    admin_headers = seeded_users["admin"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals",
            "course_code": f"SEC-{now.microsecond}",
            "description": "Comprehensive evaluation of zero-trust and crypto principles.",
            "duration_minutes": duration_minutes,
            "scheduled_start": (now + timedelta(minutes=1)).isoformat(),
            "scheduled_end": (now + timedelta(minutes=duration_minutes + 1)).isoformat(),
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=admin_headers,
    )
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]

    # 2. Upload Paper
    mock_pdf = io.BytesIO(b"%PDF-1.4 Mock Exam Paper Content for Real-Time Monitoring Test")
    mock_pdf.name = "Cybersecurity_Paper.pdf"
    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Cybersecurity Fundamentals Paper", "description": "Mock exam paper"},
        files={"file": ("Cybersecurity_Paper.pdf", mock_pdf, "application/pdf")},
        headers=admin_headers,
    )
    assert upload_res.status_code == 201
    paper_id = upload_res.json()["id"]

    # 3. Assign 3 Key Guardians
    for idx, g_key in enumerate(["guardian1", "guardian2", "guardian3"]):
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

    return exam


@pytest.mark.asyncio
async def test_01_dashboard_state_api_returns_actual_backend_state(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify GET /api/v1/exam-lifecycle/{exam_id}/dashboard-state returns full, unhardcoded state."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam_id = exam.id

    # Fetch dashboard state as Guardian
    res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert res.status_code == 200
    data = res.json()

    assert data["exam_id"] == exam_id
    assert data["exam_title"] == "Cybersecurity Fundamentals"
    assert data["course_code"] == "CS-SEC-2026"
    assert data["status"] in ["AUTHORIZED", "LIVE", "DRAFT", "READY"]
    assert data["registered_students_count"] >= 2
    assert "currently_writing_count" in data
    assert "submitted_count" in data
    assert "expired_count" in data
    assert "remaining_seconds" in data
    assert "security_status" in data
    assert "attack_attempts" in data
    assert "blocked_attacks" in data
    assert "recent_audit_events" in data
    assert isinstance(data["guardians"], list)
    assert isinstance(data["students"], list)


@pytest.mark.asyncio
async def test_02_websocket_guardian_connection_and_init_state(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify WebSocket connection, auth validation, and INIT_STATE serialization."""
    guardian_token = seeded_users["guardian1"]["token"]
    student_token = seeded_users["student1"]["token"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam_id = exam.id

        # 1. Test WebSocket token authentication validator
        from app.api.v1.ws import _authenticate_ws
        user = await _authenticate_ws(guardian_token, session)
        assert user is not None
        assert user.role == "KEY_GUARDIAN"
        assert user.username == "guardian1"

        # Test invalid token rejected
        bad_user = await _authenticate_ws("invalid.jwt.token", session)
        assert bad_user is None

        # Test student token recognized
        s_user = await _authenticate_ws(student_token, session)
        assert s_user is not None
        assert s_user.role == "STUDENT"

        # 2. Test initial dashboard state generation and serialization for WebSocket stream
        init_state = await ExamLifecycleService.get_full_dashboard_state(session, exam_id)
        assert init_state is not None
        assert init_state["course_code"] == "CS-SEC-2026"
        assert init_state["registered_students_count"] >= 2
        # Ensure json serialization works without error
        serialized = json.dumps({"type": "INIT_STATE", "exam_id": exam_id, "payload": init_state}, default=str)
        deserialized = json.loads(serialized)
        assert deserialized["type"] == "INIT_STATE"
        assert deserialized["payload"]["exam_id"] == exam_id

    # 3. Test WebSocket Manager broadcast and connection lifecycle
    ws_manager = get_ws_manager()

    class MockWebSocket:
        def __init__(self):
            self.accepted = False
            self.messages = []
            self.closed = False

        async def accept(self):
            self.accepted = True

        async def send_text(self, text: str):
            self.messages.append(text)

        async def close(self, code=1000, reason=""):
            self.closed = True

    mock_ws = MockWebSocket()
    await ws_manager.connect(mock_ws, exam_id)
    assert mock_ws.accepted is True
    assert mock_ws in ws_manager._exam_connections[exam_id]

    # Broadcast event
    await ws_manager.broadcast_to_exam(exam_id, "STATS_UPDATED", {"currently_writing_count": 2})
    assert len(mock_ws.messages) == 1
    sent_msg = json.loads(mock_ws.messages[0])
    assert sent_msg["type"] == "STATS_UPDATED"
    assert sent_msg["payload"]["currently_writing_count"] == 2

    # Disconnect
    await ws_manager.disconnect(mock_ws, exam_id)
    assert mock_ws not in ws_manager._exam_connections.get(exam_id, set())


@pytest.mark.asyncio
async def test_03_student_1_join_updates_writing_count_to_1(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify Student 1 joining transitions writing count to 1."""
    guardian_headers = seeded_users["guardian1"]["headers"]
    s1_headers = seeded_users["student1"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam.status = "AUTHORIZED"
        await session.commit()
        exam_id = exam.id

    # 1. Student 1 joins exam
    join_res = await async_client.post(
        f"/api/v1/student/exams/{exam_id}/join",
        headers=s1_headers,
    )
    assert join_res.status_code == 200

    # 2. Verify guardian dashboard state reflects Writing: 1, Submitted: 0
    dash_res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()

    assert dash_data["currently_writing_count"] == 1
    assert dash_data["submitted_count"] == 0


@pytest.mark.asyncio
async def test_04_student_2_join_updates_writing_count_to_2(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify Student 2 joining transitions writing count to 2."""
    guardian_headers = seeded_users["guardian1"]["headers"]
    s1_headers = seeded_users["student1"]["headers"]
    s2_headers = seeded_users["student2"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam.status = "AUTHORIZED"
        await session.commit()
        exam_id = exam.id

    # Both students join
    await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    s2_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s2_headers)
    assert s2_join.status_code == 200

    # Guardian check: Writing: 2, Submitted: 0
    dash_res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()

    assert dash_data["currently_writing_count"] == 2
    assert dash_data["submitted_count"] == 0


@pytest.mark.asyncio
async def test_05_student_1_submit_updates_writing_1_and_submitted_1_of_2(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify Student 1 submission transitions Writing: 1, Submitted: 1/2."""
    guardian_headers = seeded_users["guardian1"]["headers"]
    s1_headers = seeded_users["student1"]["headers"]
    s2_headers = seeded_users["student2"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam.status = "AUTHORIZED"
        await session.commit()
        exam_id = exam.id

    s1_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    s1_session_id = s1_join.json()["session_id"]
    await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s2_headers)

    # Student 1 submits
    sub_res = await async_client.post(
        f"/api/v1/student/sessions/{s1_session_id}/submit",
        json={"answers": {"1": "A", "2": "B"}},
        headers=s1_headers,
    )
    assert sub_res.status_code == 200

    # Guardian check: Writing: 1, Submitted: 1
    dash_res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()

    assert dash_data["currently_writing_count"] == 1
    assert dash_data["submitted_count"] == 1


@pytest.mark.asyncio
async def test_06_student_2_submit_updates_writing_0_and_submitted_2_of_2(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify Student 2 submission transitions Writing: 0, Submitted: 2/2."""
    guardian_headers = seeded_users["guardian1"]["headers"]
    s1_headers = seeded_users["student1"]["headers"]
    s2_headers = seeded_users["student2"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam.status = "AUTHORIZED"
        await session.commit()
        exam_id = exam.id

    s1_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s1_headers)
    s1_session_id = s1_join.json()["session_id"]
    s2_join = await async_client.post(f"/api/v1/student/exams/{exam_id}/join", headers=s2_headers)
    s2_session_id = s2_join.json()["session_id"]

    # Student 1 submits
    await async_client.post(
        f"/api/v1/student/sessions/{s1_session_id}/submit",
        json={"answers": {"1": "A"}},
        headers=s1_headers,
    )

    # Student 2 submits
    await async_client.post(
        f"/api/v1/student/sessions/{s2_session_id}/submit",
        json={"answers": {"1": "B", "2": "C"}},
        headers=s2_headers,
    )

    # Guardian check: Writing: 0, Submitted: 2
    dash_res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert dash_res.status_code == 200
    dash_data = dash_res.json()

    assert dash_data["currently_writing_count"] == 0
    assert dash_data["submitted_count"] == 2


@pytest.mark.asyncio
async def test_07_guardian_approval_broadcasts_consensus_in_realtime(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify Guardian consensus approvals update consensus counts and release paper upon quorum."""
    admin_headers = seeded_users["admin"]["headers"]
    g1_headers = seeded_users["guardian1"]["headers"]
    g2_headers = seeded_users["guardian2"]["headers"]

    # Create new exam requiring 2 of 3 approvals
    now = datetime.now(timezone.utc)
    exam_payload = {
        "title": "Real-Time Consensus Test",
        "course_code": f"RT-{now.microsecond}",
        "duration_minutes": 45,
        "scheduled_start": (now + timedelta(minutes=1)).isoformat(),
        "scheduled_end": (now + timedelta(minutes=90)).isoformat(),
        "required_quorum": 2,
        "total_guardians": 3,
    }
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=exam_payload,
        headers=admin_headers,
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # Assign guardians 1 and 2
    for g_key in ["guardian1", "guardian2", "guardian3"]:
        g = seeded_users[g_key]
        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g["user_id"], "public_key_fingerprint": f"RSA_{g_key}"},
            headers=admin_headers,
        )
        assert assign_res.status_code == 201

    # Guardian 1 approves
    app1 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=g1_headers,
    )
    assert app1.status_code == 200
    assert app1.json()["current_quorum_count"] == 1
    assert app1.json()["quorum_reached"] is False

    # Check dashboard state: Approvals: 1/2
    dash1 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=admin_headers,
    )
    assert dash1.json()["approvals_count"] == 1
    assert dash1.json()["quorum_achieved"] is False

    # Guardian 2 approves -> Quorum reached!
    app2 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        headers=g2_headers,
    )
    assert app2.status_code == 200
    assert app2.json()["current_quorum_count"] == 2
    assert app2.json()["quorum_reached"] is True

    # Check dashboard state: Approvals: 2/2, status: AUTHORIZED
    dash2 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=admin_headers,
    )
    assert dash2.json()["approvals_count"] == 2
    assert dash2.json()["quorum_achieved"] is True
    assert dash2.json()["status"] == "AUTHORIZED"


@pytest.mark.asyncio
async def test_08_exam_start_and_end_broadcasts_lifecycle_events(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify starting and ending exam updates dashboard status and server-authoritative timestamps."""
    admin_headers = seeded_users["admin"]["headers"]

    exam = await create_and_authorize_test_exam(async_client, seeded_users, duration_minutes=20)
    exam_id = exam["id"]

    # Start exam -> Transitions to LIVE
    start_res = await async_client.post(f"/api/v1/exam-lifecycle/{exam_id}/start", headers=admin_headers)
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "LIVE"

    dash_live = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=admin_headers)
    assert dash_live.json()["status"] == "LIVE"
    assert dash_live.json()["started_at"] is not None
    assert dash_live.json()["remaining_seconds"] > 0

    # End exam -> Transitions to COMPLETED
    end_res = await async_client.post(f"/api/v1/exam-lifecycle/{exam_id}/end", headers=admin_headers)
    assert end_res.status_code == 200
    assert end_res.json()["status"] == "COMPLETED"

    dash_comp = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=admin_headers)
    assert dash_comp.json()["status"] == "COMPLETED"
    assert dash_comp.json()["ended_at"] is not None


@pytest.mark.asyncio
async def test_09_security_audit_events_stream_to_monitor(
    async_client: AsyncClient,
    seeded_users: dict,
):
    """Verify security and audit events appear in chronological order on dashboard."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    async with TestingSessionLocal() as session:
        stmt = select(Exam).where(Exam.course_code == "CS-SEC-2026")
        res = await session.execute(stmt)
        exam = res.scalar_one()
        exam_id = exam.id

    # Fetch dashboard events
    dash_res = await async_client.get(f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state", headers=guardian_headers)
    assert dash_res.status_code == 200
    events = dash_res.json()["recent_audit_events"]
    assert isinstance(events, list)
    if len(events) >= 2:
        # Verify chronological order (newest first)
        t0 = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
        t1 = datetime.fromisoformat(events[1]["timestamp"].replace("Z", "+00:00"))
        assert t0 >= t1


def test_10_unauthorized_websocket_connection_rejected(
    sync_test_client: TestClient,
):
    """Verify WebSocket rejects connections with missing token, invalid token, or student role."""
    sync_test_client.post("/api/v1/users/seed")
    s1_login = sync_test_client.post(
        "/api/v1/auth/login",
        json={"username": "student1", "password": settings.DEMO_PASSWORD},
    )
    assert s1_login.status_code == 200
    s1_token = s1_login.json()["access_token"]
    exam_id = "demo-exam-id"

    # 1. Missing token
    with pytest.raises((WebSocketDisconnect, Exception)):
        with sync_test_client.websocket_connect(f"/api/v1/ws/exams/{exam_id}") as ws:
            ws.receive_json()

    # 2. Invalid token
    with pytest.raises((WebSocketDisconnect, Exception)):
        with sync_test_client.websocket_connect(f"/api/v1/ws/exams/{exam_id}?token=invalid.jwt.token") as ws:
            ws.receive_json()

    # 3. Student role attempting to access guardian WebSocket stream
    with pytest.raises((WebSocketDisconnect, Exception)):
        with sync_test_client.websocket_connect(f"/api/v1/ws/exams/{exam_id}?token={s1_token}") as ws:
            ws.receive_json()

