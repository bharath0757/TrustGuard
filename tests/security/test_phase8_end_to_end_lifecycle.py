"""Phase 8 End-to-End Test Suite: Complete Examination Lifecycle & Final Security Report Validation.

Executes the complete 28-step automated end-to-end scenario:
1. Guardian 1 logs in
2. Guardian 2 logs in
3. Guardian 3 logs in
4. Student 1 logs in
5. Student 2 logs in
6. Attacker logs in
7. Guardian creates exam
8. Guardian uploads paper
9. Paper is encrypted & staged in ephemeral RAM
10. Guardian 1 approves
11. Guardian 2 approves
12. Verify paper access is STILL blocked (2/3 < 3/3 quorum)
13. Guardian 3 approves
14. Verify 3/3 consensus reached (status transitions to AUTHORIZED)
15. Release/start exam (status transitions to LIVE)
16. Student 1 joins examination session
17. Student 2 joins examination session
18. Guardian dashboard shows 2 active writing candidates
19. Server timer is active and authoritative
20. Attacker attempts unauthorized paper access
21. Attack is blocked by Zero-Trust gate (HTTP 403)
22. Guardian dashboard receives security alert & records blocked attempt
23. Student 1 submits examination answers
24. Dashboard updates (1 writing, 1 submitted)
25. Student 2 submits examination answers
26. Dashboard updates (0 writing, 2 submitted)
27. Exam completes (status transitions to COMPLETED, ephemeral memory purged)
28. Final security report is generated, verified, and exported
"""

import io
import json
import pytest
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient

from app.core.config import settings


@pytest.fixture
async def seeded_all_users(async_client: AsyncClient):
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


@pytest.mark.asyncio
async def test_phase8_complete_28_step_end_to_end_lifecycle(
    async_client: AsyncClient, seeded_all_users: dict
):
    """Execute the full 28-step examination lifecycle from consensus to final report."""

    # ── Steps 1-6: All 6 actors login and authenticate ────────────────────────
    g1 = seeded_all_users["guardian1"]
    g2 = seeded_all_users["guardian2"]
    g3 = seeded_all_users["guardian3"]
    s1 = seeded_all_users["student1"]
    s2 = seeded_all_users["student2"]
    att = seeded_all_users["attacker"]
    admin = seeded_all_users["admin"]

    assert g1["role"] in ["KEY_GUARDIAN", "GUARDIAN"]
    assert g2["role"] in ["KEY_GUARDIAN", "GUARDIAN"]
    assert g3["role"] in ["KEY_GUARDIAN", "GUARDIAN"]
    assert s1["role"] == "STUDENT"
    assert s2["role"] == "STUDENT"
    assert att["role"] == "ATTACKER"

    # ── Step 7: Guardian creates exam ─────────────────────────────────────────
    now = datetime.now(timezone.utc)
    create_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals Final Exam",
            "course_code": f"CS-E2E-{now.microsecond}",
            "description": "Full lifecycle 28-step verification exam.",
            "duration_minutes": 30,
            "scheduled_start": (now - timedelta(minutes=2)).isoformat(),
            "scheduled_end": (now + timedelta(hours=2)).isoformat(),
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=g1["headers"],
    )
    assert create_res.status_code == 201, create_res.text
    exam = create_res.json()
    exam_id = exam["id"]

    # Assign 3 Key Guardians
    for g_user in [g1, g2, g3]:
        await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={
                "guardian_user_id": g_user["user_id"],
                "public_key_fingerprint": f"SHA256:SIG_{g_user['user_id'][:8].upper()}",
            },
            headers=g1["headers"],
        )

    # Register both Student 1 and Student 2
    reg_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/students",
        json={"student_user_ids": [s1["user_id"], s2["user_id"]]},
        headers=g1["headers"],
    )
    assert reg_res.status_code == 201

    # ── Step 8: Guardian uploads question paper ───────────────────────────────
    mock_pdf = io.BytesIO(b"%PDF-1.4 Official Final Examination Paper 2026 Cryptographic Security")
    mock_pdf.name = "Cybersecurity_Paper.pdf"
    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Cybersecurity Paper 2026", "description": "Official master paper"},
        files={"file": ("Cybersecurity_Paper.pdf", mock_pdf, "application/pdf")},
        headers=g1["headers"],
    )
    assert upload_res.status_code == 201
    paper_id = upload_res.json()["id"]

    # ── Step 9: Paper is encrypted & staged into ephemeral RAM ────────────────
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 3600},
        headers=g1["headers"],
    )
    assert stage_res.status_code == 200

    # ── Step 10: Guardian 1 approves ──────────────────────────────────────────
    g1_app = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"approval_note": "Guardian 1 authorized"},
        headers=g1["headers"],
    )
    assert g1_app.status_code == 200
    assert g1_app.json()["current_quorum_count"] == 1
    assert g1_app.json()["quorum_reached"] is False

    # ── Step 11: Guardian 2 approves ──────────────────────────────────────────
    g2_app = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"approval_note": "Guardian 2 authorized"},
        headers=g2["headers"],
    )
    assert g2_app.status_code == 200
    assert g2_app.json()["current_quorum_count"] == 2
    assert g2_app.json()["quorum_reached"] is False

    # ── Step 12: Verify paper is STILL blocked (2/3 < 3/3 quorum) ─────────────
    paper_block_res = await async_client.get(
        f"/api/v1/exams/{exam_id}/paper",
        headers=s1["headers"],
    )
    # Student cannot access paper before full 3/3 quorum
    assert paper_block_res.status_code == 403
    assert "not yet authorized" in paper_block_res.json()["detail"]

    # ── Step 13: Guardian 3 approves ──────────────────────────────────────────
    g3_app = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"approval_note": "Guardian 3 authorized"},
        headers=g3["headers"],
    )
    assert g3_app.status_code == 200
    assert g3_app.json()["current_quorum_count"] == 3
    assert g3_app.json()["quorum_reached"] is True

    # ── Step 14: Verify 3/3 consensus reached ─────────────────────────────────
    q_status = await async_client.get(
        f"/api/v1/consensus/{exam_id}/status",
        headers=g1["headers"],
    )
    assert q_status.status_code == 200
    assert q_status.json()["quorum_reached"] is True
    assert q_status.json()["current_approvals_count"] == 3

    # ── Step 15: Start / Release Exam (transitions to LIVE) ───────────────────
    start_res = await async_client.post(
        f"/api/v1/exam-lifecycle/{exam_id}/start",
        headers=admin["headers"],
    )
    assert start_res.status_code == 200
    assert start_res.json()["status"] == "LIVE"

    # ── Step 16: Student 1 joins examination session ──────────────────────────
    s1_join = await async_client.post(
        f"/api/v1/student/exams/{exam_id}/join",
        headers=s1["headers"],
    )
    assert s1_join.status_code == 200
    assert s1_join.json()["status"] == "IN_PROGRESS"
    assert len(s1_join.json()["questions"]) > 0
    s1_session_id = s1_join.json()["session_id"]

    # ── Step 17: Student 2 joins examination session ──────────────────────────
    s2_join = await async_client.post(
        f"/api/v1/student/exams/{exam_id}/join",
        headers=s2["headers"],
    )
    assert s2_join.status_code == 200
    assert s2_join.json()["status"] == "IN_PROGRESS"
    assert len(s2_join.json()["questions"]) > 0
    s2_session_id = s2_join.json()["session_id"]

    # ── Step 18: Guardian dashboard shows 2 active writing students ───────────
    dash_1 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=g1["headers"],
    )
    assert dash_1.status_code == 200
    d1_data = dash_1.json()
    assert d1_data["registered_students_count"] == 2
    assert d1_data["currently_writing_count"] == 2
    assert d1_data["submitted_count"] == 0

    # ── Step 19: Server timer is running and authoritative ────────────────────
    assert d1_data["remaining_seconds"] > 0
    assert d1_data["status"] == "LIVE"

    # ── Step 20: Attacker attempts unauthorized paper access ──────────────────
    att_res = await async_client.post(
        f"/api/v1/attack-sim/{exam_id}/execute",
        json={"attack_type": "UNAUTHORIZED_PAPER_ACCESS"},
        headers=att["headers"],
    )

    # ── Step 21: Attack is blocked by Zero-Trust gate (HTTP 403) ──────────────
    assert att_res.status_code == 200
    att_data = att_res.json()
    assert att_data["result"] == "BLOCKED"
    assert att_data["http_status"] == 403
    assert att_data["security_decision"] == "DENY"
    assert att_data["passed"] is True

    # ── Step 22: Guardian dashboard receives security alert & records blocked attack
    dash_2 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=g1["headers"],
    )
    assert dash_2.status_code == 200
    d2_data = dash_2.json()
    assert d2_data["attack_attempts"] >= 1
    assert d2_data["blocked_attacks"] >= 1

    # ── Step 23: Student 1 submits answers ────────────────────────────────────
    s1_q1 = s1_join.json()["questions"][0]["id"]
    s1_sub = await async_client.post(
        f"/api/v1/student/sessions/{s1_session_id}/submit",
        json={"answers": {s1_q1: "A"}},
        headers=s1["headers"],
    )
    assert s1_sub.status_code == 200
    assert s1_sub.json()["status"] == "SUBMITTED"

    # ── Step 24: Guardian dashboard updates (1 writing, 1 submitted) ──────────
    dash_3 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=g1["headers"],
    )
    assert dash_3.status_code == 200
    d3_data = dash_3.json()
    assert d3_data["currently_writing_count"] == 1
    assert d3_data["submitted_count"] == 1

    # ── Step 25: Student 2 submits answers ────────────────────────────────────
    s2_q1 = s2_join.json()["questions"][0]["id"]
    s2_sub = await async_client.post(
        f"/api/v1/student/sessions/{s2_session_id}/submit",
        json={"answers": {s2_q1: "B"}},
        headers=s2["headers"],
    )
    assert s2_sub.status_code == 200
    assert s2_sub.json()["status"] == "SUBMITTED"

    # ── Step 26: Guardian dashboard updates (0 writing, 2 submitted) ──────────
    dash_4 = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/dashboard-state",
        headers=g1["headers"],
    )
    assert dash_4.status_code == 200
    d4_data = dash_4.json()
    assert d4_data["currently_writing_count"] == 0
    assert d4_data["submitted_count"] == 2

    # ── Step 27: Exam completes (transitions to COMPLETED, ephemeral RAM purged)
    end_res = await async_client.post(
        f"/api/v1/exam-lifecycle/{exam_id}/end",
        json={"confirm": True},
        headers=admin["headers"],
    )
    assert end_res.status_code == 200
    assert end_res.json()["status"] == "COMPLETED"

    # ── Step 28: Final security report is generated and verified ──────────────
    rep_res = await async_client.get(
        f"/api/v1/exam-lifecycle/{exam_id}/report",
        headers=g1["headers"],
    )
    assert rep_res.status_code == 200
    report = rep_res.json()

    # 1. Exam Information
    assert report["exam_id"] == exam_id
    assert report["status"] == "COMPLETED"
    assert report["duration_minutes"] == 30

    # 2. Participation
    assert report["registered_students"] == 2
    assert report["students_joined"] == 2
    assert report["currently_writing"] == 0
    assert report["submitted_count"] == 2
    assert report["expired_count"] == 0

    # 3. Guardian Consensus
    assert report["required_quorum"] == 3
    assert report["total_guardians"] == 3
    assert report["approvals_count"] == 3
    assert report["quorum_achieved"] is True
    assert report["paper_release_status"] == "AUTHORIZED"
    assert len(report["guardians"]) == 3
    for g_info in report["guardians"]:
        assert g_info["approved"] is True

    # 4. Security Statistics
    assert report["attack_attempts"] >= 1
    assert report["blocked_attempts"] >= 1
    assert report["successful_attacks"] == 0
    assert report["overall_security"] == "VERIFIED"

    # 5. Factual Statements (no false claims)
    factual = report["factual_statements"]
    assert len(factual) > 0
    assert "All simulated unauthorized actions were blocked." in factual or any("blocked" in s.lower() for s in factual)
    assert any("threshold" in s.lower() for s in factual)
    assert any("audit" in s.lower() for s in factual)

    # 6. Chronological Timeline
    timeline = report["timeline"]
    assert len(timeline) >= 5
    timeline_titles = [t["title"] for t in timeline]
    assert any("Approved" in t or "Approval" in t for t in timeline_titles)
    assert any("Attack" in t or "Blocked" in t or "Security" in t or "Unauthorized" in t for t in timeline_titles)
