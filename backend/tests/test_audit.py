"""Audit API test suite."""

from httpx import AsyncClient
import pytest
from tests.test_exams import create_user_and_login


@pytest.mark.asyncio
async def test_audit_logging_and_query(async_client: AsyncClient):
    auditor_auth = await create_user_and_login(async_client, "auditor_user", "AUDITOR")
    center_auth = await create_user_and_login(async_client, "center_auditor", "EXAM_CENTER")

    # 1. Ingest external audit event
    event_payload = {
        "action": "EXAM_PAPER_DOWNLOAD_VERIFIED",
        "details_json": '{"integrity_verified": true}',
    }
    ingest_res = await async_client.post("/api/v1/audit/events", json=event_payload, headers=center_auth["headers"])
    assert ingest_res.status_code == 201

    # 2. Query audit logs as AUDITOR
    logs_res = await async_client.get("/api/v1/audit/events", headers=auditor_auth["headers"])
    assert logs_res.status_code == 200
    events = logs_res.json()
    assert len(events) >= 1
    actions = [e["action"] for e in events]
    assert "EXAM_PAPER_DOWNLOAD_VERIFIED" in actions
