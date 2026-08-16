"""Integration tests for Backend Simulation API endpoints."""

import pytest
from httpx import AsyncClient
from tests.fixtures import setup_all_synthetic_users


@pytest.mark.asyncio
async def test_list_simulation_scenarios(async_client: AsyncClient):
    """GET /api/v1/simulation/scenarios returns all 5 core controlled simulation scenarios."""
    response = await async_client.get("/api/v1/simulation/scenarios")
    assert response.status_code == 200
    scenarios = response.json()
    assert len(scenarios) >= 5

    scenario_ids = [s["id"] for s in scenarios]
    assert "UNAUTHORIZED_ACCESS" in scenario_ids
    assert "INSIDER_ATTEMPT" in scenario_ids
    assert "INVALID_QUORUM" in scenario_ids
    assert "TAMPERED_FRAGMENT" in scenario_ids
    assert "REPLAY_ATTEMPT" in scenario_ids


@pytest.mark.asyncio
async def test_run_simulation_unauthorized_access(async_client: AsyncClient):
    """POST /api/v1/simulation/run for UNAUTHORIZED_ACCESS produces real BLOCKED decision & audit event."""
    response = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "UNAUTHORIZED_ACCESS", "target_paper_id": "JEE-MOCK-001"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["scenario_id"] == "UNAUTHORIZED_ACCESS"
    assert data["target_paper"] == "JEE-MOCK-001"
    assert data["expected_decision"] == "DENY"
    assert data["actual_decision"] == "BLOCKED"
    assert data["status_category"] == "BLOCKED"
    assert data["risk_severity"] == "CRITICAL"
    assert "audit_event_id" in data
    assert data["audit_event_id"] is not None

    users = await setup_all_synthetic_users(async_client)
    auditor = users["auditor"]

    # Verify audit event is in audit log
    audit_res = await async_client.get("/api/v1/audit/events", headers=auditor["headers"])
    assert audit_res.status_code == 200
    events = audit_res.json()
    assert any(e["id"] == data["audit_event_id"] for e in events)


@pytest.mark.asyncio
async def test_run_simulation_insider_attempt(async_client: AsyncClient):
    """POST /api/v1/simulation/run for INSIDER_ATTEMPT produces INVALID AUTHORIZATION decision."""
    response = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "INSIDER_ATTEMPT", "target_paper_id": "NEET-MOCK-002"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["actual_decision"] == "INVALID AUTHORIZATION"
    assert data["status_category"] == "INVALID AUTHORIZATION"
    assert data["security_decision"] == "DENY"
    assert data["risk_severity"] == "HIGH"


@pytest.mark.asyncio
async def test_run_simulation_invalid_quorum(async_client: AsyncClient):
    """POST /api/v1/simulation/run for INVALID_QUORUM produces INVALID AUTHORIZATION decision."""
    response = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "INVALID_QUORUM", "target_paper_id": "EXAM-MOCK-003"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["actual_decision"] == "INVALID AUTHORIZATION"
    assert data["status_category"] == "INVALID AUTHORIZATION"
    assert data["risk_severity"] == "MEDIUM"


@pytest.mark.asyncio
async def test_run_simulation_tampered_fragment(async_client: AsyncClient):
    """POST /api/v1/simulation/run for TAMPERED_FRAGMENT produces FAILED INTEGRITY decision."""
    response = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "TAMPERED_FRAGMENT", "target_paper_id": "DEMO-004"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["actual_decision"] == "FAILED INTEGRITY"
    assert data["status_category"] == "FAILED INTEGRITY"
    assert data["risk_severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_run_simulation_replay_attempt(async_client: AsyncClient):
    """POST /api/v1/simulation/run for REPLAY_ATTEMPT produces BLOCKED decision."""
    response = await async_client.post(
        "/api/v1/simulation/run",
        json={"scenario_id": "REPLAY_ATTEMPT", "target_paper_id": "JEE-MOCK-001"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["actual_decision"] == "BLOCKED"
    assert data["status_category"] == "BLOCKED"
    assert data["risk_severity"] == "HIGH"
