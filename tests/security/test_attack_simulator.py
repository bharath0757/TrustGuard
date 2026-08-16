"""
TrustGuard — Attack Simulator Integration Tests.

Validates that the controlled attack simulator executes all 10 scenarios cleanly,
verifies defensive Zero-Trust enforcement across all scenarios (100% DENY),
and ensures audit and threat logging are properly recorded.
"""

from datetime import datetime, timezone
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from attack_simulator.runner.simulator import AttackSimulator
from attack_simulator.runner.report import (
    format_text_report,
    format_markdown_report,
    format_json_report,
)
from attack_simulator.scenarios import (
    ALL_SCENARIOS,
    SCENARIOS_BY_ID,
    Scenario01UnauthorizedUser,
    Scenario02InsufficientPrivilege,
    Scenario03NoQuorum,
    Scenario04DuplicateApproval,
    Scenario05UnauthorizedApprover,
    Scenario06OutsideTimeWindow,
    Scenario07ReplayCompletedRequest,
    Scenario08TamperedFragment,
    Scenario09InvalidResource,
    Scenario10MalformedRequest,
)


@pytest.fixture
def sim_db_session():
    """In-memory SQLite session for attack simulation testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


def test_attack_simulator_all_10_scenarios_execute_and_defend(sim_db_session: Session):
    """
    Verify all 10 attack scenarios are executed and all attacks are blocked (DENY).
    """
    simulator = AttackSimulator(db_session=sim_db_session)
    results = simulator.run_all(db=sim_db_session)

    assert len(results) == 10, "Must execute exactly 10 attack simulation scenarios"

    for r in results:
        # Every scenario must pass defensive criteria
        assert r.passed is True, f"Scenario {r.scenario_id} ({r.scenario_name}) defense check failed: {r.actual_result}"
        # Every scenario must reach a DENY decision
        assert r.security_decision == "DENY", f"Scenario {r.scenario_id} must have security_decision DENY, got {r.security_decision}"
        # Every scenario must have a timestamp and valid resource descriptor
        assert r.timestamp is not None
        assert len(r.simulated_actor) > 0
        assert len(r.target_resource) > 0
        assert len(r.action_attempted) > 0
        assert len(r.expected_result) > 0
        assert len(r.actual_result) > 0
        # Audit logging verification
        assert r.audit_event_created is True, f"Scenario {r.scenario_id} must create audit/threat record"

    summary = simulator.get_summary()
    assert summary["total_scenarios"] == 10
    assert summary["blocked_attacks"] == 10
    assert summary["breached_attacks"] == 0
    assert summary["success_rate_percent"] == 100.0
    assert summary["all_denied"] is True
    assert summary["all_audited"] is True


@pytest.mark.parametrize("scenario_id", list(range(1, 11)))
def test_individual_scenario_execution(scenario_id: int, sim_db_session: Session):
    """
    Test each of the 10 scenarios independently to ensure isolation.
    """
    simulator = AttackSimulator(db_session=sim_db_session)
    result = simulator.run_scenario(scenario_id, db=sim_db_session)

    assert result.scenario_id == scenario_id
    assert result.passed is True
    assert result.security_decision == "DENY"
    assert result.audit_event_created is True


def test_attack_simulator_reporting_formats(sim_db_session: Session):
    """
    Verify text, markdown, and JSON report generators produce valid output.
    """
    simulator = AttackSimulator(db_session=sim_db_session)
    results = simulator.run_all(db=sim_db_session)

    text_report = format_text_report(results)
    assert "TRUSTGUARD CONTROLLED ATTACK SIMULATION REPORT" in text_report
    assert "Defense Success Rate: 10/10 (100.0%)" in text_report

    md_report = format_markdown_report(results)
    assert "# TrustGuard Attack Simulation Summary Report" in md_report
    assert "| ID | Scenario Name |" in md_report

    json_report = format_json_report(results)
    import json
    parsed_json = json.loads(json_report)
    assert len(parsed_json) == 10
    assert parsed_json[0]["security_decision"] == "DENY"
