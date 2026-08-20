"""
TrustGuard Attack Simulator — Core Simulation Runner.

SAFE LOCAL SIMULATION ONLY.
Orchestrates execution of the 10 controlled attack simulation scenarios.
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional, Type, Union

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from attack_simulator.scenarios.base import BaseAttackScenario
from attack_simulator.scenarios.models import SimulationResult
from attack_simulator.scenarios import ALL_SCENARIOS, SCENARIOS_BY_ID

logger = logging.getLogger("trustguard.simulator")


class AttackSimulator:
    """
    Controlled Attack Simulator for local Zero-Trust verification.
    """
    def __init__(self, db_session: Optional[Session] = None):
        self._provided_db = db_session
        self._results: List[SimulationResult] = []

    def _get_or_create_session(self):
        """Yield an isolated in-memory or provided database session."""
        if self._provided_db is not None:
            return self._provided_db, None

        engine = create_engine(
            "sqlite:///:memory:",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(engine)
        session = Session(engine)
        return session, (session, engine)

    def run_all(self, db: Optional[Session] = None, client: Optional[Any] = None) -> List[SimulationResult]:
        """
        Execute all 10 attack scenarios sequentially.

        Returns:
            List[SimulationResult]: List of all scenario outcomes.
        """
        self._results = []
        for scenario_cls in ALL_SCENARIOS:
            result = self.run_scenario(scenario_cls.scenario_id, db=db, client=client)
            self._results.append(result)
        return self._results

    def run_scenario(
        self,
        scenario_id: int,
        db: Optional[Session] = None,
        client: Optional[Any] = None,
    ) -> SimulationResult:
        """
        Execute a single scenario by its ID (1-10).

        Args:
            scenario_id: Scenario ID integer (1-10).
            db: Optional database session.
            client: Optional test HTTP client.

        Returns:
            SimulationResult: Outcome record.
        """
        if scenario_id not in SCENARIOS_BY_ID:
            raise ValueError(f"Unknown scenario ID: {scenario_id}. Available IDs: {list(SCENARIOS_BY_ID.keys())}")

        scenario_cls = SCENARIOS_BY_ID[scenario_id]
        scenario_instance = scenario_cls()

        # Isolate database per scenario if no external session passed
        target_db = db or self._provided_db
        cleanup_context = None

        if target_db is None:
            target_db, cleanup_context = self._get_or_create_session()

        try:
            logger.info("Executing Scenario %d: %s", scenario_id, scenario_instance.scenario_name)
            result = scenario_instance.run(db=target_db, client=client)
            return result
        finally:
            if cleanup_context:
                session, engine = cleanup_context
                session.close()
                Base.metadata.drop_all(engine)
                engine.dispose()

    def get_summary(self) -> Dict[str, Any]:
        """Get summary statistics of the most recent simulation run."""
        total = len(self._results)
        passed = sum(1 for r in self._results if r.passed)
        return {
            "total_scenarios": total,
            "blocked_attacks": passed,
            "breached_attacks": total - passed,
            "success_rate_percent": (passed / total * 100) if total > 0 else 0.0,
            "all_denied": all(r.security_decision == "DENY" for r in self._results),
            "all_audited": all(r.audit_event_created for r in self._results),
        }
