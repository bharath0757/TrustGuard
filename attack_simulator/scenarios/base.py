"""
TrustGuard Attack Simulator — Base Scenario Interface.

SAFE LOCAL SIMULATION ONLY.
Abstract base class for all 10 attack simulation scenarios.
"""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import uuid

from sqlalchemy.orm import Session

from database.models.audit import AuditLog, ThreatEvent
from .models import SimulationResult

logger = logging.getLogger("trustguard.simulator")


class BaseAttackScenario(ABC):
    """
    Abstract Base Class for controlled attack scenarios.
    """
    scenario_id: int = 0
    scenario_name: str = "Base Scenario"
    description: str = "Base description"

    @abstractmethod
    def run(self, db: Session, client: Optional[Any] = None) -> SimulationResult:
        """
        Execute the controlled simulation scenario against the given database session.

        Args:
            db: SQLAlchemy database session.
            client: Optional HTTP client for REST API scenarios.

        Returns:
            SimulationResult: Complete structured execution record.
        """
        raise NotImplementedError

    def _find_recent_audit_events(
        self,
        db: Session,
        target_id: Optional[uuid.UUID] = None,
        actor_id: Optional[uuid.UUID] = None,
        actions: Optional[List[str]] = None,
    ) -> List[AuditLog]:
        """Helper to find audit log entries created during this scenario."""
        query = db.query(AuditLog)
        if target_id:
            query = query.filter(AuditLog.target_id == target_id)
        if actor_id:
            query = query.filter(AuditLog.actor_id == actor_id)
        if actions:
            query = query.filter(AuditLog.action.in_(actions))
        return query.all()

    def _find_recent_threat_events(
        self,
        db: Session,
        target_id: Optional[uuid.UUID] = None,
        actor_id: Optional[uuid.UUID] = None,
    ) -> List[ThreatEvent]:
        """Helper to find threat incident rows created during this scenario."""
        query = db.query(ThreatEvent)
        if target_id:
            query = query.filter(ThreatEvent.target_id == target_id)
        if actor_id:
            query = query.filter(ThreatEvent.actor_id == actor_id)
        return query.all()
