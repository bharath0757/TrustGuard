"""
TrustGuard Attack Simulator — Scenario Models.

Defines the structured data models for recording attack simulation execution results.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


@dataclass
class SimulationResult:
    """
    Structured outcome of a controlled attack simulation scenario.

    Required fields as specified by TrustGuard specification:
    - scenario_name
    - timestamp
    - simulated_actor
    - target_resource
    - action_attempted
    - expected_result
    - actual_result
    - security_decision (DENY / ALLOW)
    - audit_event_created (bool)
    """
    scenario_id: int
    scenario_name: str
    timestamp: str
    simulated_actor: str
    target_resource: str
    action_attempted: str
    expected_result: str
    actual_result: str
    security_decision: str  # "DENY" or "ALLOW"
    audit_event_created: bool
    threat_event_created: bool = False
    passed: bool = True
    audit_actions_found: List[str] = field(default_factory=list)
    threat_types_found: List[str] = field(default_factory=list)
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert result to dictionary representation."""
        return {
            "scenario_id": self.scenario_id,
            "scenario_name": self.scenario_name,
            "timestamp": self.timestamp,
            "simulated_actor": self.simulated_actor,
            "target_resource": self.target_resource,
            "action_attempted": self.action_attempted,
            "expected_result": self.expected_result,
            "actual_result": self.actual_result,
            "security_decision": self.security_decision,
            "audit_event_created": self.audit_event_created,
            "threat_event_created": self.threat_event_created,
            "passed": self.passed,
            "audit_actions_found": self.audit_actions_found,
            "threat_types_found": self.threat_types_found,
            "details": self.details,
        }
