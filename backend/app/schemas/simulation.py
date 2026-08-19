"""Schemas for controlled attack simulation requests and results."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SimulationScenarioInfo(BaseModel):
    id: str
    scenario_id: int
    name: str
    description: str
    simulated_actor: str
    expected_decision: str
    risk_severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    default_target: str
    mechanism: str


class SimulationRequest(BaseModel):
    scenario_id: str = Field(..., description="Scenario identifier, e.g. UNAUTHORIZED_ACCESS, INSIDER_ATTEMPT, etc.")
    target_paper_id: Optional[str] = Field(default="JEE-MOCK-001", description="Target examination paper identifier")
    actor_override: Optional[str] = None
    exam_id: Optional[str] = None


class SimulationResponse(BaseModel):
    scenario_id: str
    scenario_name: str
    target_paper: str
    simulated_actor: str
    expected_decision: str
    actual_decision: str  # BLOCKED, ALLOWED, FAILED INTEGRITY, INVALID AUTHORIZATION
    security_decision: str  # DENY, ALLOW
    risk_severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    timestamp: str
    audit_result: str
    audit_event_id: str
    status_category: str  # BLOCKED | ALLOWED | FAILED INTEGRITY | INVALID AUTHORIZATION
    passed: bool
    details: Dict[str, Any] = Field(default_factory=dict)
