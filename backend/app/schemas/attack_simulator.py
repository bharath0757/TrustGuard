"""Schemas for Phase 7 Controlled Attack Simulator.

Each AttackResult represents a real attempted API call against TrustGuard's
protected endpoints, with the backend's actual security decision.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AttackScenarioInfo(BaseModel):
    """Describes one available attack simulation type."""
    id: str = Field(..., description="Attack type identifier, e.g. UNAUTHORIZED_PAPER_ACCESS")
    name: str
    description: str
    target_endpoint: str = Field(..., description="The API endpoint this attack targets")
    expected_http_status: int = Field(..., description="Expected HTTP status code (403, 400, etc.)")
    risk_severity: str = Field(..., description="CRITICAL, HIGH, MEDIUM, LOW")
    attack_vector: str = Field(..., description="Brief description of the attack vector")


class AttackExecuteRequest(BaseModel):
    """Request to execute a specific attack against a live exam."""
    attack_type: str = Field(..., description="One of the 6 attack type IDs")


class AttackResult(BaseModel):
    """Result of a single controlled attack attempt."""
    id: str = Field(..., description="Unique ID for this attack result")
    exam_id: str
    actor: str = Field(..., description="Attacker username")
    attack_type: str = Field(..., description="e.g. UNAUTHORIZED_PAPER_ACCESS")
    attack_name: str = Field(..., description="Human-readable attack name")
    target: str = Field(..., description="Target API endpoint path")
    result: str = Field(..., description="BLOCKED or DENIED")
    http_status: int = Field(..., description="Actual HTTP status code returned")
    reason: str = Field(..., description="Why the attack was blocked")
    metadata: Dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(..., description="ISO format timestamp")
    audit_event_id: str = Field(..., description="Link to AuditEvent record in database")
    security_decision: str = Field(default="DENY", description="Always DENY for attacks")
    passed: bool = Field(default=True, description="True if security held (attack was blocked)")


class AttackHistoryResponse(BaseModel):
    """History of attacks against a specific exam."""
    exam_id: str
    total_attacks: int
    total_blocked: int
    attacks: List[AttackResult]
