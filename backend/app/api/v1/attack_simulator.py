"""Phase 7: Attack Simulator API endpoints.

Provides controlled attack simulation capabilities restricted to ATTACKER and ADMIN roles.
Each endpoint triggers a real API-level attack against TrustGuard's own security layer.
"""

from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.attack_simulator import (
    AttackExecuteRequest,
    AttackHistoryResponse,
    AttackResult,
    AttackScenarioInfo,
)
from app.services.attack_simulator_service import AttackSimulatorService

router = APIRouter(prefix="/attack-sim", tags=["Attack Simulator"])

ATTACKER_ROLES = ["ATTACKER", "ADMIN"]


@router.get(
    "/scenarios",
    response_model=List[AttackScenarioInfo],
    summary="List available controlled attack types",
)
async def list_attack_scenarios(
    current_user: User = Depends(require_roles(ATTACKER_ROLES)),
) -> List[AttackScenarioInfo]:
    """Return all 6 available attack simulation types for authorized security testers."""
    return AttackSimulatorService.get_scenarios()


@router.post(
    "/{exam_id}/execute",
    response_model=AttackResult,
    status_code=status.HTTP_200_OK,
    summary="Execute a controlled attack against a live exam",
)
async def execute_attack(
    exam_id: str,
    payload: AttackExecuteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(ATTACKER_ROLES)),
) -> AttackResult:
    """
    Execute a specific controlled attack simulation against a real exam:
    - Calls TrustGuard's actual service layer with attacker credentials
    - Records the security decision as a real audit event
    - Broadcasts SECURITY_ALERT via WebSocket to guardian dashboards
    """
    return await AttackSimulatorService.execute_attack(
        db=db,
        exam_id=exam_id,
        attack_type=payload.attack_type,
        attacker=current_user,
    )


@router.get(
    "/{exam_id}/history",
    response_model=AttackHistoryResponse,
    summary="Get attack history for an exam",
)
async def get_attack_history(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(ATTACKER_ROLES)),
) -> AttackHistoryResponse:
    """Retrieve all attack simulation events for a specific exam."""
    attacks = await AttackSimulatorService.get_attack_history(db, exam_id)
    return AttackHistoryResponse(
        exam_id=exam_id,
        total_attacks=len(attacks),
        total_blocked=sum(1 for a in attacks if a.passed),
        attacks=attacks,
    )
