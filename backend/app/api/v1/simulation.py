"""Simulation API endpoints for controlled attack scenarios."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_optional_current_user
from app.db.database import get_db
from app.db.models import User
from app.schemas.simulation import (
    SimulationRequest,
    SimulationResponse,
    SimulationScenarioInfo,
)
from app.services.simulation_service import SimulationService

router = APIRouter(prefix="/simulation", tags=["Attack Simulator"])


async def require_attacker_or_open_simulation(
    current_user: Optional[User] = Depends(get_optional_current_user),
) -> Optional[User]:
    if current_user is not None:
        if current_user.role not in {"ATTACKER", "ADMIN", "EXAM_SETTER"}:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Operation not permitted for role '{current_user.role}'. Required: ATTACKER or ADMIN",
            )
    return current_user


@router.get(
    "/scenarios",
    response_model=List[SimulationScenarioInfo],
    summary="List available controlled attack scenarios",
)
async def list_simulation_scenarios(
    current_user: Optional[User] = Depends(require_attacker_or_open_simulation),
) -> List[SimulationScenarioInfo]:
    """Return all available controlled attack scenarios for authorized security testers."""
    return SimulationService.get_available_scenarios()


@router.post(
    "/run",
    response_model=SimulationResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute a controlled attack simulation",
)
async def run_simulation(
    payload: SimulationRequest,
    db: AsyncSession = Depends(get_db),
    current_user: Optional[User] = Depends(require_attacker_or_open_simulation),
) -> SimulationResponse:
    """
    Execute a controlled attack simulation on the backend:
    - Enforces ATTACKER / ADMIN authorization for authenticated callers
    - Runs the real security evaluation
    - Records an audit event to the database
    - Returns the real security decision without fake state or hardcoded responses
    """
    actor = payload.actor_override
    if not actor and current_user:
        actor = current_user.username

    return await SimulationService.run_simulation(
        db=db,
        scenario_id=payload.scenario_id,
        target_paper_id=payload.target_paper_id,
        actor_override=actor,
        exam_id=payload.exam_id,
    )
