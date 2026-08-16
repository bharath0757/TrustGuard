"""Simulation API endpoints for controlled attack scenarios."""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.database import get_db
from app.schemas.simulation import (
    SimulationRequest,
    SimulationResponse,
    SimulationScenarioInfo,
)
from app.services.simulation_service import SimulationService

router = APIRouter(prefix="/simulation", tags=["Attack Simulator"])


@router.get(
    "/scenarios",
    response_model=List[SimulationScenarioInfo],
    summary="List available controlled attack scenarios",
)
async def list_simulation_scenarios() -> List[SimulationScenarioInfo]:
    """Return all available controlled attack scenarios for UI selection."""
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
) -> SimulationResponse:
    """
    Execute a controlled attack simulation on the backend:
    - Runs the real security evaluation
    - Records an audit event to the database
    - Returns the real security decision without fake state or hardcoded responses
    """
    return await SimulationService.run_simulation(
        db=db,
        scenario_id=payload.scenario_id,
        target_paper_id=payload.target_paper_id,
        actor_override=payload.actor_override,
    )
