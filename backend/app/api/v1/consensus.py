"""Multi-party quorum consensus API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.consensus import (
    ConsensusApproveRequest,
    ConsensusApproveResponse,
    PendingConsensusExamResponse,
    QuorumStatusResponse,
)
from app.services.consensus_service import ConsensusService

router = APIRouter(prefix="/consensus", tags=["Multi-Party Consensus"])

GUARDIAN_ROLES = ["ADMIN", "EXAM_SETTER", "GUARDIAN", "KEY_GUARDIAN"]


@router.get("/pending", response_model=List[PendingConsensusExamResponse])
async def list_pending_exams(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """List all exams awaiting multi-guardian authorization."""
    return await ConsensusService.list_pending_exams(db, current_user.id)


@router.post("/{exam_id}/approve", response_model=ConsensusApproveResponse)
async def submit_approval(
    exam_id: str,
    request_in: Optional[ConsensusApproveRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """Submit a Key Guardian authorization share/token for an exam.

    When threshold quorum (k of n) is met, exam status automatically updates to AUTHORIZED.
    """
    return await ConsensusService.submit_approval(db, exam_id, current_user.id, request_in)


@router.get("/{exam_id}/status", response_model=QuorumStatusResponse)
async def get_quorum_status(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get current quorum progress, per-guardian vote breakdown, and paper authorization state."""
    return await ConsensusService.get_quorum_status(db, exam_id)
