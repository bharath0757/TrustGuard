"""Ephemeral Question-Paper Distribution API endpoints."""

from fastapi import APIRouter, Depends, Header
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.distribution import StreamPurgeResponse
from app.services.distribution_service import DistributionService

router = APIRouter(prefix="/distribution", tags=["Ephemeral Distribution"])


@router.get("/{exam_id}/stream")
async def stream_question_paper(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["EXAM_CENTER", "ADMIN", "KEY_GUARDIAN", "EXAM_SETTER"])),
):
    """Stream encrypted question paper payload directly from Ephemeral RAM (Redis/Memory).

    Enforces:
    1. Multi-party Quorum Approval (Status must be UNLOCKED or AUTHORIZED).
    2. Time-Lock Window (Current time must be within scheduled start/end window).
    3. Ephemeral RAM transport: Zero persistent disk storage.
    """
    stream_gen = await DistributionService.get_payload_stream_generator(
        db, exam_id, center_id=current_user.id
    )
    return StreamingResponse(
        stream_gen,
        media_type="application/octet-stream",
        headers={
            "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
            "Pragma": "no-cache",
            "X-Content-Type-Options": "nosniff",
        },
    )


@router.post("/{exam_id}/purge", response_model=StreamPurgeResponse)
async def purge_ephemeral_buffers(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER", "KEY_GUARDIAN", "EXAM_CENTER"])),
):
    """Force immediate purge of ephemeral RAM payload buffers and key shares for an exam."""
    return await DistributionService.purge_ephemeral_data(db, exam_id, current_user.id)
