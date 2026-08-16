"""Exam management and ephemeral staging API endpoints."""

from typing import List
from fastapi import APIRouter, Depends, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.exam import (
    ExamCreate,
    ExamResponse,
    GuardianAssign,
    GuardianResponse,
    PayloadStageRequest,
    PayloadStageResponse,
)
from app.services.exam_service import ExamService

router = APIRouter(prefix="/exams", tags=["Exams"])


@router.post("/", response_model=ExamResponse, status_code=status.HTTP_201_CREATED)
async def create_exam(
    exam_in: ExamCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER"])),
):
    """Create a new examination metadata record (Draft state)."""
    return await ExamService.create_exam(db, exam_in, current_user.id)


@router.get("/", response_model=List[ExamResponse])
async def list_exams(
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all exams."""
    return await ExamService.list_exams(db, skip=skip, limit=limit)


@router.get("/{exam_id}", response_model=ExamResponse)
async def get_exam(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Get exam details and assigned guardians."""
    return await ExamService.get_exam_by_id(db, exam_id)


@router.post("/{exam_id}/guardians", response_model=GuardianResponse, status_code=status.HTTP_201_CREATED)
async def assign_guardian(
    exam_id: str,
    assign_in: GuardianAssign,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER"])),
):
    """Assign a key guardian (1 of n) to an exam."""
    return await ExamService.assign_guardian(db, exam_id, assign_in, current_user.id)


@router.post("/{exam_id}/stage-payload", response_model=PayloadStageResponse)
async def stage_encrypted_payload(
    exam_id: str,
    payload_in: PayloadStageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER"])),
):
    """Stage encrypted question paper chunks into Ephemeral RAM (Redis with TTL).

    Stores ONLY the SHA-256 integrity hash in PostgreSQL.
    Stores raw encrypted chunks and split key shares exclusively in RAM.
    """
    return await ExamService.stage_encrypted_payload(db, exam_id, payload_in, current_user.id)
