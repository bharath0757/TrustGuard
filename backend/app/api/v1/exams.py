"""Exam management, student registration, and ephemeral paper staging API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.exam import (
    ExamCreate,
    ExamResponse,
    GuardianAssign,
    GuardianResponse,
    MultiStudentAssign,
    PayloadStageRequest,
    PayloadStageResponse,
    StagePaperRequest,
    StudentAssign,
    StudentResponse,
)
from app.schemas.student import GuardianStudentStatsResponse
from app.services.exam_service import ExamService
from app.services.student_service import StudentService

router = APIRouter(prefix="/exams", tags=["Exams"])

GUARDIAN_ROLES = ["ADMIN", "EXAM_SETTER", "GUARDIAN", "KEY_GUARDIAN"]


@router.post("/", response_model=ExamResponse, status_code=status.HTTP_201_CREATED)
async def create_exam(
    exam_in: ExamCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """Create a new examination metadata record (Guardian/Admin only)."""
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
    """Get exam details, assigned guardians, and registered students."""
    return await ExamService.get_exam_by_id(db, exam_id)


@router.post("/{exam_id}/guardians", response_model=GuardianResponse, status_code=status.HTTP_201_CREATED)
async def assign_guardian(
    exam_id: str,
    assign_in: GuardianAssign,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """Assign a key guardian (1 of n) to an exam."""
    return await ExamService.assign_guardian(db, exam_id, assign_in, current_user.id)


@router.post("/{exam_id}/students", response_model=List[StudentResponse], status_code=status.HTTP_201_CREATED)
async def register_students_to_exam(
    exam_id: str,
    payload: MultiStudentAssign,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """Register student candidates to an exam (Guardian/Admin only)."""
    return await ExamService.register_students(
        db=db,
        exam_id=exam_id,
        student_user_ids=payload.student_user_ids,
        actor_id=current_user.id,
    )


@router.post("/{exam_id}/stage-paper", status_code=status.HTTP_200_OK)
async def stage_exam_paper(
    exam_id: str,
    payload: StagePaperRequest = StagePaperRequest(),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """
    Stage the encrypted question paper into Ephemeral RAM for the exam:
    - Encrypts & shards ciphertext into RAM buffer
    - Generates Shamir secret shares for all assigned key guardians
    - Transitions exam state to AWAITING_APPROVAL
    """
    return await ExamService.stage_exam_paper(
        db=db,
        exam_id=exam_id,
        paper_id=payload.paper_id,
        ttl_seconds=payload.ttl_seconds,
        actor_id=current_user.id,
    )


@router.post("/{exam_id}/stage-payload", response_model=PayloadStageResponse)
async def stage_encrypted_payload(
    exam_id: str,
    payload_in: PayloadStageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(GUARDIAN_ROLES)),
):
    """Stage raw encrypted question paper chunks into Ephemeral RAM (Redis with TTL)."""
    return await ExamService.stage_encrypted_payload(db, exam_id, payload_in, current_user.id)


@router.get("/{exam_id}/paper")
async def get_exam_paper_access(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Retrieve question paper access for an exam:
    - ATTACKER: Strictly forbidden (403)
    - STUDENT: Requires 3/3 multi-guardian authorization (status AUTHORIZED/UNLOCKED/LIVE) AND student registration (403 if unauthorized)
    - STAFF: Allowed (Guardian/Admin/Center/Auditor)
    """
    from fastapi import HTTPException
    if current_user.role == "ATTACKER":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Attacker role cannot access examination papers",
        )

    exam = await ExamService.get_exam_by_id(db, exam_id)

    if current_user.role == "STUDENT":
        # Check student registration
        is_registered = any(s.student_id == current_user.id for s in exam.students)
        if not is_registered:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Student '{current_user.username}' is not registered for this examination",
            )

        # Check authorization requirement (3/3 approvals)
        if exam.status not in ["AUTHORIZED", "UNLOCKED", "LIVE", "COMPLETED"]:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access Denied: Examination paper is not yet authorized by guardians (Status: {exam.status}). Quorum (3/3) approval required.",
            )

    if not exam.paper:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No question paper is associated with this examination",
        )

    return {
        "exam_id": exam.id,
        "exam_title": exam.title,
        "course_code": exam.course_code,
        "paper_id": exam.paper.id,
        "paper_name": exam.paper.paper_name,
        "status": exam.paper.status,
        "authorized": exam.status in ["AUTHORIZED", "UNLOCKED", "LIVE", "COMPLETED"],
        "integrity_status": exam.paper.integrity_status,
        "integrity_hash": exam.paper.integrity_hash,
        "file_size": exam.paper.file_size,
        "released_at": exam.paper.released_at,
    }


@router.get("/{exam_id}/student-stats", response_model=GuardianStudentStatsResponse)
async def get_exam_student_stats(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get candidate participation and live writing/submitted counts for an exam:
    - Registered students (e.g., 2)
    - Currently writing (e.g., 2 -> 1 -> 0)
    - Submitted (e.g., 0 -> 1/2 -> 2/2)
    """
    if current_user.role not in ["ADMIN", "EXAM_SETTER", "KEY_GUARDIAN", "GUARDIAN", "EXAM_CENTER", "AUDITOR"]:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access Denied: Only examination staff can monitor candidate statistics",
        )
    return await StudentService.get_guardian_student_stats(db, exam_id)

