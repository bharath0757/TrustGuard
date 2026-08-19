"""Student Examination Portal API endpoints with strict RBAC enforcement."""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.student import (
    SaveAnswersRequest,
    StudentExamSummary,
    StudentSessionDetail,
    StudentSubmissionResult,
    SubmitExamRequest,
)
from app.services.student_service import StudentService

router = APIRouter(prefix="/student", tags=["Student Portal"])


class StudentStatusResponse(BaseModel):
    student_id: str
    student_username: str
    enrolled_role: str
    active_sessions_count: int
    server_time: datetime


@router.get(
    "/exams",
    response_model=List[StudentExamSummary],
    summary="List available/authorized exams for the authenticated student",
)
async def list_student_exams(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """
    Student view of examinations:
    - Lists all exams the student is registered for
    - Reflects live student session status (NOT_STARTED, IN_PROGRESS, SUBMITTED, EXPIRED)
    """
    return await StudentService.get_student_exams(db, current_user.id)


@router.post(
    "/exams/{exam_id}/join",
    response_model=StudentSessionDetail,
    summary="Join an authorized examination session",
)
async def join_exam(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """
    Student joins an examination:
    - Verifies student is registered for this exam (403 if unassigned)
    - Verifies exam is in authorized/released state (403/400 if draft/staged/unauthorized)
    - Initializes or resumes server-authoritative timer
    - Returns questions (WITHOUT correct answers!)
    """
    return await StudentService.join_or_start_session(db, exam_id, current_user)


@router.get(
    "/exams/{exam_id}/session",
    response_model=StudentSessionDetail,
    summary="Get current candidate session state and timer info",
)
async def get_exam_session(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """
    Get current session status:
    - Returns server-authoritative timer and remaining seconds
    - Auto-expires if time limit is reached
    - Returns saved answers and public questions
    """
    return await StudentService.get_session_state(db, exam_id, current_user)


@router.get(
    "/exams/{exam_id}/questions",
    response_model=StudentSessionDetail,
    summary="View examination questions for an active session (alias)",
)
async def get_exam_questions(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """Retrieve questions for student examination."""
    return await StudentService.get_session_state(db, exam_id, current_user)


@router.post(
    "/sessions/{session_id}/answers",
    response_model=StudentSessionDetail,
    summary="Save intermediate candidate exam answers",
)
async def save_answers(
    session_id: str,
    payload: SaveAnswersRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """
    Save student answers:
    - Enforces session ownership (student cannot touch another student's session)
    - Enforces server-authoritative timer (rejects if expired)
    - Rejects if already submitted
    """
    return await StudentService.save_answers(db, session_id, current_user, payload.answers)


@router.post(
    "/sessions/{session_id}/submit",
    response_model=StudentSubmissionResult,
    summary="Submit and finalize candidate examination",
)
async def submit_exam(
    session_id: str,
    payload: Optional[SubmitExamRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """
    Finalize and submit candidate examination:
    - Enforces session ownership
    - Enforces server timer (rejects if expired)
    - Idempotent duplicate submission handling
    - Computes score securely server-side
    - Transitions session to SUBMITTED
    """
    answers = payload.answers if payload else None
    return await StudentService.submit_exam(db, session_id, current_user, answers)


@router.get(
    "/status",
    response_model=StudentStatusResponse,
    summary="Get student portal status and profile context",
)
async def get_student_status(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["STUDENT"])),
):
    """Return student portal connectivity status."""
    now = datetime.now(timezone.utc)
    exams = await StudentService.get_student_exams(db, current_user.id)
    active_count = sum(1 for e in exams if e.session_status == "IN_PROGRESS")

    return StudentStatusResponse(
        student_id=current_user.id,
        student_username=current_user.username,
        enrolled_role=current_user.role,
        active_sessions_count=active_count,
        server_time=now,
    )
