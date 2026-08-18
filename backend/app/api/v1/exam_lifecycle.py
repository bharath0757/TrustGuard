"""Exam lifecycle API endpoints — start, end, security, events, report, timeline."""

from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.exam_lifecycle import (
    ExamCreateExtended,
    ExamEndRequest,
    ExamEndResponse,
    ExamEventResponse,
    ExamFullResponse,
    ExamSecurityReport,
    ExamSecurityStatus,
    ExamStartResponse,
    GuardianRealTimeDashboardState,
    TimelineEvent,
)
from app.services.exam_lifecycle_service import ExamLifecycleService
from app.services.exam_service import ExamService


router = APIRouter(prefix="/exam-lifecycle", tags=["Exam Lifecycle"])


@router.post(
    "/{exam_id}/start",
    response_model=ExamStartResponse,
    summary="Start an exam — transitions to LIVE",
)
async def start_exam(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER", "EXAM_CENTER"])),
):
    """
    Start an exam:
    1. Validates exam status, paper protection, integrity, quorum
    2. Creates exam session
    3. Sets exam status to LIVE with server-authoritative timestamp
    4. Initializes live security monitoring state
    """
    return await ExamLifecycleService.start_exam(db, exam_id, current_user.id)


@router.post(
    "/{exam_id}/end",
    response_model=ExamEndResponse,
    summary="End an exam — transitions to COMPLETED",
)
async def end_exam(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER", "EXAM_CENTER"])),
):
    """
    End a running exam:
    1. Validates current state (must be LIVE)
    2. Closes active sessions and expires access
    3. Sets status to COMPLETED with server timestamp
    4. Purges ephemeral data to prevent replay
    """
    return await ExamLifecycleService.end_exam(db, exam_id, current_user.id)


@router.get(
    "/{exam_id}/security",
    response_model=ExamSecurityStatus,
    summary="Get aggregated exam security status",
)
async def get_security_status(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns aggregated security status including:
    - Paper integrity, encryption, protection
    - Quorum status
    - Live metrics (events, unauthorized attempts, blocks)
    - Server time for timer synchronization
    """
    return await ExamLifecycleService.get_security_status(db, exam_id)


@router.get(
    "/{exam_id}/dashboard-state",
    response_model=GuardianRealTimeDashboardState,
    summary="Get aggregated real-time guardian examination monitoring dashboard state",
)
async def get_dashboard_state(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns complete real-time dashboard state for guardians:
    - Exam status, server-authoritative timer, and duration
    - Paper protection status, encryption, and cryptographic integrity hash
    - Guardian consensus quorum progress and list of assigned guardians
    - Live candidate counts (registered, writing, submitted, expired) and student roster
    - Security monitor metrics (attempts, blocked attacks, integrity violations)
    - Chronological recent audit events feed
    """
    return await ExamLifecycleService.get_full_dashboard_state(db, exam_id)



@router.get(
    "/{exam_id}/events",
    response_model=List[ExamEventResponse],
    summary="Get exam security events (supports polling)",
)
async def get_events(
    exam_id: str,
    since: Optional[str] = Query(default=None, description="ISO timestamp for incremental polling"),
    limit: int = Query(default=200, ge=1, le=1000),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Get exam security events. Supports incremental polling via `since` parameter.
    Returns events newer than the given timestamp for efficient live updates.
    """
    since_dt = None
    if since:
        try:
            since_dt = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            pass
    return await ExamLifecycleService.get_events(db, exam_id, since=since_dt, limit=limit)


@router.get(
    "/{exam_id}/report",
    response_model=ExamSecurityReport,
    summary="Generate final security report",
)
async def get_report(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "EXAM_SETTER", "KEY_GUARDIAN", "GUARDIAN", "EXAM_CENTER", "AUDITOR"])),
):
    """
    Generate a final security report based on actual stored events.
    Includes exam info, security summary, timeline, and final status.
    """
    return await ExamLifecycleService.generate_report(db, exam_id)


@router.get(
    "/{exam_id}/timeline",
    response_model=List[TimelineEvent],
    summary="Get exam security timeline",
)
async def get_timeline(
    exam_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Returns an ordered timeline of all security events for the exam.
    """
    report = await ExamLifecycleService.generate_report(db, exam_id)
    return report.get("timeline", [])
