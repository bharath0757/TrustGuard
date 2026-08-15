"""Audit event logging and query API endpoints."""

from typing import List, Optional
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.api.deps import get_current_user, require_roles
from app.db.database import get_db
from app.db.models import User
from app.schemas.audit import AuditEventCreate, AuditEventResponse
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["Audit Trails"])


@router.get("/events", response_model=List[AuditEventResponse])
async def list_audit_events(
    exam_id: Optional[str] = None,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_roles(["ADMIN", "AUDITOR"])),
):
    """Retrieve immutable audit event logs."""
    return await AuditService.get_events(db, exam_id=exam_id, limit=limit)


@router.post("/events", response_model=AuditEventResponse, status_code=status.HTTP_201_CREATED)
async def log_external_event(
    event_in: AuditEventCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ingest external client or exam center receipt audit events."""
    client_ip = request.client.host if request.client else "unknown"
    return await AuditService.log_event(
        db=db,
        action=event_in.action,
        exam_id=event_in.exam_id,
        actor_id=current_user.id,
        ip_address=client_ip,
        details={"details_json": event_in.details_json},
    )
