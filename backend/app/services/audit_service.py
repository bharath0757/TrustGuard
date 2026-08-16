"""Audit logging service."""

import json
from typing import List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from app.db.models import AuditEvent


class AuditService:

    @staticmethod
    async def log_event(
        db: AsyncSession,
        action: str,
        exam_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        details: Optional[dict] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            exam_id=exam_id,
            actor_id=actor_id,
            action=action,
            ip_address=ip_address,
            details_json=json.dumps(details) if details else None,
        )
        db.add(event)
        await db.commit()
        await db.refresh(event)
        return event

    @staticmethod
    async def get_events(
        db: AsyncSession,
        exam_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AuditEvent]:
        query = select(AuditEvent).order_by(AuditEvent.timestamp.desc()).limit(limit)
        if exam_id:
            query = query.where(AuditEvent.exam_id == exam_id)
        result = await db.execute(query)
        return list(result.scalars().all())
