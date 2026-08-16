"""Audit log Pydantic schemas."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AuditEventCreate(BaseModel):
    exam_id: Optional[str] = None
    action: str
    details_json: Optional[str] = None


class AuditEventResponse(BaseModel):
    id: str
    exam_id: Optional[str] = None
    actor_id: Optional[str] = None
    action: str
    ip_address: Optional[str] = None
    details_json: Optional[str] = None
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)
