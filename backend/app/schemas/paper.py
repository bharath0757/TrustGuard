"""Pydantic schemas for paper upload request and response."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class PaperUploadResponse(BaseModel):
    """Response after uploading/registering a paper."""
    id: str
    paper_name: str
    description: Optional[str] = None
    original_filename: str
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    encryption_status: str
    integrity_status: str
    fragment_status: str
    protection_status: str
    integrity_hash: Optional[str] = None
    total_fragments: Optional[int] = None
    status: Optional[str] = "DRAFT"
    staged_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class PaperListResponse(BaseModel):
    """Paper summary for listing."""
    id: str
    paper_name: str
    description: Optional[str] = None
    original_filename: str
    file_size: Optional[int] = None
    encryption_status: str
    integrity_status: str
    fragment_status: str
    protection_status: str
    status: Optional[str] = "DRAFT"
    staged_at: Optional[datetime] = None
    expires_at: Optional[datetime] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)
