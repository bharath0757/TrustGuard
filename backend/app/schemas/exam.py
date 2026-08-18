"""Exam lifecycle Pydantic schemas."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ExamCreate(BaseModel):
    title: str = Field(..., min_length=3, max_length=150)
    course_code: str = Field(..., min_length=2, max_length=50)
    description: Optional[str] = None
    paper_id: Optional[str] = Field(default=None, description="ID of the protected uploaded paper")
    scheduled_start: datetime
    scheduled_end: datetime
    duration_minutes: int = Field(60, ge=1, le=1440)
    required_quorum: int = Field(2, ge=1, description="Threshold k approvals required")
    total_guardians: int = Field(3, ge=1, description="Total n key guardians assigned")


class GuardianAssign(BaseModel):
    guardian_user_id: str
    public_key_fingerprint: str = Field(..., min_length=8, max_length=64)


class GuardianResponse(BaseModel):
    id: str
    guardian_id: str
    public_key_fingerprint: str
    assigned_at: datetime

    model_config = ConfigDict(from_attributes=True)


class StudentAssign(BaseModel):
    student_user_id: str
    registration_status: Optional[str] = "REGISTERED"


class MultiStudentAssign(BaseModel):
    student_user_ids: List[str] = Field(..., min_length=1, description="List of student user IDs to register")


class StudentResponse(BaseModel):
    id: str
    student_id: str
    registration_status: str
    registered_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ExamResponse(BaseModel):
    id: str
    title: str
    course_code: str
    description: Optional[str] = None
    paper_id: Optional[str] = None
    status: str
    scheduled_start: datetime
    scheduled_end: datetime
    duration_minutes: int = 60
    required_quorum: int
    total_guardians: int
    encrypted_payload_hash: Optional[str] = None
    started_at: Optional[datetime] = None
    ended_at: Optional[datetime] = None
    created_by: str
    created_at: datetime
    updated_at: datetime
    guardians: List[GuardianResponse] = []
    students: List[StudentResponse] = []

    model_config = ConfigDict(from_attributes=True)


class PayloadStageRequest(BaseModel):
    encrypted_chunks: List[str] = Field(..., min_length=1, description="Base64 encoded encrypted chunks")
    ttl_seconds: int = Field(1800, ge=60, le=86400)


class PayloadStageResponse(BaseModel):
    exam_id: str
    status: str
    chunks_staged: int
    encrypted_payload_hash: str
    ttl_seconds: int


class StagePaperRequest(BaseModel):
    paper_id: Optional[str] = Field(default=None, description="Paper ID to stage (defaults to exam's linked paper)")
    ttl_seconds: int = Field(1800, ge=60, le=86400)
