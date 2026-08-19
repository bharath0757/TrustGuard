"""Consensus and Quorum approval Pydantic schemas."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ConsensusApproveRequest(BaseModel):
    share_token: Optional[str] = Field(None, description="Cryptographic guardian share token or signature")
    comments: Optional[str] = Field(None, description="Optional guardian approval comments")


class ConsensusApproveResponse(BaseModel):
    exam_id: str
    guardian_id: str
    approved_at: datetime
    current_quorum_count: int
    required_quorum: int
    quorum_reached: bool
    new_exam_status: str
    message: Optional[str] = None


class GuardianApprovalDetail(BaseModel):
    guardian_id: str
    username: Optional[str] = None
    full_name: Optional[str] = None
    role: Optional[str] = None
    status: str = "WAITING"  # APPROVED or WAITING
    approved_at: Optional[datetime] = None

    model_config = ConfigDict(from_attributes=True)


class QuorumStatusResponse(BaseModel):
    exam_id: str
    exam_title: Optional[str] = None
    paper_id: Optional[str] = None
    paper_name: Optional[str] = None
    status: str
    required_quorum: int
    total_guardians: int
    current_approvals_count: int
    quorum_reached: bool
    approved_guardians: List[str]
    guardians: List[GuardianApprovalDetail] = []


class PendingConsensusExamResponse(BaseModel):
    exam_id: str
    exam_title: str
    course_code: str
    paper_id: Optional[str] = None
    paper_name: Optional[str] = None
    status: str
    required_quorum: int
    total_guardians: int
    current_approvals_count: int
    quorum_reached: bool
    has_approved: bool
    created_at: datetime
