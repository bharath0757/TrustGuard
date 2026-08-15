"""Consensus and Quorum approval Pydantic schemas."""

from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ConsensusApproveRequest(BaseModel):
    share_token: str = Field(..., min_length=5, description="Cryptographic guardian share token")


class ConsensusApproveResponse(BaseModel):
    exam_id: str
    guardian_id: str
    approved_at: datetime
    current_quorum_count: int
    required_quorum: int
    quorum_reached: bool
    new_exam_status: str


class GuardianApprovalDetail(BaseModel):
    guardian_id: str
    approved_at: datetime

    model_config = ConfigDict(from_attributes=True)


class QuorumStatusResponse(BaseModel):
    exam_id: str
    status: str
    required_quorum: int
    total_guardians: int
    current_approvals_count: int
    quorum_reached: bool
    approved_guardians: List[str]
