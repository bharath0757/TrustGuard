"""Pydantic schemas for blockchain ledger recording and verification APIs."""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class BlockchainRecordRequest(BaseModel):
    exam_id: str
    payload_hash: str
    paper_id: Optional[str] = None


class BlockchainRecordResponse(BaseModel):
    index: int
    block_hash: str
    prev_block_hash: str
    exam_id: str
    paper_id: Optional[str] = None
    payload_hash: str
    timestamp: datetime

    model_config = ConfigDict(from_attributes=True)


class BlockchainVerifyResponse(BaseModel):
    status: str
    verified: bool
    exam_id: str
    recorded_hash: Optional[str] = None
    current_hash: Optional[str] = None
    block_index: Optional[int] = None
    block_hash: Optional[str] = None
    prev_block_hash: Optional[str] = None
    timestamp: Optional[str] = None
    chain_valid: Optional[bool] = None
    message: str

    model_config = ConfigDict(from_attributes=True)
