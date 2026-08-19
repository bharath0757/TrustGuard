"""Blockchain Ledger API Endpoints for TrustGuard."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.db.database import get_db
from app.db.models import User
from app.schemas.blockchain import (
    BlockchainRecordRequest,
    BlockchainRecordResponse,
    BlockchainVerifyResponse,
)
from app.services.blockchain_service import BlockchainService

router = APIRouter(prefix="/blockchain", tags=["blockchain"])


@router.post("/record", response_model=BlockchainRecordResponse, status_code=status.HTTP_201_CREATED)
async def record_blockchain_hash(
    body: BlockchainRecordRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Record an exam paper SHA-256 payload integrity hash to the immutable ledger."""
    try:
        block = await BlockchainService.record_payload_hash(
            db=db,
            exam_id=body.exam_id,
            payload_hash=body.payload_hash,
            paper_id=body.paper_id,
            recorded_by=current_user.id if current_user else None,
        )
        return block
    except ValueError as err:
        raise HTTPException(status_code=400, detail=str(err))
    except Exception as err:
        raise HTTPException(status_code=500, detail=f"Failed to record block: {str(err)}")


@router.get("/verify/{exam_id}", response_model=BlockchainVerifyResponse)
async def verify_exam_hash(
    exam_id: str,
    current_hash: Optional[str] = Query(None, description="Optional payload hash to verify against ledger"),
    db: AsyncSession = Depends(get_db),
):
    """Verify live question paper payload hash against recorded immutable ledger block."""
    result = await BlockchainService.verify_payload_hash(
        db=db,
        exam_id=exam_id,
        current_payload_hash=current_hash,
    )
    return result


@router.get("/chain")
async def audit_ledger_chain(
    db: AsyncSession = Depends(get_db),
):
    """Audit the overall cryptographic hash-chain ledger for block tamper detection."""
    return await BlockchainService.verify_ledger_chain_integrity(db)
