"""Blockchain Verification & Immutable Ledger Service for TrustGuard.

Provides a cryptographically linked local hash-chain ledger for recording and verifying
question paper SHA-256 integrity hashes, detecting payload tampering, and verifying
chain integrity.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.models import BlockchainBlock, Exam, UploadedPaper
from app.services.audit_service import AuditService


class BlockchainService:
    """Immutable Hash-Chain Ledger Service for Exam Integrity."""

    @staticmethod
    def _format_timestamp(dt: datetime) -> str:
        """Format timestamp consistently for block hashing across database adapters."""
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.strftime("%Y-%m-%dT%H:%M:%S.%f")

    @staticmethod
    def _compute_block_hash(
        index: int,
        timestamp_str: str,
        exam_id: str,
        paper_id: Optional[str],
        payload_hash: str,
        prev_block_hash: str,
    ) -> str:
        """Compute deterministic SHA-256 block hash for ledger chain linkage."""
        block_content = f"{index}:{timestamp_str}:{exam_id}:{paper_id or ''}:{payload_hash}:{prev_block_hash}"
        return hashlib.sha256(block_content.encode("utf-8")).hexdigest()

    @staticmethod
    async def record_payload_hash(
        db: AsyncSession,
        exam_id: str,
        payload_hash: str,
        paper_id: Optional[str] = None,
        recorded_by: Optional[str] = None,
    ) -> BlockchainBlock:
        """Record a question paper SHA-256 payload integrity hash to the immutable ledger.

        Generates a new linked ledger block referencing the previous block hash.
        """
        if not payload_hash:
            raise ValueError("Payload hash must be provided to record to blockchain ledger")

        # Fetch latest block for prev_block_hash chaining
        stmt = select(BlockchainBlock).order_by(BlockchainBlock.index.desc()).limit(1)
        result = await db.execute(stmt)
        latest_block = result.scalar_one_or_none()

        if latest_block:
            next_index = latest_block.index + 1
            prev_block_hash = latest_block.block_hash
        else:
            next_index = 1
            prev_block_hash = "0" * 64  # Genesis block previous hash

        now_utc = datetime.now(timezone.utc)
        timestamp_str = BlockchainService._format_timestamp(now_utc)

        block_hash = BlockchainService._compute_block_hash(
            index=next_index,
            timestamp_str=timestamp_str,
            exam_id=exam_id,
            paper_id=paper_id,
            payload_hash=payload_hash,
            prev_block_hash=prev_block_hash,
        )

        new_block = BlockchainBlock(
            index=next_index,
            block_hash=block_hash,
            prev_block_hash=prev_block_hash,
            timestamp=now_utc,
            exam_id=exam_id,
            paper_id=paper_id,
            payload_hash=payload_hash,
            recorded_by=recorded_by,
        )

        db.add(new_block)
        await db.commit()
        await db.refresh(new_block)

        # Audit event
        await AuditService.log_event(
            db=db,
            action="BLOCKCHAIN_HASH_RECORDED",
            exam_id=exam_id,
            actor_id=recorded_by,
            details={
                "block_index": new_block.index,
                "block_hash": new_block.block_hash,
                "prev_block_hash": new_block.prev_block_hash,
                "payload_hash": payload_hash,
            },
        )

        return new_block

    @staticmethod
    async def get_recorded_block(db: AsyncSession, exam_id: str) -> Optional[BlockchainBlock]:
        """Retrieve the latest recorded ledger block for an exam."""
        stmt = select(BlockchainBlock).where(BlockchainBlock.exam_id == exam_id).order_by(BlockchainBlock.index.desc()).limit(1)
        result = await db.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def verify_ledger_chain_integrity(db: AsyncSession) -> Dict[str, Any]:
        """Audit entire blockchain ledger for chain linkage and block hash tampering."""
        stmt = select(BlockchainBlock).order_by(BlockchainBlock.index.asc())
        result = await db.execute(stmt)
        blocks: List[BlockchainBlock] = list(result.scalars().all())

        if not blocks:
            return {"total_blocks": 0, "chain_valid": True, "tampered_blocks": []}

        tampered_blocks = []
        expected_prev = "0" * 64

        for block in blocks:
            if block.prev_block_hash != expected_prev:
                tampered_blocks.append(
                    {
                        "index": block.index,
                        "block_hash": block.block_hash,
                        "expected_prev_hash": expected_prev,
                        "actual_prev_hash": block.prev_block_hash,
                        "reason": "Previous block hash mismatch",
                    }
                )

            # Re-compute block hash
            timestamp_str = BlockchainService._format_timestamp(block.timestamp)
            recomputed = BlockchainService._compute_block_hash(
                index=block.index,
                timestamp_str=timestamp_str,
                exam_id=block.exam_id,
                paper_id=block.paper_id,
                payload_hash=block.payload_hash,
                prev_block_hash=block.prev_block_hash,
            )

            if recomputed != block.block_hash:
                tampered_blocks.append(
                    {
                        "index": block.index,
                        "block_hash": block.block_hash,
                        "recomputed_hash": recomputed,
                        "reason": "Block content hash corrupted/tampered",
                    }
                )

            expected_prev = block.block_hash

        chain_valid = len(tampered_blocks) == 0
        return {
            "total_blocks": len(blocks),
            "chain_valid": chain_valid,
            "tampered_blocks": tampered_blocks,
        }

    @staticmethod
    async def verify_payload_hash(
        db: AsyncSession,
        exam_id: str,
        current_payload_hash: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Verify current question paper payload hash against immutable ledger record.

        Detects TAMPER_DETECTED when live hash differs from recorded blockchain hash.
        """
        # Fetch recorded ledger block
        recorded_block = await BlockchainService.get_recorded_block(db, exam_id)
        if not recorded_block:
            return {
                "status": "MISSING_RECORD",
                "verified": False,
                "exam_id": exam_id,
                "message": f"No blockchain ledger record found for exam {exam_id}",
            }

        # If current_payload_hash is not passed directly, look up current exam paper hash
        if not current_payload_hash:
            exam_stmt = select(Exam).where(Exam.id == exam_id)
            exam_res = await db.execute(exam_stmt)
            exam = exam_res.scalar_one_or_none()

            if exam and exam.encrypted_payload_hash:
                current_payload_hash = exam.encrypted_payload_hash
            elif exam and exam.paper:
                current_payload_hash = exam.paper.integrity_hash or exam.paper.file_hash

        # Audit entire ledger chain
        chain_audit = await BlockchainService.verify_ledger_chain_integrity(db)
        chain_valid = chain_audit["chain_valid"]

        hashes_match = (
            current_payload_hash is not None
            and current_payload_hash.lower() == recorded_block.payload_hash.lower()
        )

        is_verified = hashes_match and chain_valid
        status = "VERIFIED" if is_verified else "TAMPER_DETECTED"

        msg = (
            "Payload integrity successfully verified against immutable blockchain ledger"
            if is_verified
            else "CRITICAL INTEGRITY FAILURE: Current payload hash does not match immutable ledger block!"
        )

        # Log audit event for verification attempt
        await AuditService.log_event(
            db=db,
            action="BLOCKCHAIN_VERIFICATION_CHECK",
            exam_id=exam_id,
            details={
                "status": status,
                "verified": is_verified,
                "recorded_hash": recorded_block.payload_hash,
                "current_hash": current_payload_hash,
                "block_index": recorded_block.index,
                "block_hash": recorded_block.block_hash,
                "chain_valid": chain_valid,
            },
        )

        return {
            "status": status,
            "verified": is_verified,
            "exam_id": exam_id,
            "recorded_hash": recorded_block.payload_hash,
            "current_hash": current_payload_hash,
            "block_index": recorded_block.index,
            "block_hash": recorded_block.block_hash,
            "prev_block_hash": recorded_block.prev_block_hash,
            "timestamp": recorded_block.timestamp.isoformat(),
            "chain_valid": chain_valid,
            "message": msg,
        }
