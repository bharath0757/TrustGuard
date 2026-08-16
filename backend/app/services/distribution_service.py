"""Ephemeral JIT Question-Paper Distribution Service."""

from datetime import datetime, timezone
from typing import AsyncGenerator
from fastapi import HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from app.crypto_wrapper.interface import get_crypto_adapter
from app.db.ephemeral import get_ephemeral_store
from app.services.audit_service import AuditService
from app.services.exam_service import ExamService


class DistributionService:

    @staticmethod
    async def get_payload_stream_generator(
        db: AsyncSession, exam_id: str, center_id: str
    ) -> AsyncGenerator[bytes, None]:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        # 1. Check Exam Status: If completed, expired, or revoked -> 410 Gone
        if exam.status in ["COMPLETED", "EXPIRED", "REVOKED"]:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail=f"Distribution closed: Exam status is '{exam.status}'",
            )

        # Must be UNLOCKED
        if exam.status != "UNLOCKED":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Distribution forbidden: Exam status is '{exam.status}', quorum approval is required",
            )

        # 2. Check Scheduled Window Time-Lock
        now = datetime.now(timezone.utc)
        sched_start = exam.scheduled_start.replace(tzinfo=timezone.utc) if exam.scheduled_start.tzinfo is None else exam.scheduled_start
        sched_end = exam.scheduled_end.replace(tzinfo=timezone.utc) if exam.scheduled_end.tzinfo is None else exam.scheduled_end

        if now < sched_start:
            raise HTTPException(
                status_code=status.HTTP_425_TOO_EARLY,
                detail=f"Time-Lock Enforced: Exam distribution opens at {sched_start.isoformat()}",
            )
        if now > sched_end:
            exam.status = "EXPIRED"
            await db.commit()
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Exam window has expired and distribution is closed",
            )

        # 3. Retrieve Encrypted Chunks directly from Ephemeral RAM Store
        ephemeral = get_ephemeral_store()
        chunks = await ephemeral.get_payload_chunks(exam_id)

        if not chunks:
            raise HTTPException(
                status_code=status.HTTP_410_GONE,
                detail="Ephemeral question paper payload is no longer present in RAM memory (purged/expired)",
            )

        # 4. Apply Traceable Watermarking via Crypto Adapter Interface & Stream
        crypto = get_crypto_adapter()

        await AuditService.log_event(
            db=db,
            action="EPHEMERAL_STREAM_ACCESSED",
            exam_id=exam.id,
            actor_id=center_id,
            details={"chunks_count": len(chunks), "center_id": center_id},
        )

        async def stream_generator():
            for chunk in chunks:
                watermarked = crypto.watermark_chunk_stream(chunk, center_id=center_id)
                yield watermarked

        return stream_generator()

    @staticmethod
    async def purge_ephemeral_data(db: AsyncSession, exam_id: str, actor_id: str) -> dict:
        exam = await ExamService.get_exam_by_id(db, exam_id)
        ephemeral = get_ephemeral_store()

        await ephemeral.purge_exam_data(exam_id)

        old_status = exam.status
        exam.status = "COMPLETED"
        await db.commit()

        await AuditService.log_event(
            db=db,
            action="EPHEMERAL_DATA_PURGED",
            exam_id=exam.id,
            actor_id=actor_id,
            details={"previous_status": old_status, "new_status": "COMPLETED"},
        )

        return {
            "exam_id": exam.id,
            "purged": True,
            "status": exam.status,
            "message": "Ephemeral payload memory buffers successfully purged from RAM",
        }
