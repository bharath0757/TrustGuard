"""Exam Lifecycle management service."""

import base64
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.crypto_wrapper.interface import get_crypto_adapter
from app.db.ephemeral import get_ephemeral_store
from app.db.models import Exam, KeyGuardianAssignment, User
from app.schemas.exam import ExamCreate, GuardianAssign, PayloadStageRequest
from app.services.audit_service import AuditService


class ExamService:

    @staticmethod
    async def create_exam(db: AsyncSession, exam_in: ExamCreate, creator_id: str) -> Exam:
        if exam_in.required_quorum > exam_in.total_guardians:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Required quorum (k) cannot exceed total guardians (n)",
            )

        exam = Exam(
            title=exam_in.title,
            course_code=exam_in.course_code,
            scheduled_start=exam_in.scheduled_start,
            scheduled_end=exam_in.scheduled_end,
            required_quorum=exam_in.required_quorum,
            total_guardians=exam_in.total_guardians,
            created_by=creator_id,
            status="DRAFT",
        )
        db.add(exam)
        await db.commit()
        await db.refresh(exam)

        await AuditService.log_event(
            db=db,
            action="EXAM_CREATED",
            exam_id=exam.id,
            actor_id=creator_id,
            details={"title": exam.title, "k": exam.required_quorum, "n": exam.total_guardians},
        )
        return exam

    @staticmethod
    async def get_exam_by_id(db: AsyncSession, exam_id: str) -> Exam:
        stmt = (
            select(Exam)
            .where(Exam.id == exam_id)
            .options(selectinload(Exam.guardians), selectinload(Exam.approvals))
        )
        result = await db.execute(stmt)
        exam = result.scalar_one_or_none()
        if not exam:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Exam with ID {exam_id} not found",
            )
        return exam

    @staticmethod
    async def list_exams(db: AsyncSession, skip: int = 0, limit: int = 100) -> List[Exam]:
        stmt = (
            select(Exam)
            .options(selectinload(Exam.guardians))
            .order_by(Exam.created_at.desc())
            .offset(skip)
            .limit(limit)
        )
        result = await db.execute(stmt)
        return list(result.scalars().all())

    @staticmethod
    async def assign_guardian(
        db: AsyncSession, exam_id: str, assign_in: GuardianAssign, actor_id: str
    ) -> KeyGuardianAssignment:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        if len(exam.guardians) >= exam.total_guardians:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Cannot assign more than configured {exam.total_guardians} guardians",
            )

        # Verify target user exists
        user_stmt = select(User).where(User.id == assign_in.guardian_user_id)
        user_res = await db.execute(user_stmt)
        guardian_user = user_res.scalar_one_or_none()
        if not guardian_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Guardian user {assign_in.guardian_user_id} not found",
            )

        # Check if already assigned
        for existing in exam.guardians:
            if existing.guardian_id == assign_in.guardian_user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Guardian is already assigned to this exam",
                )

        assignment = KeyGuardianAssignment(
            exam_id=exam.id,
            guardian_id=assign_in.guardian_user_id,
            public_key_fingerprint=assign_in.public_key_fingerprint,
        )
        db.add(assignment)
        await db.commit()
        await db.refresh(assignment)

        await AuditService.log_event(
            db=db,
            action="GUARDIAN_ASSIGNED",
            exam_id=exam.id,
            actor_id=actor_id,
            details={
                "guardian_id": assign_in.guardian_user_id,
                "public_key_fingerprint": assign_in.public_key_fingerprint,
            },
        )
        return assignment

    @staticmethod
    async def stage_encrypted_payload(
        db: AsyncSession, exam_id: str, payload_in: PayloadStageRequest, actor_id: str
    ) -> dict:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        if len(exam.guardians) < exam.required_quorum:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"At least {exam.required_quorum} guardians must be assigned before staging payload",
            )

        crypto = get_crypto_adapter()
        ephemeral = get_ephemeral_store()

        raw_chunks = []
        full_payload_bytes = bytearray()
        for chunk_b64 in payload_in.encrypted_chunks:
            try:
                chunk_bytes = base64.b64decode(chunk_b64)
            except Exception:
                chunk_bytes = chunk_b64.encode("utf-8")
            raw_chunks.append(chunk_bytes)
            full_payload_bytes.extend(chunk_bytes)

        payload_hash = crypto.compute_payload_hash(bytes(full_payload_bytes))

        await ephemeral.store_payload_chunks(
            exam_id=exam.id, chunks=raw_chunks, ttl_seconds=payload_in.ttl_seconds
        )

        guardian_ids = [g.guardian_id for g in exam.guardians]
        key_shares = crypto.split_secret(
            secret_bytes=bytes(full_payload_bytes),
            threshold_k=exam.required_quorum,
            total_n=len(guardian_ids),
            guardian_ids=guardian_ids,
        )

        for share in key_shares:
            await ephemeral.store_key_share(
                exam_id=exam.id,
                guardian_id=share.guardian_id,
                share_data=share.share_data,
                ttl_seconds=payload_in.ttl_seconds,
            )

        exam.encrypted_payload_hash = payload_hash
        exam.status = "CONSENSUS_PENDING"
        await db.commit()
        await db.refresh(exam)

        await AuditService.log_event(
            db=db,
            action="EPHEMERAL_PAYLOAD_STAGED",
            exam_id=exam.id,
            actor_id=actor_id,
            details={
                "chunks_count": len(raw_chunks),
                "payload_hash": payload_hash,
                "ttl_seconds": payload_in.ttl_seconds,
            },
        )

        return {
            "exam_id": exam.id,
            "status": exam.status,
            "chunks_staged": len(raw_chunks),
            "encrypted_payload_hash": payload_hash,
            "ttl_seconds": payload_in.ttl_seconds,
        }
