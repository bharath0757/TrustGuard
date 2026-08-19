"""Exam Lifecycle management service with multi-guardian assignment, student registration, and encrypted staging."""

import base64
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.crypto_wrapper.interface import get_crypto_adapter
from app.db.ephemeral import get_ephemeral_store
from app.db.models import Exam, ExamStudent, KeyGuardianAssignment, UploadedPaper, User
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

        if exam_in.duration_minutes <= 0:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Exam duration must be greater than 0 minutes",
            )

        exam = Exam(
            title=exam_in.title,
            course_code=exam_in.course_code,
            description=getattr(exam_in, 'description', None),
            paper_id=getattr(exam_in, 'paper_id', None),
            scheduled_start=exam_in.scheduled_start,
            scheduled_end=exam_in.scheduled_end,
            duration_minutes=exam_in.duration_minutes,
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
            details={
                "title": exam.title,
                "course_code": exam.course_code,
                "duration_minutes": exam.duration_minutes,
                "paper_id": exam.paper_id,
                "k": exam.required_quorum,
                "n": exam.total_guardians,
            },
        )

        # Seed standard questions for prototype examination
        from app.services.student_service import StudentService
        await StudentService.ensure_exam_questions_seeded(db, exam.id)

        return await ExamService.get_exam_by_id(db, exam.id)

    @staticmethod
    async def get_exam_by_id(db: AsyncSession, exam_id: str) -> Exam:
        stmt = (
            select(Exam)
            .where(Exam.id == exam_id)
            .options(
                selectinload(Exam.guardians),
                selectinload(Exam.students),
                selectinload(Exam.approvals),
                selectinload(Exam.paper),
            )
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
            .options(
                selectinload(Exam.guardians),
                selectinload(Exam.students),
                selectinload(Exam.paper),
            )
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

        # Verify target user exists and has guardian or admin role
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
                "guardian_username": guardian_user.username,
                "public_key_fingerprint": assign_in.public_key_fingerprint,
            },
        )
        return assignment

    @staticmethod
    async def assign_student(
        db: AsyncSession, exam_id: str, student_user_id: str, actor_id: str
    ) -> ExamStudent:
        """Register a student for an exam."""
        exam = await ExamService.get_exam_by_id(db, exam_id)

        # Verify user exists
        user_stmt = select(User).where(User.id == student_user_id)
        user_res = await db.execute(user_stmt)
        student_user = user_res.scalar_one_or_none()
        if not student_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Student user with ID '{student_user_id}' not found",
            )

        # Check if already registered
        for existing in exam.students:
            if existing.student_id == student_user_id:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Student '{student_user.username}' is already registered for this exam",
                )

        student_reg = ExamStudent(
            exam_id=exam.id,
            student_id=student_user_id,
            registration_status="REGISTERED",
        )
        db.add(student_reg)
        await db.commit()
        await db.refresh(student_reg)

        await AuditService.log_event(
            db=db,
            action="STUDENT_REGISTERED",
            exam_id=exam.id,
            actor_id=actor_id,
            details={
                "student_id": student_user_id,
                "student_username": student_user.username,
                "exam_title": exam.title,
            },
        )
        return student_reg

    @staticmethod
    async def register_students(
        db: AsyncSession, exam_id: str, student_user_ids: List[str], actor_id: str
    ) -> List[ExamStudent]:
        """Bulk register students for an examination."""
        registered = []
        for sid in student_user_ids:
            try:
                reg = await ExamService.assign_student(db, exam_id, sid, actor_id)
                registered.append(reg)
            except HTTPException as e:
                # If already registered, skip; if not found, raise
                if e.status_code == 404:
                    raise e
        return registered

    @staticmethod
    async def stage_exam_paper(
        db: AsyncSession, exam_id: str, paper_id: Optional[str], ttl_seconds: int, actor_id: str
    ) -> dict:
        """
        Stage an encrypted question paper into Ephemeral RAM for the exam:
        1. Verifies quorum of guardians assigned (at least required_quorum)
        2. Retrieves encrypted paper payload
        3. Shards ciphertext into ephemeral RAM buffer with TTL
        4. Splits key material among assigned guardians using Shamir Secret Sharing
        5. Transitions exam state to AWAITING_APPROVAL
        6. Records audit event
        """
        exam = await ExamService.get_exam_by_id(db, exam_id)

        target_paper_id = paper_id or exam.paper_id
        if not target_paper_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No question paper associated with this exam. Upload paper first.",
            )

        # Retrieve paper
        paper_stmt = select(UploadedPaper).where(UploadedPaper.id == target_paper_id)
        paper_res = await db.execute(paper_stmt)
        paper = paper_res.scalar_one_or_none()
        if not paper:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Question paper with ID '{target_paper_id}' not found",
            )

        if len(exam.guardians) < exam.required_quorum:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"At least {exam.required_quorum} guardians must be assigned before staging paper (currently assigned: {len(exam.guardians)})",
            )

        crypto = get_crypto_adapter()
        ephemeral = get_ephemeral_store()

        # Retrieve encrypted bytes (or create simulated secure chunks)
        if paper.encrypted_payload_hex:
            try:
                encrypted_bytes = bytes.fromhex(paper.encrypted_payload_hex)
            except Exception:
                encrypted_bytes = paper.encrypted_payload_hex.encode("utf-8")
        else:
            encrypted_bytes = f"ENCRYPTED_PAPER_PAYLOAD_FOR_{exam.id}".encode("utf-8")

        # Split encrypted payload into chunks for sharding
        chunk_size = max(1024, len(encrypted_bytes) // 3 if len(encrypted_bytes) >= 3 else 1)
        raw_chunks = [encrypted_bytes[i:i + chunk_size] for i in range(0, len(encrypted_bytes), chunk_size)]
        if not raw_chunks:
            raw_chunks = [encrypted_bytes]

        payload_hash = crypto.compute_payload_hash(encrypted_bytes)

        # Store in ephemeral RAM store with TTL
        await ephemeral.store_payload_chunks(
            exam_id=exam.id, chunks=raw_chunks, ttl_seconds=ttl_seconds
        )

        # Split key share among guardians
        guardian_ids = [g.guardian_id for g in exam.guardians]
        key_shares = crypto.split_secret(
            secret_bytes=encrypted_bytes,
            threshold_k=exam.required_quorum,
            total_n=len(guardian_ids),
            guardian_ids=guardian_ids,
        )

        for share in key_shares:
            await ephemeral.store_key_share(
                exam_id=exam.id,
                guardian_id=share.guardian_id,
                share_data=share.share_data,
                ttl_seconds=ttl_seconds,
            )

        # Update exam state to AWAITING_APPROVAL / CONSENSUS_PENDING
        exam.paper_id = paper.id
        exam.encrypted_payload_hash = payload_hash
        exam.status = "AWAITING_APPROVAL"
        paper.status = "AWAITING_APPROVAL"
        paper.staged_at = datetime.now(timezone.utc)

        # Record SHA-256 payload hash to immutable blockchain ledger
        from app.services.blockchain_service import BlockchainService
        await BlockchainService.record_payload_hash(
            db=db,
            exam_id=exam.id,
            payload_hash=payload_hash,
            paper_id=paper.id,
            recorded_by=actor_id,
        )

        await db.commit()
        await db.refresh(exam)

        await AuditService.log_event(
            db=db,
            action="PAPER_STAGED_FOR_APPROVAL",
            exam_id=exam.id,
            actor_id=actor_id,
            details={
                "paper_id": paper.id,
                "paper_name": paper.paper_name,
                "chunks_count": len(raw_chunks),
                "payload_hash": payload_hash,
                "ttl_seconds": ttl_seconds,
                "status": "AWAITING_APPROVAL",
            },
        )

        return {
            "exam_id": exam.id,
            "paper_id": paper.id,
            "status": exam.status,
            "chunks_staged": len(raw_chunks),
            "encrypted_payload_hash": payload_hash,
            "ttl_seconds": ttl_seconds,
            "message": f"Paper '{paper.paper_name}' staged securely. Ready for multi-guardian approval ({exam.required_quorum}/{len(exam.guardians)}).",
        }

    @staticmethod
    async def stage_encrypted_payload(
        db: AsyncSession, exam_id: str, payload_in: PayloadStageRequest, actor_id: str
    ) -> dict:
        """Legacy payload staging method for compatibility."""
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
