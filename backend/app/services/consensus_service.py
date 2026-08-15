"""Multi-Party Quorum & Consensus Service."""

from datetime import datetime, timezone
import hashlib
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from app.crypto_wrapper.interface import KeyShare, get_crypto_adapter
from app.db.ephemeral import get_ephemeral_store
from app.db.models import ConsensusApproval, Exam, KeyGuardianAssignment
from app.schemas.consensus import ConsensusApproveRequest, QuorumStatusResponse
from app.services.audit_service import AuditService
from app.services.exam_service import ExamService


class ConsensusService:

    @staticmethod
    async def submit_approval(
        db: AsyncSession,
        exam_id: str,
        guardian_id: str,
        request_in: ConsensusApproveRequest,
    ) -> dict:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        if exam.status not in ["CONSENSUS_PENDING", "EPHEMERAL_PAYLOAD_STAGED"]:
            if exam.status == "UNLOCKED":
                # Already unlocked
                pass
            else:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Exam is in invalid status '{exam.status}' for consensus approvals",
                )

        # 1. Verify guardian is assigned to this exam
        assignment_stmt = select(KeyGuardianAssignment).where(
            KeyGuardianAssignment.exam_id == exam_id,
            KeyGuardianAssignment.guardian_id == guardian_id,
        )
        assign_res = await db.execute(assignment_stmt)
        assignment = assign_res.scalar_one_or_none()
        if not assignment:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="User is not an assigned Key Guardian for this exam",
            )

        # 2. Check if guardian already approved
        existing_approval_stmt = select(ConsensusApproval).where(
            ConsensusApproval.exam_id == exam_id,
            ConsensusApproval.guardian_id == guardian_id,
        )
        existing_res = await db.execute(existing_approval_stmt)
        if existing_res.scalar_one_or_none():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Guardian has already submitted approval for this exam",
            )

        # 3. Verify share using crypto wrapper
        crypto = get_crypto_adapter()
        mock_share = KeyShare(
            guardian_id=guardian_id,
            share_index=1,
            share_data=request_in.share_token,
        )
        if not crypto.verify_share(mock_share, assignment.public_key_fingerprint):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid cryptographic share token or signature",
            )

        # 4. Save approval metadata token in DB (SHA-256 hash of token, NO raw key)
        approval_token_hash = hashlib.sha256(request_in.share_token.encode("utf-8")).hexdigest()
        approval = ConsensusApproval(
            exam_id=exam_id,
            guardian_id=guardian_id,
            approval_hash=approval_token_hash,
        )
        db.add(approval)
        await db.commit()

        # 5. Count total distinct approvals
        approvals_stmt = select(ConsensusApproval).where(ConsensusApproval.exam_id == exam_id)
        approvals_res = await db.execute(approvals_stmt)
        current_approvals = list(approvals_res.scalars().all())
        quorum_count = len(current_approvals)

        quorum_reached = quorum_count >= exam.required_quorum
        if quorum_reached and exam.status != "UNLOCKED":
            exam.status = "UNLOCKED"
            await db.commit()
            await db.refresh(exam)

            await AuditService.log_event(
                db=db,
                action="QUORUM_REACHED",
                exam_id=exam.id,
                actor_id=guardian_id,
                details={
                    "quorum_count": quorum_count,
                    "required_quorum": exam.required_quorum,
                    "new_status": "UNLOCKED",
                },
            )

        await AuditService.log_event(
            db=db,
            action="GUARDIAN_APPROVED",
            exam_id=exam.id,
            actor_id=guardian_id,
            details={
                "current_quorum_count": quorum_count,
                "required_quorum": exam.required_quorum,
            },
        )

        return {
            "exam_id": exam.id,
            "guardian_id": guardian_id,
            "approved_at": datetime.now(timezone.utc),
            "current_quorum_count": quorum_count,
            "required_quorum": exam.required_quorum,
            "quorum_reached": quorum_reached,
            "new_exam_status": exam.status,
        }

    @staticmethod
    async def get_quorum_status(db: AsyncSession, exam_id: str) -> QuorumStatusResponse:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        approvals_stmt = select(ConsensusApproval).where(ConsensusApproval.exam_id == exam_id)
        approvals_res = await db.execute(approvals_stmt)
        approvals = list(approvals_res.scalars().all())

        approved_guardian_ids = [a.guardian_id for a in approvals]
        quorum_reached = len(approvals) >= exam.required_quorum

        return QuorumStatusResponse(
            exam_id=exam.id,
            status=exam.status,
            required_quorum=exam.required_quorum,
            total_guardians=exam.total_guardians,
            current_approvals_count=len(approvals),
            quorum_reached=quorum_reached,
            approved_guardians=approved_guardian_ids,
        )
