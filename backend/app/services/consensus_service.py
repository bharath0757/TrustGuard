"""Multi-Party Quorum & Consensus Service."""

from datetime import datetime, timezone
import hashlib
from typing import List, Optional
from fastapi import HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.crypto_wrapper.interface import KeyShare, get_crypto_adapter
from app.db.ephemeral import get_ephemeral_store
from app.db.models import ConsensusApproval, Exam, KeyGuardianAssignment, UploadedPaper, User
from app.schemas.consensus import (
    ConsensusApproveRequest,
    GuardianApprovalDetail,
    PendingConsensusExamResponse,
    QuorumStatusResponse,
)
from app.services.audit_service import AuditService
from app.services.exam_service import ExamService


class ConsensusService:

    @staticmethod
    async def submit_approval(
        db: AsyncSession,
        exam_id: str,
        guardian_id: str,
        request_in: Optional[ConsensusApproveRequest] = None,
    ) -> dict:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        valid_approval_statuses = [
            "CONSENSUS_PENDING",
            "EPHEMERAL_PAYLOAD_STAGED",
            "AWAITING_APPROVAL",
            "STAGED",
            "DRAFT",
            "READY",
            "UNLOCKED",
            "AUTHORIZED",
        ]
        if exam.status not in valid_approval_statuses:
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

        # 3. Cryptographic share verification & resolution
        crypto = get_crypto_adapter()
        ephemeral = get_ephemeral_store()

        share_token = request_in.share_token if (request_in and request_in.share_token) else None
        if not share_token:
            # Retrieve guardian key share from ephemeral store or generate signature
            stored_share = await ephemeral.get_key_share(exam_id, guardian_id)
            if stored_share:
                share_token = stored_share
            else:
                share_token = f"GUARDIAN_APPROVAL_SHARE_{guardian_id}_{exam_id}"
        else:
            mock_share = KeyShare(
                guardian_id=guardian_id,
                share_index=1,
                share_data=share_token,
            )
            if not crypto.verify_share(mock_share, assignment.public_key_fingerprint):
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Invalid cryptographic share token or signature",
                )

        # 4. Save approval metadata token in DB (SHA-256 hash of token, NO raw key)
        approval_token_hash = hashlib.sha256(share_token.encode("utf-8")).hexdigest()
        approval = ConsensusApproval(
            exam_id=exam_id,
            guardian_id=guardian_id,
            approval_hash=approval_token_hash,
            approved_at=datetime.now(timezone.utc),
        )
        db.add(approval)
        await db.commit()

        # 5. Count total distinct approvals
        approvals_stmt = select(ConsensusApproval).where(ConsensusApproval.exam_id == exam_id)
        approvals_res = await db.execute(approvals_stmt)
        current_approvals = list(approvals_res.scalars().all())
        quorum_count = len(current_approvals)

        quorum_reached = quorum_count >= exam.required_quorum
        if quorum_reached and exam.status not in ["AUTHORIZED", "UNLOCKED"]:
            # Transition exam to AUTHORIZED state
            exam.status = "AUTHORIZED"

            # Transition paper to AUTHORIZED state and record release timestamp
            if exam.paper_id:
                paper_stmt = select(UploadedPaper).where(UploadedPaper.id == exam.paper_id)
                paper_res = await db.execute(paper_stmt)
                paper = paper_res.scalar_one_or_none()
                if paper:
                    paper.status = "AUTHORIZED"
                    paper.released_at = datetime.now(timezone.utc)

            await db.commit()
            await db.refresh(exam)

            # Record consensus reached and paper authorized audit events
            await AuditService.log_event(
                db=db,
                action="CONSENSUS_REACHED",
                exam_id=exam.id,
                actor_id=guardian_id,
                details={
                    "quorum_count": quorum_count,
                    "required_quorum": exam.required_quorum,
                    "new_status": "AUTHORIZED",
                    "paper_authorized": True,
                },
            )

            await AuditService.log_event(
                db=db,
                action="QUORUM_REACHED",
                exam_id=exam.id,
                actor_id=guardian_id,
                details={
                    "quorum_count": quorum_count,
                    "required_quorum": exam.required_quorum,
                    "new_status": "AUTHORIZED",
                },
            )

            await AuditService.log_event(
                db=db,
                action="PAPER_AUTHORIZED",
                exam_id=exam.id,
                actor_id=guardian_id,
                details={
                    "exam_id": exam.id,
                    "paper_id": exam.paper_id,
                    "quorum_count": quorum_count,
                    "required_quorum": exam.required_quorum,
                    "status": "AUTHORIZED",
                },
            )
        elif not quorum_reached and exam.status in ["AWAITING_APPROVAL", "DRAFT", "READY", "EPHEMERAL_PAYLOAD_STAGED"]:
            exam.status = "CONSENSUS_PENDING"
            await db.commit()
            await db.refresh(exam)

        await AuditService.log_event(
            db=db,
            action="GUARDIAN_APPROVED",
            exam_id=exam.id,
            actor_id=guardian_id,
            details={
                "current_quorum_count": quorum_count,
                "required_quorum": exam.required_quorum,
                "quorum_reached": quorum_reached,
            },
        )

        # Real-time WebSocket event broadcast to guardian dashboard
        try:
            from app.services.websocket_manager import get_ws_manager
            ws_manager = get_ws_manager()
            await ws_manager.broadcast_to_exam(
                exam.id,
                "GUARDIAN_APPROVED",
                {
                    "guardian_id": guardian_id,
                    "approvals_count": quorum_count,
                    "required_quorum": exam.required_quorum,
                    "quorum_reached": quorum_reached,
                    "exam_status": exam.status,
                },
            )
            if quorum_reached:
                await ws_manager.broadcast_to_exam(
                    exam.id,
                    "CONSENSUS_REACHED",
                    {
                        "exam_id": exam.id,
                        "quorum_count": quorum_count,
                        "required_quorum": exam.required_quorum,
                        "status": "AUTHORIZED",
                    },
                )
                await ws_manager.broadcast_to_exam(
                    exam.id,
                    "PAPER_RELEASED",
                    {
                        "exam_id": exam.id,
                        "paper_id": exam.paper_id,
                        "status": "RELEASED",
                    },
                )
        except Exception:
            pass

        msg = (
            f"Quorum reached ({quorum_count}/{exam.required_quorum})! Question paper is AUTHORIZED for release."
            if quorum_reached
            else f"Approval recorded ({quorum_count}/{exam.required_quorum}). Awaiting remaining guardian authorizations."
        )

        return {
            "exam_id": exam.id,
            "guardian_id": guardian_id,
            "approved_at": approval.approved_at,
            "current_quorum_count": quorum_count,
            "required_quorum": exam.required_quorum,
            "quorum_reached": quorum_reached,
            "new_exam_status": exam.status,
            "message": msg,
        }

    @staticmethod
    async def get_quorum_status(db: AsyncSession, exam_id: str) -> QuorumStatusResponse:
        exam = await ExamService.get_exam_by_id(db, exam_id)

        # Retrieve all approvals
        approvals_stmt = (
            select(ConsensusApproval)
            .where(ConsensusApproval.exam_id == exam_id)
            .order_by(ConsensusApproval.approved_at.asc())
        )
        approvals_res = await db.execute(approvals_stmt)
        approvals = list(approvals_res.scalars().all())

        approval_map = {a.guardian_id: a for a in approvals}
        approved_guardian_ids = list(approval_map.keys())

        # Retrieve all assigned guardians with user details
        assignments_stmt = (
            select(KeyGuardianAssignment)
            .where(KeyGuardianAssignment.exam_id == exam_id)
            .options(selectinload(KeyGuardianAssignment.guardian))
        )
        assign_res = await db.execute(assignments_stmt)
        assignments = list(assign_res.scalars().all())

        guardians_detail = []
        for assign in assignments:
            guardian_user = assign.guardian
            appr = approval_map.get(assign.guardian_id)
            is_approved = appr is not None

            g_username = guardian_user.username if guardian_user else "guardian"
            g_role = guardian_user.role if guardian_user else "KEY_GUARDIAN"
            g_full_name = getattr(guardian_user, "full_name", None) or g_username.capitalize()

            guardians_detail.append(
                GuardianApprovalDetail(
                    guardian_id=assign.guardian_id,
                    username=g_username,
                    full_name=g_full_name,
                    role=g_role,
                    status="APPROVED" if is_approved else "WAITING",
                    approved_at=appr.approved_at if appr else None,
                )
            )

        quorum_reached = len(approvals) >= exam.required_quorum

        paper_name = exam.paper.paper_name if exam.paper else None

        return QuorumStatusResponse(
            exam_id=exam.id,
            exam_title=exam.title,
            paper_id=exam.paper_id,
            paper_name=paper_name,
            status=exam.status,
            required_quorum=exam.required_quorum,
            total_guardians=exam.total_guardians,
            current_approvals_count=len(approvals),
            quorum_reached=quorum_reached,
            approved_guardians=approved_guardian_ids,
            guardians=guardians_detail,
        )

    @staticmethod
    async def list_pending_exams(
        db: AsyncSession, guardian_id: str
    ) -> List[PendingConsensusExamResponse]:
        """List all exams assigned to this guardian or requiring consensus."""
        stmt = (
            select(Exam)
            .options(
                selectinload(Exam.guardians),
                selectinload(Exam.approvals),
                selectinload(Exam.paper),
            )
            .order_by(Exam.created_at.desc())
        )
        res = await db.execute(stmt)
        exams = list(res.scalars().all())

        pending_list = []
        for exam in exams:
            # Check if this guardian is assigned
            is_assigned = any(g.guardian_id == guardian_id for g in exam.guardians)
            # Check if guardian has approved
            has_approved = any(a.guardian_id == guardian_id for a in exam.approvals)

            approvals_count = len(exam.approvals)
            quorum_reached = approvals_count >= exam.required_quorum
            paper_name = exam.paper.paper_name if exam.paper else None

            pending_list.append(
                PendingConsensusExamResponse(
                    exam_id=exam.id,
                    exam_title=exam.title,
                    course_code=exam.course_code,
                    paper_id=exam.paper_id,
                    paper_name=paper_name,
                    status=exam.status,
                    required_quorum=exam.required_quorum,
                    total_guardians=exam.total_guardians,
                    current_approvals_count=approvals_count,
                    quorum_reached=quorum_reached,
                    has_approved=has_approved,
                    created_at=exam.created_at,
                )
            )

        return pending_list
