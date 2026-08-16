"""
TrustGuard Attack Simulator — Synthetic Target Resources.

SAFE LOCAL SIMULATION ONLY.
Creates synthetic question papers, keys, and access objects for simulated testing.
Zero real examination content (uses dummy labels like "TRUSTGUARD_DEMO_PAPER").
"""

from datetime import datetime, timedelta, timezone
import hashlib
import os
from typing import Any, Dict, List, Optional, Tuple
import uuid

from sqlalchemy.orm import Session

from database.models.access import (
    AccessRequest,
    AccessWindow,
    Approval,
    ApprovalDecision,
    RequestStatus,
    RequestType,
    WindowStatus,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole
from security import (
    protect_paper,
    fragment_paper,
    create_access_request,
    cast_approval_vote,
    create_access_window,
)
from security.crypto.fragmentation import FragmentPayload


SYNTHETIC_DEMO_PAYLOAD = b"TRUSTGUARD_DEMO_PAPER\n[SECTION_A=100, SECTION_B=200, SIMULATION_ONLY]"


def create_simulated_target_paper(
    db: Session,
    exam_identifier: Optional[str] = None,
    paper_name: str = "Synthetic Defense Benchmark Exam",
    num_fragments: int = 5,
    key: Optional[bytes] = None,
    creator_id: Optional[uuid.UUID] = None,
) -> Tuple[QuestionPaper, List[PaperFragment], bytes]:
    """
    Create, protect, and fragment a synthetic examination paper for attack simulation.

    Returns:
        Tuple[QuestionPaper, List[PaperFragment], bytes]: (paper, db_fragments, master_key)
    """
    master_key = key or os.urandom(32)
    ident = exam_identifier or f"SIM-TARGET-{uuid.uuid4().hex[:8].upper()}"

    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier=ident,
        paper_name=paper_name,
        status=PaperStatus.CREATED,
        created_by=creator_id,
    )
    db.add(paper)
    db.flush()

    protect_paper(
        db=db,
        paper_id=paper.id,
        plaintext_data=SYNTHETIC_DEMO_PAYLOAD,
        key=master_key,
        actor_id=creator_id,
        actor_ip="127.0.0.1",
    )

    fragments = fragment_paper(
        db=db,
        paper_id=paper.id,
        num_fragments=num_fragments,
        actor_id=creator_id,
        actor_ip="127.0.0.1",
    )

    db.flush()
    return paper, fragments, master_key


def create_simulated_access_setup(
    db: Session,
    paper_id: uuid.UUID,
    requester_id: uuid.UUID,
    approver_ids: List[uuid.UUID],
    approve_count: int = 0,
    required_approvals: int = 3,
    start_offset_minutes: int = -5,
    end_offset_minutes: int = 60,
) -> Tuple[AccessRequest, Optional[AccessWindow]]:
    """
    Create an access request with a configurable number of approvals and time window.
    """
    req = create_access_request(
        db=db,
        paper_id=paper_id,
        requested_by=requester_id,
        request_type=RequestType.RECONSTRUCT,
        reason="Controlled simulation testing setup",
        required_approvals=required_approvals,
        actor_ip="127.0.0.1",
    )

    for i in range(min(approve_count, len(approver_ids))):
        cast_approval_vote(
            db=db,
            request_id=req.id,
            approver_id=approver_ids[i],
            decision=ApprovalDecision.APPROVED,
            reason=f"Simulated pre-approval vote {i+1}",
        )

    window = None
    if req.status == RequestStatus.APPROVED:
        now = datetime.now(timezone.utc)
        window = create_access_window(
            db=db,
            request_id=req.id,
            start_time=now + timedelta(minutes=start_offset_minutes),
            end_time=now + timedelta(minutes=end_offset_minutes),
        )

    db.flush()
    return req, window
