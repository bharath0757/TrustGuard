"""
TrustGuard — Quorum Authorization & Multi-Party Approval Service.

TERMINOLOGY & ARCHITECTURAL NOTE:
---------------------------------
This service implements **Quorum Authorization** (also known as **Multi-Party Authorization**).
It is **NOT** threshold cryptography (e.g. Shamir's Secret Sharing or threshold signatures).

CORE PRINCIPLES:
1. Zero Single-Point of Trust: A single valid user account must NEVER automatically be
   sufficient to authorize access to a protected question paper.
2. Default-to-Deny: Access is denied unless a strictly validated set of independent
   authorized approver votes meets or exceeds the required quorum threshold.
3. Separation of Duties: Requesters cannot approve their own requests by default.
4. Strict Vote Integrity:
   - Approvers must be authenticated, active system users.
   - Approvers must possess an authorized role (e.g., APPROVER, OFFICER, ADMIN).
   - Duplicate votes on the same request are strictly forbidden.
   - Non-approver, rejected, or invalid votes do not count toward quorum.
   - Expired or completed requests cannot accept new votes.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import enum
import logging
from typing import List, Optional, Set, Tuple
import uuid

from sqlalchemy.orm import Session

from database.models.access import (
    AccessRequest,
    Approval,
    ApprovalDecision,
    RequestStatus,
    RequestType,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.user import User, UserRole, Role


logger = logging.getLogger("trustguard.security.quorum")

# Canonical roles authorized to cast approval votes by default
DEFAULT_APPROVER_ROLES: Set[str] = {"APPROVER", "OFFICER", "ADMIN"}


# ---------------------------------------------------------------------------
# Enums and Result Containers
# ---------------------------------------------------------------------------

class QuorumDecision(str, enum.Enum):
    """Quorum authorization outcome."""
    AUTHORIZED = "AUTHORIZED"   # Quorum threshold met; access granted
    PENDING = "PENDING"         # Insufficient votes; awaiting further approvals
    DENIED = "DENIED"           # Explicitly rejected or invalid


@dataclass
class QuorumResult:
    """Detailed summary of a quorum evaluation."""
    decision: QuorumDecision
    is_authorized: bool
    request_id: uuid.UUID
    paper_id: uuid.UUID
    approved_count: int
    rejected_count: int
    required_approvals: int
    request_status: RequestStatus
    details: str


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class QuorumError(Exception):
    """Base exception for all quorum and authorization operations."""
    pass


class QuorumValidationError(QuorumError):
    """Raised when request or approval parameters fail validation."""
    pass


class UnauthorizedApproverError(QuorumValidationError):
    """Raised when an approver is not authenticated, inactive, or lacks required role."""
    pass


class InvalidApproverRoleError(UnauthorizedApproverError):
    """Raised when an approver lacks an authorized role to vote."""
    pass


class DuplicateApprovalError(QuorumValidationError):
    """Raised when an approver attempts to vote multiple times on the same request."""
    pass


class RequestNotPendingError(QuorumValidationError):
    """Raised when attempting to vote on an already decided, expired, or completed request."""
    pass


class SelfApprovalError(QuorumValidationError):
    """Raised when a requester attempts to approve their own access request."""
    pass


class AccessDeniedError(QuorumError):
    """Raised when access to a protected question paper is denied due to unmet quorum."""
    pass


# ---------------------------------------------------------------------------
# Role Helper Functions
# ---------------------------------------------------------------------------

def get_user_role_names(db: Session, user_id: uuid.UUID) -> Set[str]:
    """
    Retrieve the set of canonical role names assigned to a user.

    Args:
        db: SQLAlchemy database session.
        user_id: User UUID.

    Returns:
        Set[str]: Set of uppercase role names (e.g., {'OFFICER', 'APPROVER'}).
    """
    user_roles = (
        db.query(Role.name)
        .join(UserRole, UserRole.role_id == Role.id)
        .filter(UserRole.user_id == user_id)
        .all()
    )
    return {r[0].upper() for r in user_roles}


def is_user_authorized_approver(
    db: Session,
    user_id: uuid.UUID,
    allowed_roles: Optional[Set[str]] = None,
) -> bool:
    """
    Check if a user is active and possesses an authorized approver role.

    Args:
        db: SQLAlchemy database session.
        user_id: User UUID to check.
        allowed_roles: Optional set of authorized role names (defaults to DEFAULT_APPROVER_ROLES).

    Returns:
        bool: True if authorized, False otherwise.
    """
    user = db.get(User, user_id)
    if not user or not user.is_active:
        return False

    roles_to_check = allowed_roles if allowed_roles is not None else DEFAULT_APPROVER_ROLES
    user_roles = get_user_role_names(db, user_id)
    return bool(user_roles & roles_to_check)


# ---------------------------------------------------------------------------
# Access Request Lifecycle
# ---------------------------------------------------------------------------

def create_access_request(
    db: Session,
    paper_id: uuid.UUID,
    requested_by: uuid.UUID,
    request_type: RequestType = RequestType.RECONSTRUCT,
    reason: str = "Formal request for examination paper access",
    required_approvals: int = 3,
) -> AccessRequest:
    """
    Create and persist a new multi-party access request for a question paper.

    Args:
        db: SQLAlchemy database session.
        paper_id: UUID of the protected QuestionPaper.
        requested_by: UUID of the authenticated requesting user.
        request_type: Type of access requested (VIEW, RECONSTRUCT, EMERGENCY).
        reason: Mandatory justification.
        required_approvals: Quorum threshold (must be >= 1, defaults to 3).

    Returns:
        AccessRequest: The persisted access request in PENDING status.

    Raises:
        QuorumValidationError: If parameters, paper, or user are invalid.
    """
    if required_approvals < 1:
        raise QuorumValidationError(f"required_approvals must be >= 1, got {required_approvals}")
    if not reason or not reason.strip():
        raise QuorumValidationError("Access request reason cannot be empty")

    # Verify paper existence
    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        raise QuorumValidationError(f"Question paper with ID {paper_id} not found")

    # Verify requester existence and active status
    requester = db.get(User, requested_by)
    if not requester:
        raise QuorumValidationError(f"Requesting user with ID {requested_by} not found")
    if not requester.is_active:
        raise QuorumValidationError(f"Requesting user {requested_by} is inactive")

    # If paper is fragmented/protected, transition to AWAITING_APPROVAL
    if paper.status in (PaperStatus.PROTECTED, PaperStatus.FRAGMENTED):
        paper.status = PaperStatus.AWAITING_APPROVAL

    access_request = AccessRequest(
        id=uuid.uuid4(),
        paper_id=paper_id,
        requested_by=requested_by,
        request_type=request_type,
        status=RequestStatus.PENDING,
        required_approvals=required_approvals,
        reason=reason.strip(),
    )
    db.add(access_request)
    db.flush()

    logger.info(
        "Access request %s created for paper %s (required approvals: %d)",
        access_request.id,
        paper_id,
        required_approvals,
    )
    return access_request


# ---------------------------------------------------------------------------
# Approval Voting & Quorum Evaluation
# ---------------------------------------------------------------------------

def calculate_quorum_counts(
    db: Session,
    request_id: uuid.UUID,
) -> Tuple[int, int, int]:
    """
    Calculate the count of valid APPROVED votes, REJECTED votes, and required threshold.

    Args:
        db: SQLAlchemy database session.
        request_id: UUID of the AccessRequest.

    Returns:
        Tuple[int, int, int]: (approved_count, rejected_count, required_approvals)
    """
    access_request = db.get(AccessRequest, request_id)
    if not access_request:
        raise QuorumValidationError(f"Access request {request_id} not found")

    approved_count = (
        db.query(Approval)
        .filter(
            Approval.request_id == request_id,
            Approval.decision == ApprovalDecision.APPROVED,
        )
        .count()
    )

    rejected_count = (
        db.query(Approval)
        .filter(
            Approval.request_id == request_id,
            Approval.decision == ApprovalDecision.REJECTED,
        )
        .count()
    )

    return approved_count, rejected_count, access_request.required_approvals


def evaluate_quorum(
    db: Session,
    request_id: uuid.UUID,
    reject_on_single_rejection: bool = False,
) -> QuorumResult:
    """
    Evaluate the current quorum state of an access request and perform state transitions.

    Decision Rules (Default to Deny):
    - If approved_count >= required_approvals:
        -> AUTHORIZED (request -> APPROVED, paper -> AUTHORIZED)
    - If reject_on_single_rejection is True and rejected_count > 0:
        -> DENIED (request -> REJECTED)
    - If request is already REJECTED, EXPIRED, or WITHDRAWN:
        -> DENIED
    - If approved_count < required_approvals:
        -> PENDING (request remains PENDING, paper remains AWAITING_APPROVAL)

    Args:
        db: SQLAlchemy database session.
        request_id: UUID of the AccessRequest.
        reject_on_single_rejection: If True, a single REJECTED vote transitions request to REJECTED.

    Returns:
        QuorumResult: The evaluated quorum status.
    """
    access_request = db.get(AccessRequest, request_id)
    if not access_request:
        raise QuorumValidationError(f"Access request {request_id} not found")

    paper = db.get(QuestionPaper, access_request.paper_id)
    paper_id = access_request.paper_id
    now = datetime.now(timezone.utc)

    approved_count, rejected_count, required_approvals = calculate_quorum_counts(db, request_id)

    # 1. Check if request was already terminated
    if access_request.status == RequestStatus.EXPIRED:
        return QuorumResult(
            decision=QuorumDecision.DENIED,
            is_authorized=False,
            request_id=request_id,
            paper_id=paper_id,
            approved_count=approved_count,
            rejected_count=rejected_count,
            required_approvals=required_approvals,
            request_status=RequestStatus.EXPIRED,
            details=f"Request {request_id} is EXPIRED",
        )

    if access_request.status == RequestStatus.WITHDRAWN:
        return QuorumResult(
            decision=QuorumDecision.DENIED,
            is_authorized=False,
            request_id=request_id,
            paper_id=paper_id,
            approved_count=approved_count,
            rejected_count=rejected_count,
            required_approvals=required_approvals,
            request_status=RequestStatus.WITHDRAWN,
            details=f"Request {request_id} was WITHDRAWN",
        )

    # 2. Check for explicit rejection policy
    if reject_on_single_rejection and rejected_count > 0:
        access_request.status = RequestStatus.REJECTED
        access_request.decided_at = now
        db.flush()
        return QuorumResult(
            decision=QuorumDecision.DENIED,
            is_authorized=False,
            request_id=request_id,
            paper_id=paper_id,
            approved_count=approved_count,
            rejected_count=rejected_count,
            required_approvals=required_approvals,
            request_status=RequestStatus.REJECTED,
            details=f"Request rejected ({rejected_count} rejection votes cast)",
        )

    # 3. Check if Quorum threshold is reached (APPROVED)
    if approved_count >= required_approvals:
        access_request.status = RequestStatus.APPROVED
        access_request.decided_at = now
        if paper and paper.status == PaperStatus.AWAITING_APPROVAL:
            paper.status = PaperStatus.AUTHORIZED
        db.flush()

        logger.info(
            "Quorum AUTHORIZED for request %s (%d/%d approvals)",
            request_id,
            approved_count,
            required_approvals,
        )
        return QuorumResult(
            decision=QuorumDecision.AUTHORIZED,
            is_authorized=True,
            request_id=request_id,
            paper_id=paper_id,
            approved_count=approved_count,
            rejected_count=rejected_count,
            required_approvals=required_approvals,
            request_status=RequestStatus.APPROVED,
            details=f"Quorum reached: {approved_count}/{required_approvals} approvals",
        )

    # 4. Quorum not yet reached -> Remains PENDING (Default to Deny)
    return QuorumResult(
        decision=QuorumDecision.PENDING,
        is_authorized=False,
        request_id=request_id,
        paper_id=paper_id,
        approved_count=approved_count,
        rejected_count=rejected_count,
        required_approvals=required_approvals,
        request_status=access_request.status,
        details=f"Quorum pending: {approved_count}/{required_approvals} approvals",
    )


def cast_approval_vote(
    db: Session,
    request_id: uuid.UUID,
    approver_id: uuid.UUID,
    decision: ApprovalDecision,
    reason: Optional[str] = None,
    allowed_roles: Optional[Set[str]] = None,
    allow_self_approval: bool = False,
    reject_on_single_rejection: bool = False,
) -> Tuple[Approval, QuorumResult]:
    """
    Validate and cast an approver's vote on an access request.

    Verifications performed:
    1. Request exists and is in PENDING status.
    2. Approver user exists and is active.
    3. Approver holds an authorized role (e.g. APPROVER, OFFICER, ADMIN).
    4. Separation of duties: Requester cannot approve their own request (unless allow_self_approval=True).
    5. Approver has not already voted on this request (duplicate vote prevention).
    6. Persists vote and re-evaluates quorum status.

    Args:
        db: SQLAlchemy database session.
        request_id: UUID of the AccessRequest.
        approver_id: UUID of the voting user.
        decision: ApprovalDecision.APPROVED or ApprovalDecision.REJECTED.
        reason: Optional justification for the vote.
        allowed_roles: Set of authorized roles (defaults to DEFAULT_APPROVER_ROLES).
        allow_self_approval: Whether requester can approve their own request (default False).
        reject_on_single_rejection: Whether a single REJECTED vote immediately denies the request.

    Returns:
        Tuple[Approval, QuorumResult]: The recorded Approval record and updated QuorumResult.

    Raises:
        QuorumValidationError: If request does not exist.
        RequestNotPendingError: If request is not PENDING.
        UnauthorizedApproverError: If approver is unknown or inactive.
        InvalidApproverRoleError: If approver lacks required role.
        SelfApprovalError: If requester attempts self-approval.
        DuplicateApprovalError: If approver attempts to vote twice.
    """
    # 1. Validate request existence and status
    access_request = db.get(AccessRequest, request_id)
    if not access_request:
        raise QuorumValidationError(f"Access request {request_id} not found")

    if access_request.status != RequestStatus.PENDING:
        raise RequestNotPendingError(
            f"Cannot cast vote on request {request_id} because its status is "
            f"'{access_request.status.value}'. Only PENDING requests accept votes."
        )

    # 2. Validate approver user existence and active status
    approver = db.get(User, approver_id)
    if not approver:
        raise UnauthorizedApproverError(f"Approver user with ID {approver_id} not found")
    if not approver.is_active:
        raise UnauthorizedApproverError(f"Approver user {approver_id} is inactive / disabled")

    # 3. Validate approver role
    roles_to_check = allowed_roles if allowed_roles is not None else DEFAULT_APPROVER_ROLES
    user_roles = get_user_role_names(db, approver_id)
    if not (user_roles & roles_to_check):
        raise InvalidApproverRoleError(
            f"User {approver_id} has roles {user_roles}, but requires one of {roles_to_check}"
        )

    # 4. Separation of duties check
    if not allow_self_approval and access_request.requested_by == approver_id:
        raise SelfApprovalError(
            f"User {approver_id} is the requester of request {request_id} "
            f"and cannot approve their own request under Separation of Duties policy"
        )

    # 5. Prevent duplicate voting
    existing_vote = (
        db.query(Approval)
        .filter(
            Approval.request_id == request_id,
            Approval.approved_by == approver_id,
        )
        .first()
    )
    if existing_vote:
        raise DuplicateApprovalError(
            f"User {approver_id} has already voted ({existing_vote.decision.value}) "
            f"on access request {request_id}"
        )

    # 6. Record vote
    vote = Approval(
        id=uuid.uuid4(),
        request_id=request_id,
        approved_by=approver_id,
        decision=decision,
        reason=reason,
        created_at=datetime.now(timezone.utc),
    )
    db.add(vote)
    db.flush()

    logger.info(
        "Vote cast on request %s by approver %s: %s",
        request_id,
        approver_id,
        decision.value,
    )

    # 7. Re-evaluate Quorum
    quorum_result = evaluate_quorum(
        db,
        request_id,
        reject_on_single_rejection=reject_on_single_rejection,
    )

    return vote, quorum_result


# ---------------------------------------------------------------------------
# Request Expiration and Administrative Actions
# ---------------------------------------------------------------------------

def expire_access_request(
    db: Session,
    request_id: uuid.UUID,
    reason: str = "Request timed out before quorum was reached",
) -> AccessRequest:
    """
    Explicitly expire a pending access request (e.g. timeout reached).

    Args:
        db: SQLAlchemy database session.
        request_id: UUID of the AccessRequest.
        reason: Optional audit reason.

    Returns:
        AccessRequest: The updated access request.

    Raises:
        RequestNotPendingError: If the request is not in PENDING state.
    """
    access_request = db.get(AccessRequest, request_id)
    if not access_request:
        raise QuorumValidationError(f"Access request {request_id} not found")

    if access_request.status != RequestStatus.PENDING:
        raise RequestNotPendingError(
            f"Cannot expire request in '{access_request.status.value}' state. "
            f"Only PENDING requests can be expired."
        )

    access_request.status = RequestStatus.EXPIRED
    access_request.decided_at = datetime.now(timezone.utc)

    # If paper was awaiting approval, revert paper to FRAGMENTED
    paper = db.get(QuestionPaper, access_request.paper_id)
    if paper and paper.status == PaperStatus.AWAITING_APPROVAL:
        paper.status = PaperStatus.FRAGMENTED

    db.flush()
    logger.info("Access request %s expired: %s", request_id, reason)
    return access_request


# ---------------------------------------------------------------------------
# Gatekeeper / Access Verification
# ---------------------------------------------------------------------------

def check_paper_access_authorization(
    db: Session,
    paper_id: uuid.UUID,
    request_id: Optional[uuid.UUID] = None,
) -> bool:
    """
    Verify whether a question paper is currently authorized for access via multi-party quorum.

    DEFAULT TO DENY: Returns False unless an approved request with valid quorum exists.

    Args:
        db: SQLAlchemy database session.
        paper_id: UUID of the QuestionPaper.
        request_id: Optional specific AccessRequest UUID to verify.

    Returns:
        bool: True if authorized, False otherwise.
    """
    paper = db.get(QuestionPaper, paper_id)
    if not paper:
        return False

    # Paper must be in AUTHORIZED or ACTIVE state
    if paper.status not in (PaperStatus.AUTHORIZED, PaperStatus.ACTIVE):
        return False

    if request_id is not None:
        access_request = db.get(AccessRequest, request_id)
        if not access_request or access_request.paper_id != paper_id:
            return False
        if access_request.status != RequestStatus.APPROVED:
            return False
        
        approved_count, _, required = calculate_quorum_counts(db, request_id)
        return approved_count >= required

    # If no specific request_id provided, check if any APPROVED request exists for this paper
    approved_requests = (
        db.query(AccessRequest)
        .filter(
            AccessRequest.paper_id == paper_id,
            AccessRequest.status == RequestStatus.APPROVED,
        )
        .all()
    )

    for req in approved_requests:
        approved_count, _, required = calculate_quorum_counts(db, req.id)
        if approved_count >= required:
            return True

    return False


def assert_paper_access_authorized(
    db: Session,
    paper_id: uuid.UUID,
    request_id: Optional[uuid.UUID] = None,
) -> None:
    """
    Assert that access to a question paper is authorized under multi-party quorum.

    Raises:
        AccessDeniedError: If quorum authorization is not satisfied.
    """
    if not check_paper_access_authorization(db, paper_id, request_id):
        raise AccessDeniedError(
            f"Access to QuestionPaper {paper_id} is DENIED. "
            f"Multi-party quorum authorization requirement not met."
        )
