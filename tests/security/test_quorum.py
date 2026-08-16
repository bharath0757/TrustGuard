"""
TrustGuard — Quorum Authorization & Multi-Party Approval Tests.

Comprehensive security test suite verifying:
  1. Quorum progression: 0/3, 1/3, 2/3, 3/3 approvals
  2. Unauthorized approver handling (unknown or inactive user)
  3. Duplicate approval prevention (same approver voting twice)
  4. Rejected vote handling (rejections do not count toward quorum)
  5. Expired request rejection (no votes accepted on expired requests)
  6. Invalid role rejection (users without authorized approver role)
  7. Repeated / completed request voting prevention (no voting on already approved requests)
  8. Separation of duties enforcement (requester cannot approve own request)
  9. Default-to-deny gatekeeper authorization checks
"""
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import (
    AccessRequest,
    Approval,
    ApprovalDecision,
    RequestStatus,
    RequestType,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.user import User, Role, UserRole
from security.quorum import (
    QuorumDecision,
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
    DuplicateApprovalError,
    RequestNotPendingError,
    SelfApprovalError,
    AccessDeniedError,
    create_access_request,
    calculate_quorum_counts,
    evaluate_quorum,
    cast_approval_vote,
    expire_access_request,
    check_paper_access_authorization,
    assert_paper_access_authorized,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """In-memory SQLite database session with fresh schema for each test."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def test_setup(db_session: Session):
    """
    Sets up roles, users, and a test QuestionPaper:
    - Roles: ADMIN, OFFICER, APPROVER, AUDITOR
    - Requester: requester_user (Role: OFFICER)
    - Approvers: officer_a, officer_b, officer_c (Role: APPROVER / OFFICER)
    - Auditor: auditor_user (Role: AUDITOR)
    - Inactive: inactive_officer (Role: OFFICER, is_active=False)
    - Paper: question_paper (Status: FRAGMENTED)
    """
    # 1. Create Roles
    role_admin = Role(id=uuid.uuid4(), name="ADMIN", description="Administrator")
    role_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    role_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Authorized Approver")
    role_auditor = Role(id=uuid.uuid4(), name="AUDITOR", description="Auditor")
    db_session.add_all([role_admin, role_officer, role_approver, role_auditor])
    db_session.flush()

    # 2. Create Users
    def make_user(email: str, name: str, role: Role, is_active: bool = True) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash="fake_hash",
            full_name=name,
            is_active=is_active,
        )
        db_session.add(u)
        db_session.flush()
        ur = UserRole(user_id=u.id, role_id=role.id)
        db_session.add(ur)
        db_session.flush()
        return u

    requester = make_user("requester@trustguard.org", "Exam Requester", role_officer)
    officer_a = make_user("officer_a@trustguard.org", "Officer Alice", role_approver)
    officer_b = make_user("officer_b@trustguard.org", "Officer Bob", role_approver)
    officer_c = make_user("officer_c@trustguard.org", "Officer Charlie", role_officer)
    auditor = make_user("auditor@trustguard.org", "Auditor Dan", role_auditor)
    inactive_officer = make_user("inactive@trustguard.org", "Officer Inactive", role_approver, is_active=False)

    # 3. Create QuestionPaper
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="GATE-2026-CS",
        paper_name="Computer Science & Engineering",
        status=PaperStatus.FRAGMENTED,
        total_fragments=5,
    )
    db_session.add(paper)
    db_session.commit()

    return {
        "paper": paper,
        "requester": requester,
        "officer_a": officer_a,
        "officer_b": officer_b,
        "officer_c": officer_c,
        "auditor": auditor,
        "inactive_officer": inactive_officer,
    }


# ---------------------------------------------------------------------------
# 1. Quorum Progression Tests (0/3 -> 1/3 -> 2/3 -> 3/3)
# ---------------------------------------------------------------------------

def test_quorum_progression_0_to_3(db_session: Session, test_setup: dict):
    """Verify Quorum calculation and authorization progression through 0/3, 1/3, 2/3, and 3/3."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]
    officer_b = test_setup["officer_b"]
    officer_c = test_setup["officer_c"]

    # Step 0: Create Access Request with required_approvals = 3
    req = create_access_request(
        db=db_session,
        paper_id=paper.id,
        requested_by=requester.id,
        required_approvals=3,
        reason="Conducting exam session",
    )
    db_session.commit()

    assert req.status == RequestStatus.PENDING
    assert paper.status == PaperStatus.AWAITING_APPROVAL

    # State: 0/3 Approvals
    approved, rejected, required = calculate_quorum_counts(db_session, req.id)
    assert approved == 0
    assert rejected == 0
    assert required == 3
    q_result = evaluate_quorum(db_session, req.id)
    assert q_result.decision == QuorumDecision.PENDING
    assert not q_result.is_authorized
    assert not check_paper_access_authorization(db_session, paper.id, req.id)

    # Step 1: Officer A Approves (1/3)
    _, res1 = cast_approval_vote(
        db=db_session,
        request_id=req.id,
        approver_id=officer_a.id,
        decision=ApprovalDecision.APPROVED,
        reason="Officer A verified identity",
    )
    db_session.commit()

    assert res1.approved_count == 1
    assert res1.decision == QuorumDecision.PENDING
    assert not res1.is_authorized
    assert req.status == RequestStatus.PENDING
    assert paper.status == PaperStatus.AWAITING_APPROVAL
    assert not check_paper_access_authorization(db_session, paper.id, req.id)

    # Step 2: Officer B Approves (2/3)
    _, res2 = cast_approval_vote(
        db=db_session,
        request_id=req.id,
        approver_id=officer_b.id,
        decision=ApprovalDecision.APPROVED,
        reason="Officer B verified schedule",
    )
    db_session.commit()

    assert res2.approved_count == 2
    assert res2.decision == QuorumDecision.PENDING
    assert not res2.is_authorized
    assert req.status == RequestStatus.PENDING
    assert paper.status == PaperStatus.AWAITING_APPROVAL
    assert not check_paper_access_authorization(db_session, paper.id, req.id)

    # Step 3: Officer C Approves (3/3 -> QUORUM REACHED!)
    _, res3 = cast_approval_vote(
        db=db_session,
        request_id=req.id,
        approver_id=officer_c.id,
        decision=ApprovalDecision.APPROVED,
        reason="Officer C final authorization",
    )
    db_session.commit()

    assert res3.approved_count == 3
    assert res3.decision == QuorumDecision.AUTHORIZED
    assert res3.is_authorized
    assert req.status == RequestStatus.APPROVED
    assert req.decided_at is not None
    assert paper.status == PaperStatus.AUTHORIZED

    # Gatekeeper check now passes
    assert check_paper_access_authorization(db_session, paper.id, req.id)
    assert_paper_access_authorized(db_session, paper.id, req.id)


# ---------------------------------------------------------------------------
# 2. Unauthorized Approver (Inactive / Non-existent User)
# ---------------------------------------------------------------------------

def test_unauthorized_inactive_approver(db_session: Session, test_setup: dict):
    """Inactive/disabled users cannot cast approval votes."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    inactive_officer = test_setup["inactive_officer"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    with pytest.raises(UnauthorizedApproverError, match="inactive / disabled"):
        cast_approval_vote(
            db=db_session,
            request_id=req.id,
            approver_id=inactive_officer.id,
            decision=ApprovalDecision.APPROVED,
        )


def test_nonexistent_approver(db_session: Session, test_setup: dict):
    """Non-existent approver user UUID raises UnauthorizedApproverError."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    fake_user_id = uuid.uuid4()

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    with pytest.raises(UnauthorizedApproverError, match="not found"):
        cast_approval_vote(
            db=db_session,
            request_id=req.id,
            approver_id=fake_user_id,
            decision=ApprovalDecision.APPROVED,
        )


# ---------------------------------------------------------------------------
# 3. Duplicate Approval Prevention
# ---------------------------------------------------------------------------

def test_duplicate_approval_prevention(db_session: Session, test_setup: dict):
    """An approver cannot cast more than one vote on the same access request."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    # First vote succeeds
    cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)
    db_session.commit()

    # Second vote from the same user fails
    with pytest.raises(DuplicateApprovalError, match="already voted"):
        cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)


# ---------------------------------------------------------------------------
# 4. Rejected Approval Handling
# ---------------------------------------------------------------------------

def test_rejected_approval_does_not_count_towards_quorum(db_session: Session, test_setup: dict):
    """A REJECTED vote does not increment approved_count and prevents reaching quorum."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]
    officer_b = test_setup["officer_b"]
    officer_c = test_setup["officer_c"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    # Officer A: APPROVED
    cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)
    # Officer B: REJECTED
    cast_approval_vote(db_session, req.id, officer_b.id, ApprovalDecision.REJECTED, reason="Security anomaly detected")
    # Officer C: APPROVED
    _, res = cast_approval_vote(db_session, req.id, officer_c.id, ApprovalDecision.APPROVED)
    db_session.commit()

    # Total approved = 2/3, rejected = 1 -> Quorum NOT met
    assert res.approved_count == 2
    assert res.rejected_count == 1
    assert res.decision == QuorumDecision.PENDING
    assert not res.is_authorized
    assert req.status == RequestStatus.PENDING
    assert not check_paper_access_authorization(db_session, paper.id, req.id)


def test_reject_on_single_rejection_policy(db_session: Session, test_setup: dict):
    """When reject_on_single_rejection is enabled, a single REJECTED vote transitions request to REJECTED."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]
    officer_b = test_setup["officer_b"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)
    _, res = cast_approval_vote(
        db=db_session,
        request_id=req.id,
        approver_id=officer_b.id,
        decision=ApprovalDecision.REJECTED,
        reject_on_single_rejection=True,
    )
    db_session.commit()

    assert res.decision == QuorumDecision.DENIED
    assert req.status == RequestStatus.REJECTED
    assert not check_paper_access_authorization(db_session, paper.id, req.id)


# ---------------------------------------------------------------------------
# 5. Expired Request Rejection
# ---------------------------------------------------------------------------

def test_expired_request_rejects_votes(db_session: Session, test_setup: dict):
    """Votes cannot be cast on an expired access request."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    # Expire the request
    expire_access_request(db_session, req.id, reason="Timeout reached")
    db_session.commit()

    assert req.status == RequestStatus.EXPIRED

    # Attempt to vote on expired request
    with pytest.raises(RequestNotPendingError, match="EXPIRED"):
        cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)


# ---------------------------------------------------------------------------
# 6. Invalid Approver Role
# ---------------------------------------------------------------------------

def test_invalid_role_cannot_approve(db_session: Session, test_setup: dict):
    """Users without an authorized approver role (e.g. AUDITOR) cannot cast approval votes."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    auditor = test_setup["auditor"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    with pytest.raises(InvalidApproverRoleError, match="requires one of"):
        cast_approval_vote(db_session, req.id, auditor.id, ApprovalDecision.APPROVED)


# ---------------------------------------------------------------------------
# 7. Repeated / Already Completed Request
# ---------------------------------------------------------------------------

def test_already_approved_request_cannot_receive_more_votes(db_session: Session, test_setup: dict):
    """Once quorum is met and request is APPROVED, further votes are rejected."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]
    officer_b = test_setup["officer_b"]
    officer_c = test_setup["officer_c"]

    # 2 required approvals
    req = create_access_request(db_session, paper.id, requester.id, required_approvals=2)
    db_session.commit()

    cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, officer_b.id, ApprovalDecision.APPROVED)
    db_session.commit()

    assert req.status == RequestStatus.APPROVED

    # Officer C attempts to vote after completion
    with pytest.raises(RequestNotPendingError, match="APPROVED"):
        cast_approval_vote(db_session, req.id, officer_c.id, ApprovalDecision.APPROVED)


# ---------------------------------------------------------------------------
# 8. Separation of Duties (Self-Approval Restriction)
# ---------------------------------------------------------------------------

def test_separation_of_duties_self_approval_blocked(db_session: Session, test_setup: dict):
    """A requester cannot approve their own request by default."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=3)
    db_session.commit()

    with pytest.raises(SelfApprovalError, match="cannot approve their own request"):
        cast_approval_vote(db_session, req.id, requester.id, ApprovalDecision.APPROVED)


# ---------------------------------------------------------------------------
# 9. Gatekeeper Authorization Checks
# ---------------------------------------------------------------------------

def test_gatekeeper_assert_paper_access_authorized(db_session: Session, test_setup: dict):
    """Access gatekeeper enforces multi-party quorum before granting access."""
    paper = test_setup["paper"]
    requester = test_setup["requester"]
    officer_a = test_setup["officer_a"]
    officer_b = test_setup["officer_b"]

    req = create_access_request(db_session, paper.id, requester.id, required_approvals=2)
    db_session.commit()

    # Prior to quorum -> Denied
    assert not check_paper_access_authorization(db_session, paper.id, req.id)
    with pytest.raises(AccessDeniedError, match="DENIED"):
        assert_paper_access_authorized(db_session, paper.id, req.id)

    # After full quorum -> Authorized
    cast_approval_vote(db_session, req.id, officer_a.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db_session, req.id, officer_b.id, ApprovalDecision.APPROVED)
    db_session.commit()

    assert check_paper_access_authorization(db_session, paper.id, req.id)
    # Should not raise exception
    assert_paper_access_authorized(db_session, paper.id, req.id)
