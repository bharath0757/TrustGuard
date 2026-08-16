"""
TrustGuard — Quorum Authorization Abuse Cases & Controlled Stress Test Suite.

TEST MATRIX:
1.  Duplicate approval from same user
2.  Approval by unauthorized role
3.  Approval for wrong request
4.  Approval for wrong paper
5.  Approval after request expiry
6.  Approval after request completion
7.  Reuse of rejected approval
8.  Attempt to submit more approvals than required
9.  Attempt to manipulate approval count
10. Attempt to bypass quorum state (0/3, 1/3, 2/3 -> DENY, 3/3 -> ALLOW iff all conditions valid)

RULE ENFORCEMENT:
Only valid, authorized, non-duplicate approvals for the correct request count toward quorum.
2/3 -> DENY
3/3 -> ALLOW only if every other condition is valid
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import (
    AccessRequest,
    AccessWindow,
    Approval,
    ApprovalDecision,
    RequestStatus,
    RequestType,
    WindowStatus,
)
from database.models.audit import AuditLog, ThreatEvent, ThreatEventType, ThreatSeverity
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    create_access_request,
    cast_approval_vote,
    check_quorum,
    evaluate_quorum,
    calculate_quorum_counts,
    expire_access_request,
    check_paper_access_authorization,
    assert_paper_access_authorized,
    create_access_window,
    authorize_access,
    execute_jit_paper_access,
    complete_access_session,
    AccessDecision,
    QuorumDecision,
)
from security.quorum import (
    QuorumValidationError,
    UnauthorizedApproverError,
    InvalidApproverRoleError,
    DuplicateApprovalError,
    RequestNotPendingError,
    SelfApprovalError,
    AccessDeniedError,
)
from security.access_window import WindowScheduleError, JITAccessDeniedError
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from tests.fixtures import (
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    setup_all_synthetic_users,
)


@pytest.fixture
def db_session():
    """In-memory SQLite database session."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def quorum_test_env(db_session: Session):
    """Setup test fixture with officer, approvers, candidate, and protected paper."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Key Guardian Approver")
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="System Admin")
    r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Exam Candidate")
    db_session.add_all([r_officer, r_approver, r_admin, r_candidate])
    db_session.flush()

    def make_user(email: str, name: str, role: Role, is_active: bool = True) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
            full_name=name,
            is_active=is_active,
        )
        db_session.add(u)
        db_session.flush()
        db_session.add(UserRole(user_id=u.id, role_id=role.id))
        db_session.flush()
        return u

    officer = make_user("officer.lead@synth.local", "Lead Officer", r_officer)
    app1 = make_user("approver.one@synth.local", "Approver 1", r_approver)
    app2 = make_user("approver.two@synth.local", "Approver 2", r_approver)
    app3 = make_user("approver.three@synth.local", "Approver 3", r_approver)
    app4 = make_user("approver.four@synth.local", "Approver 4", r_approver)
    candidate = make_user("student.eve@synth.local", "Candidate Eve", r_candidate)
    inactive_approver = make_user("approver.inactive@synth.local", "Inactive Approver", r_approver, is_active=False)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="QUORUM-ABUSE-2026",
    )

    paper2, fragments2, master_key2 = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="SECOND-PAPER-2026",
    )

    return {
        "db": db_session,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "app3": app3,
        "app4": app4,
        "candidate": candidate,
        "inactive_approver": inactive_approver,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
        "paper2": paper2,
        "fragments2": fragments2,
        "master_key2": master_key2,
    }


# ===========================================================================
# SCENARIO 1: Duplicate approval from same user
# ===========================================================================

def test_abuse_01_duplicate_approval_from_same_user(quorum_test_env):
    """
    Scenario 1: Same approver attempts to cast multiple approval votes on the same request.
    Asserts: DuplicateApprovalError raised, only 1 vote counted, quorum remains PENDING.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
    assert req.status == RequestStatus.PENDING

    # First vote: Valid
    vote1, q_res1 = cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    assert vote1 is not None
    assert q_res1.approved_count == 1
    assert q_res1.is_authorized is False

    # Second vote by exact same approver: Blocked
    with pytest.raises(DuplicateApprovalError) as exc_info:
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    assert "already voted" in str(exc_info.value).lower()

    # Verify quorum was not manipulated
    approved, rejected, required = calculate_quorum_counts(db, req.id)
    assert approved == 1
    assert required == 3
    assert req.status == RequestStatus.PENDING


# ===========================================================================
# SCENARIO 2: Approval by unauthorized role
# ===========================================================================

def test_abuse_02_approval_by_unauthorized_role(quorum_test_env):
    """
    Scenario 2: User with unauthorized role (e.g. CANDIDATE) or inactive user attempts to approve.
    Asserts: InvalidApproverRoleError or UnauthorizedApproverError raised, zero votes counted.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    candidate = quorum_test_env["candidate"]
    inactive_app = quorum_test_env["inactive_approver"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)

    # 1. Candidate attempts approval -> InvalidApproverRoleError
    with pytest.raises(InvalidApproverRoleError) as exc_info:
        cast_approval_vote(db, req.id, candidate.id, ApprovalDecision.APPROVED)
    assert "requires one of" in str(exc_info.value).lower() or "role" in str(exc_info.value).lower()

    # 2. Inactive approver attempts approval -> UnauthorizedApproverError
    with pytest.raises(UnauthorizedApproverError) as exc_info:
        cast_approval_vote(db, req.id, inactive_app.id, ApprovalDecision.APPROVED)
    assert "inactive" in str(exc_info.value).lower() or "disabled" in str(exc_info.value).lower()

    # 3. Non-existent UUID attempts approval -> UnauthorizedApproverError
    fake_user_id = uuid.uuid4()
    with pytest.raises(UnauthorizedApproverError) as exc_info:
        cast_approval_vote(db, req.id, fake_user_id, ApprovalDecision.APPROVED)
    assert "not found" in str(exc_info.value).lower()

    approved, _, _ = calculate_quorum_counts(db, req.id)
    assert approved == 0


# ===========================================================================
# SCENARIO 3: Approval for wrong request
# ===========================================================================

def test_abuse_03_approval_for_wrong_request(quorum_test_env):
    """
    Scenario 3: Approver attempts to cast vote for a non-existent or arbitrary request ID.
    Asserts: QuorumValidationError raised, no records modified.
    """
    db: Session = quorum_test_env["db"]
    app1 = quorum_test_env["app1"]

    non_existent_req_id = uuid.uuid4()
    with pytest.raises(QuorumValidationError) as exc_info:
        cast_approval_vote(db, non_existent_req_id, app1.id, ApprovalDecision.APPROVED)
    assert "not found" in str(exc_info.value).lower()

    with pytest.raises(QuorumValidationError):
        calculate_quorum_counts(db, non_existent_req_id)

    with pytest.raises(QuorumValidationError):
        evaluate_quorum(db, non_existent_req_id)


# ===========================================================================
# SCENARIO 4: Approval for wrong paper
# ===========================================================================

def test_abuse_04_approval_for_wrong_paper(quorum_test_env):
    """
    Scenario 4: Approvals exist for Paper 1, but requester references Paper 1's request for Paper 2.
    Asserts: check_paper_access_authorization returns False, authorize_access returns DENY.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    app2 = quorum_test_env["app2"]
    app3 = quorum_test_env["app3"]
    paper1 = quorum_test_env["paper"]
    paper2 = quorum_test_env["paper2"]

    # Request 1 created for Paper 1 with 3 approvals
    req1 = create_access_request(db, paper_id=paper1.id, requested_by=officer.id, required_approvals=3)
    cast_approval_vote(db, req1.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req1.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req1.id, app3.id, ApprovalDecision.APPROVED)

    assert req1.status == RequestStatus.APPROVED
    assert check_paper_access_authorization(db, paper_id=paper1.id, request_id=req1.id) is True

    # Attempt to use Request 1 to authorize access to Paper 2 -> Must be DENIED
    is_paper2_authorized = check_paper_access_authorization(db, paper_id=paper2.id, request_id=req1.id)
    assert is_paper2_authorized is False

    with pytest.raises(AccessDeniedError):
        assert_paper_access_authorized(db, paper_id=paper2.id, request_id=req1.id)

    # authorize_access with mismatched request_id and paper_id -> DENY
    auth_res = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper2.id,
        request_id=req1.id,
        actor_ip="10.0.0.40",
    )
    assert auth_res.decision == AccessDecision.DENY
    assert auth_res.is_allowed is False
    assert "not found for target paper" in auth_res.reason.lower()


# ===========================================================================
# SCENARIO 5: Approval after request expiry
# ===========================================================================

def test_abuse_05_approval_after_request_expiry(quorum_test_env):
    """
    Scenario 5: Attempt to vote on an access request that has already expired.
    Asserts: RequestNotPendingError raised, evaluate_quorum returns DENIED.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
    expire_access_request(db, req.id, reason="Timeout before quorum reached")
    assert req.status == RequestStatus.EXPIRED

    # Attempt to vote on expired request
    with pytest.raises(RequestNotPendingError) as exc_info:
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    assert "expired" in str(exc_info.value).lower() or "only pending" in str(exc_info.value).lower()

    # Evaluation on expired request returns DENIED
    q_res = evaluate_quorum(db, req.id)
    assert q_res.decision == QuorumDecision.DENIED
    assert q_res.is_authorized is False
    assert q_res.request_status == RequestStatus.EXPIRED


# ===========================================================================
# SCENARIO 6: Approval after request completion
# ===========================================================================

def test_abuse_06_approval_after_request_completion(quorum_test_env):
    """
    Scenario 6: Attempt to cast approvals or reuse an access request after session completion.
    Asserts: RequestNotPendingError on voting, authorize_access returns DENY (replay prevented).
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    app2 = quorum_test_env["app2"]
    app3 = quorum_test_env["app3"]
    app4 = quorum_test_env["app4"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)

    now = datetime.now(timezone.utc)
    create_access_window(db, req.id, start_time=now - timedelta(minutes=5), end_time=now + timedelta(minutes=30))

    # Complete access session normally
    complete_access_session(db, paper_id=paper.id, request_id=req.id, actor_id=officer.id)
    assert req.status == RequestStatus.EXPIRED

    # Attempt to add a 4th approval to completed request
    with pytest.raises(RequestNotPendingError):
        cast_approval_vote(db, req.id, app4.id, ApprovalDecision.APPROVED)

    # Replay attempt using completed request -> DENY
    replay_auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id)
    assert replay_auth.decision == AccessDecision.DENY
    assert replay_auth.is_allowed is False


# ===========================================================================
# SCENARIO 7: Reuse of rejected approval
# ===========================================================================

def test_abuse_07_reuse_of_rejected_approval(quorum_test_env):
    """
    Scenario 7: Approver casts REJECTED. Later attempt to re-vote or count rejected votes toward quorum.
    Asserts: Rejected votes do not increment approved_count, re-voting is blocked by DuplicateApprovalError.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    app2 = quorum_test_env["app2"]
    app3 = quorum_test_env["app3"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)

    # Approver 1 casts REJECTED
    vote_rej, q_res1 = cast_approval_vote(db, req.id, app1.id, ApprovalDecision.REJECTED, reason="Suspected anomaly")
    assert vote_rej.decision == ApprovalDecision.REJECTED
    assert q_res1.approved_count == 0
    assert q_res1.rejected_count == 1

    # Approver 1 attempts to re-vote APPROVED -> DuplicateApprovalError
    with pytest.raises(DuplicateApprovalError):
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

    # Approvers 2 & 3 cast APPROVED -> total approvals is 2/3 (rejected does not count)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)

    approved, rejected, required = calculate_quorum_counts(db, req.id)
    assert approved == 2
    assert rejected == 1
    assert required == 3

    # 2/3 approved votes -> PENDING / DENY
    q_eval = evaluate_quorum(db, req.id)
    assert q_eval.is_authorized is False
    assert q_eval.decision == QuorumDecision.PENDING


# ===========================================================================
# SCENARIO 8: Attempt to submit more approvals than required
# ===========================================================================

def test_abuse_08_attempt_to_submit_more_approvals_than_required(quorum_test_env):
    """
    Scenario 8: Request requires k=3 approvals. Once k=3 is met (status -> APPROVED),
    attempt to submit a 4th approval vote.
    Asserts: RequestNotPendingError raised; request does not accept redundant votes.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    app2 = quorum_test_env["app2"]
    app3 = quorum_test_env["app3"]
    app4 = quorum_test_env["app4"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)

    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)

    assert req.status == RequestStatus.APPROVED

    # Approver 4 attempts to vote on already APPROVED request
    with pytest.raises(RequestNotPendingError) as exc_info:
        cast_approval_vote(db, req.id, app4.id, ApprovalDecision.APPROVED)
    assert "approved" in str(exc_info.value).lower()
    assert "only pending" in str(exc_info.value).lower()

    # Total recorded approvals remains exactly 3
    approved, _, _ = calculate_quorum_counts(db, req.id)
    assert approved == 3


# ===========================================================================
# SCENARIO 9: Attempt to manipulate approval count
# ===========================================================================

def test_abuse_09_attempt_to_manipulate_approval_count(quorum_test_env):
    """
    Scenario 9: Attempt to manipulate or forge approval counts by direct object alteration
    or unverified records.
    Asserts: calculate_quorum_counts and check_quorum query persisted verified Approval rows strictly.
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    app1 = quorum_test_env["app1"]
    paper = quorum_test_env["paper"]

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

    # Injected record for another request ID or invalid decision
    other_req_id = uuid.uuid4()
    forged_vote = Approval(
        id=uuid.uuid4(),
        request_id=other_req_id,
        approved_by=app1.id,
        decision=ApprovalDecision.APPROVED,
        created_at=datetime.now(timezone.utc),
    )
    db.add(forged_vote)
    db.flush()

    # check_quorum for req.id ignores forged record for other_req_id
    q_res = check_quorum(db, req.id)
    assert q_res.approved_count == 1
    assert q_res.is_authorized is False
    assert req.status == RequestStatus.PENDING


# ===========================================================================
# SCENARIO 10: Attempt to bypass quorum state (0/3, 1/3, 2/3 -> DENY; 3/3 -> ALLOW iff valid)
# ===========================================================================

def test_abuse_10_attempt_to_bypass_quorum_state(quorum_test_env):
    """
    Scenario 10: Full quorum progression test:
    - 0/3 -> DENY
    - 1/3 -> DENY
    - 2/3 -> DENY
    - 3/3 -> ALLOW only if every other condition is valid.
    Asserts:
      2/3 -> DENY
      3/3 -> ALLOW when all other conditions valid
      3/3 -> DENY if time window is invalid
      3/3 -> DENY if fragments are tampered
      3/3 -> DENY if actor is unauthorized candidate
    """
    db: Session = quorum_test_env["db"]
    officer = quorum_test_env["officer"]
    candidate = quorum_test_env["candidate"]
    app1 = quorum_test_env["app1"]
    app2 = quorum_test_env["app2"]
    app3 = quorum_test_env["app3"]
    paper = quorum_test_env["paper"]
    fragments = quorum_test_env["fragments"]
    master_key = quorum_test_env["master_key"]

    now = datetime.now(timezone.utc)

    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)

    # -------------------------------------------------------------------
    # Step 1: 0/3 Approvals -> DENY
    # -------------------------------------------------------------------
    q0 = check_quorum(db, req.id)
    assert q0.approved_count == 0
    assert q0.is_authorized is False
    assert req.status == RequestStatus.PENDING

    auth_0 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
    assert auth_0.decision == AccessDecision.DENY
    assert auth_0.is_allowed is False

    # -------------------------------------------------------------------
    # Step 2: 1/3 Approvals -> DENY
    # -------------------------------------------------------------------
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    q1 = check_quorum(db, req.id)
    assert q1.approved_count == 1
    assert q1.is_authorized is False
    assert req.status == RequestStatus.PENDING

    auth_1 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
    assert auth_1.decision == AccessDecision.DENY
    assert auth_1.is_allowed is False

    # -------------------------------------------------------------------
    # Step 3: 2/3 Approvals -> DENY
    # -------------------------------------------------------------------
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    q2 = check_quorum(db, req.id)
    assert q2.approved_count == 2
    assert q2.is_authorized is False
    assert req.status == RequestStatus.PENDING

    auth_2 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
    assert auth_2.decision == AccessDecision.DENY
    assert auth_2.is_allowed is False

    # Direct decryption at 2/3 is blocked
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)):
        execute_jit_paper_access(db, user_id=officer.id, paper_id=paper.id, key=master_key, request_id=req.id)

    # -------------------------------------------------------------------
    # Step 4: 3/3 Approvals -> Reaches Quorum
    # -------------------------------------------------------------------
    cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)
    q3 = check_quorum(db, req.id)
    assert q3.approved_count == 3
    assert q3.is_authorized is True
    assert req.status == RequestStatus.APPROVED

    # Schedule valid AccessWindow
    window = create_access_window(
        db=db,
        request_id=req.id,
        start_time=now - timedelta(minutes=10),
        end_time=now + timedelta(minutes=50),
        current_time=now,
    )
    assert window.status == WindowStatus.ACTIVE

    # 4a: 3/3 approvals + ALL valid conditions -> ALLOW
    auth_3_valid = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=now,
    )
    assert auth_3_valid.decision == AccessDecision.ALLOW
    assert auth_3_valid.is_allowed is True

    # Decryption succeeds when all conditions valid
    decrypted_bytes = execute_jit_paper_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        key=master_key,
        request_id=req.id,
        current_time=now,
    )
    assert decrypted_bytes == SYNTHETIC_DEMO_PAYLOAD

    # 4b: 3/3 approvals BUT time window is OUTSIDE (AFTER_WINDOW) -> DENY
    past_time = now + timedelta(hours=5)
    auth_3_expired_time = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=past_time,
    )
    assert auth_3_expired_time.decision == AccessDecision.DENY
    assert auth_3_expired_time.is_allowed is False
    assert "after_window" in auth_3_expired_time.reason.lower()

    # 4c: 3/3 approvals BUT actor is an unauthorized CANDIDATE -> DENY
    auth_3_candidate = authorize_access(
        db=db,
        user_id=candidate.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=now,
    )
    assert auth_3_candidate.decision == AccessDecision.DENY
    assert auth_3_candidate.is_allowed is False
    assert "lack authorized access roles" in auth_3_candidate.reason.lower()

    # 4d: 3/3 approvals BUT a shard is corrupted/tampered -> DENY
    original_frag_data = fragments[0].fragment_data
    fragments[0].fragment_data = b"TAMPERED_FRAGMENT_DATA_OVERWRITE"
    db.flush()

    auth_3_tampered = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=now,
    )
    assert auth_3_tampered.decision == AccessDecision.DENY
    assert auth_3_tampered.is_allowed is False
    assert "integrity check failed" in auth_3_tampered.reason.lower()

    # Restore fragment
    fragments[0].fragment_data = original_frag_data
    db.flush()


# ===========================================================================
# REST API QUORUM ABUSE VERIFICATION
# ===========================================================================

@pytest.mark.asyncio
async def test_api_consensus_duplicate_approval_rejected(async_client: AsyncClient):
    """
    REST API: Key Guardian attempts duplicate approval submission -> 400 Bad Request.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]

    # 1. Create exam & assign guardians
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
        headers=setter["headers"],
    )
    await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "RSA_4096_FP_G2"},
        headers=setter["headers"],
    )

    # 2. Stage payload
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )

    # 3. First approval: 200 OK
    app1_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert app1_res.status_code == 200

    # 4. Duplicate approval attempt by g1: 400 Bad Request
    dup_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert dup_res.status_code == 400
    assert "already submitted" in dup_res.json()["detail"].lower()
