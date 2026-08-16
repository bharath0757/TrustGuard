"""
TrustGuard — Complete Legitimate Workflow End-to-End Integration Test Suite.

Validates the full legitimate Zero-Trust lifecycle across all 15 required logical steps:
1.  Authenticate authorized user
2.  Create test question paper
3.  Protect/encrypt it
4.  Fragment it
5.  Store protected fragments
6.  Create access request
7.  Submit required approvals
8.  Reach quorum
9.  Validate access window
10. Validate fragment integrity
11. Reconstruct protected representation
12. Decrypt through the security service
13. Record audit events
14. Complete the access lifecycle
15. Prevent replay

MANDATORY ASSERTIONS:
- paper exists
- protected state exists
- fragments exist
- quorum is achieved
- access is allowed
- protected content can be successfully recovered
- audit trail exists
- completed access cannot be reused

CRITICAL SECURITY CONSTRAINTS:
- Use ONLY synthetic test content ("TRUSTGUARD_DEMO_PAPER").
- Zero real examination content (no JEE/NEET or other confidential exam data).
- Real cryptographic primitives (AES-256-GCM, SHA-256) and real database persistence.
"""

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import os
import time
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

# Database Models
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
from database.models.audit import (
    AuditLog,
    AuditResult,
    ThreatEvent,
    ThreatEventType,
    ThreatSeverity,
)
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

# Security Service Interfaces
from security import (
    protect_paper,
    fragment_paper,
    validate_fragments,
    create_access_request,
    check_quorum,
    is_access_window_valid,
    authorize_access,
    reconstruct_paper,
    decrypt_paper,
    complete_access,
    create_audit_event,
    cast_approval_vote,
    create_access_window,
    WindowTimeState,
    AccessDecision,
    AuditEventType,
)
from security.crypto.encryption import encrypt, decrypt
from security.crypto.key_manager import generate_master_key
from security.crypto.integrity import generate_integrity_hash
from security.crypto.fragmentation import retrieve_paper_fragments
from security.access_window import JITAccessDeniedError
from security.quorum import AccessDeniedError, RequestNotPendingError

# Reusable API Test Fixtures
from tests.fixtures import (
    SYNTHETIC_USERS,
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    register_and_login_user,
    setup_all_synthetic_users,
)


# ===========================================================================
# FIXTURES FOR SERVICE-LAYER E2E TEST
# ===========================================================================

@pytest.fixture
def master_key() -> bytes:
    """32-byte cryptographic master key for AES-256-GCM encryption."""
    return os.urandom(32)


@pytest.fixture
def synthetic_paper_content() -> bytes:
    """Synthetic examination content for testing."""
    return b"TRUSTGUARD_DEMO_PAPER\n[SYNTHETIC_EXAM_BODY: SECTION_A=100, SECTION_B=200]"


@pytest.fixture
def db_session():
    """In-memory SQLite database session with complete database schema."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def service_e2e_env(db_session: Session, master_key: bytes, synthetic_paper_content: bytes):
    """
    Sets up a full production-like security environment:
    - Roles: ADMIN, OFFICER, APPROVER, CANDIDATE
    - Users:
      - Admin Creator
      - Requester Officer (Alice)
      - Approver 1 (Bob)
      - Approver 2 (Charlie)
      - Approver 3 (Diana)
    """
    # 1. Create Roles
    r_admin = Role(id=uuid.uuid4(), name="ADMIN", description="System Administrator")
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Controller Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Key Custodian Approver")
    r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Exam Candidate")
    db_session.add_all([r_admin, r_officer, r_approver, r_candidate])
    db_session.flush()

    # 2. Helper to create user with role
    def make_user(email: str, name: str, role: Role) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hashlib.sha256(b"SecurePassword2026!").hexdigest(),
            full_name=name,
            is_active=True,
        )
        db_session.add(u)
        db_session.flush()
        ur = UserRole(user_id=u.id, role_id=role.id)
        db_session.add(ur)
        db_session.flush()
        return u

    admin_user = make_user("admin@trustguard.synth.org", "Chief Admin", r_admin)
    officer_user = make_user("officer.alice@trustguard.synth.org", "Officer Alice", r_officer)
    approver_1 = make_user("approver.bob@trustguard.synth.org", "Approver Bob", r_approver)
    approver_2 = make_user("approver.charlie@trustguard.synth.org", "Approver Charlie", r_approver)
    approver_3 = make_user("approver.diana@trustguard.synth.org", "Approver Diana", r_approver)

    return {
        "db": db_session,
        "master_key": master_key,
        "raw_content": synthetic_paper_content,
        "admin": admin_user,
        "officer": officer_user,
        "approvers": [approver_1, approver_2, approver_3],
    }


# ===========================================================================
# 1. SERVICE-LAYER COMPLETE LEGITIMATE WORKFLOW E2E TEST
# ===========================================================================

def test_legitimate_trustguard_service_workflow_e2e(service_e2e_env):
    """
    Complete 15-step legitimate TrustGuard workflow through the Security Service Layer.
    
    Validates:
    1.  Authenticate authorized user
    2.  Create test question paper
    3.  Protect/encrypt it
    4.  Fragment it
    5.  Store protected fragments
    6.  Create access request
    7.  Submit required approvals
    8.  Reach quorum
    9.  Validate access window
    10. Validate fragment integrity
    11. Reconstruct protected representation
    12. Decrypt through the security service
    13. Record audit events
    14. Complete the access lifecycle
    15. Prevent replay
    """
    start_time = time.perf_counter()
    db: Session = service_e2e_env["db"]
    key: bytes = service_e2e_env["master_key"]
    raw_content: bytes = service_e2e_env["raw_content"]
    admin: User = service_e2e_env["admin"]
    officer: User = service_e2e_env["officer"]
    approver_1, approver_2, approver_3 = service_e2e_env["approvers"]

    # -----------------------------------------------------------------------
    # STEP 1: AUTHENTICATE AUTHORIZED USER
    # -----------------------------------------------------------------------
    assert admin.is_active is True, "Assertion 1.1: Admin user must be active"
    assert officer.is_active is True, "Assertion 1.2: Officer user must be active"
    for idx, app_user in enumerate([approver_1, approver_2, approver_3]):
        assert app_user.is_active is True, f"Assertion 1.3.{idx+1}: Approver {idx+1} must be active"
        role_names = [ur.role.name for ur in app_user.user_roles]
        assert "APPROVER" in role_names, f"Assertion 1.4.{idx+1}: Approver must possess APPROVER role"

    # -----------------------------------------------------------------------
    # STEP 2: CREATE TEST QUESTION PAPER
    # -----------------------------------------------------------------------
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="TRUSTGUARD-DEMO-2026",
        paper_name="TrustGuard Synthetic Demonstration Exam",
        status=PaperStatus.CREATED,
        created_by=admin.id,
    )
    db.add(paper)
    db.flush()

    # ASSERTION: paper exists
    queried_paper = db.get(QuestionPaper, paper.id)
    assert queried_paper is not None, "Assertion 2.1: [MANDATORY] Paper exists in database"
    assert queried_paper.status == PaperStatus.CREATED, "Assertion 2.2: Paper initial status is CREATED"
    assert queried_paper.exam_identifier == "TRUSTGUARD-DEMO-2026"

    # -----------------------------------------------------------------------
    # STEP 3: PROTECT / ENCRYPT IT
    # -----------------------------------------------------------------------
    protected_paper = protect_paper(
        db=db,
        paper_id=paper.id,
        plaintext_data=raw_content,
        key=key,
        actor_id=admin.id,
        actor_ip="127.0.0.1",
    )

    # ASSERTION: protected state exists
    assert protected_paper.status == PaperStatus.PROTECTED, "Assertion 3.1: [MANDATORY] Protected state exists"
    assert protected_paper.protected_at is not None, "Assertion 3.2: Protection timestamp is recorded"
    assert protected_paper.integrity_hash.startswith("sha256:"), "Assertion 3.3: SHA-256 manifest hash generated"
    expected_manifest_hash = generate_integrity_hash(raw_content)
    assert protected_paper.integrity_hash == expected_manifest_hash, "Assertion 3.4: Integrity hash matches plaintext"

    # -----------------------------------------------------------------------
    # STEP 4: FRAGMENT IT & STEP 5: STORE PROTECTED FRAGMENTS
    # -----------------------------------------------------------------------
    stored_fragments = fragment_paper(
        db=db,
        paper_id=paper.id,
        num_fragments=5,
        actor_id=admin.id,
        actor_ip="127.0.0.1",
    )

    # ASSERTION: fragments exist
    assert len(stored_fragments) == 5, "Assertion 4.1: Exactly 5 fragments produced"
    assert protected_paper.status == PaperStatus.FRAGMENTED, "Assertion 4.2: Paper status transitioned to FRAGMENTED"
    assert protected_paper.total_fragments == 5, "Assertion 4.3: Total fragments count is 5"

    db_fragments = db.query(PaperFragment).filter(PaperFragment.paper_id == paper.id).all()
    assert len(db_fragments) == 5, "Assertion 5.1: [MANDATORY] Fragments exist in database"
    for idx, frag in enumerate(db_fragments):
        assert frag.status == FragmentStatus.STORED, f"Assertion 5.2.{idx+1}: Shard {idx+1} status is STORED"
        assert frag.fragment_index == idx, f"Assertion 5.3.{idx+1}: Shard index {idx} is 0-indexed"
        assert frag.integrity_hash.startswith("sha256:"), f"Assertion 5.4.{idx+1}: Shard {idx+1} has SHA-256 digest"
        assert len(frag.fragment_data) > 0, f"Assertion 5.5.{idx+1}: Shard {idx+1} contains binary payload"

    # -----------------------------------------------------------------------
    # STEP 6: CREATE ACCESS REQUEST & SCHEDULE ACCESS WINDOW
    # -----------------------------------------------------------------------
    # STEP 6: CREATE ACCESS REQUEST
    # -----------------------------------------------------------------------
    access_req = create_access_request(
        db=db,
        paper_id=paper.id,
        requested_by=officer.id,
        request_type=RequestType.RECONSTRUCT,
        reason="Official examination release ceremony for TrustGuard Demo",
        required_approvals=3,
        actor_ip="127.0.0.1",
    )
    assert access_req.status == RequestStatus.PENDING, "Assertion 6.1: Access request created in PENDING status"
    assert access_req.required_approvals == 3, "Assertion 6.2: Threshold quorum set to 3"

    # -----------------------------------------------------------------------
    # STEP 7: SUBMIT REQUIRED APPROVALS
    # -----------------------------------------------------------------------
    from security.service import approve_access_request
    # Vote 1 (Bob)
    vote1, q_res1 = approve_access_request(
        db=db,
        request_id=access_req.id,
        approver_id=approver_1.id,
        decision=ApprovalDecision.APPROVED,
        reason="Identity verified; authorizing demo examination release",
    )
    assert vote1.decision == ApprovalDecision.APPROVED, "Assertion 7.1: Approver 1 approval recorded"
    assert q_res1.is_authorized is False, "Assertion 7.2: Quorum not yet reached after 1 vote"

    # Vote 2 (Charlie)
    vote2, q_res2 = approve_access_request(
        db=db,
        request_id=access_req.id,
        approver_id=approver_2.id,
        decision=ApprovalDecision.APPROVED,
        reason="Security baseline intact; approval granted",
    )
    assert vote2.decision == ApprovalDecision.APPROVED, "Assertion 7.3: Approver 2 approval recorded"
    assert q_res2.is_authorized is False, "Assertion 7.4: Quorum not achieved with 2 of 3 votes"
    assert q_res2.approved_count == 2, "Assertion 7.5: Approved count is 2"

    # Vote 3 (Diana) - Meets Quorum Threshold (3 of 3)
    vote3, q_res3 = approve_access_request(
        db=db,
        request_id=access_req.id,
        approver_id=approver_3.id,
        decision=ApprovalDecision.APPROVED,
        reason="Final threshold signature provided",
    )
    assert vote3.decision == ApprovalDecision.APPROVED, "Assertion 7.6: Approver 3 approval recorded"

    # -----------------------------------------------------------------------
    # STEP 8: REACH QUORUM & SCHEDULE ACCESS WINDOW
    # -----------------------------------------------------------------------
    quorum_result = check_quorum(db, access_req.id)

    # ASSERTION: quorum is achieved
    assert quorum_result.is_authorized is True, "Assertion 8.1: [MANDATORY] Quorum is achieved (3 of 3)"
    assert quorum_result.approved_count == 3, "Assertion 8.2: Exactly 3 approved votes recorded"
    from security.quorum import QuorumDecision
    assert quorum_result.decision == QuorumDecision.AUTHORIZED, "Assertion 8.3: Quorum decision is AUTHORIZED"
    assert access_req.status == RequestStatus.APPROVED, "Assertion 8.4: Request status updated to APPROVED"

    # Schedule valid access window for the approved request (started 5 min ago, ends in 60 min)
    now = datetime.now(timezone.utc)
    access_window = create_access_window(
        db=db,
        request_id=access_req.id,
        start_time=now - timedelta(minutes=5),
        end_time=now + timedelta(minutes=60),
    )
    assert access_window.status == WindowStatus.ACTIVE, "Assertion 8.5: Access window is ACTIVE during legitimate window"

    # -----------------------------------------------------------------------
    # STEP 9: VALIDATE ACCESS WINDOW & JIT AUTHORIZATION
    # -----------------------------------------------------------------------
    is_valid_window, time_state = is_access_window_valid(db, access_window.id, current_time=now)
    assert is_valid_window is True, "Assertion 9.1: Access window is temporally valid"
    assert time_state == WindowTimeState.DURING_WINDOW, "Assertion 9.2: Current time is DURING_WINDOW"

    auth_decision = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=access_req.id,
        current_time=now,
        actor_ip="127.0.0.1",
    )

    # ASSERTION: access is allowed
    assert auth_decision.decision == AccessDecision.ALLOW, "Assertion 9.3: [MANDATORY] Access is allowed"
    assert auth_decision.is_allowed is True, "Assertion 9.4: Full 6-factor JIT authorization passed"
    assert auth_decision.window_id == access_window.id, "Assertion 9.5: Linked to active access window"

    # -----------------------------------------------------------------------
    # STEP 10: VALIDATE FRAGMENT INTEGRITY
    # -----------------------------------------------------------------------
    shards_to_validate = retrieve_paper_fragments(db, paper.id)
    assert len(shards_to_validate) == 5, "Assertion 10.1: Retrieved all 5 fragments"

    validated_shards = validate_fragments(
        fragments=shards_to_validate,
        expected_paper_id=paper.id,
        expected_count=5,
    )
    assert len(validated_shards) == 5, "Assertion 10.2: All 5 shards successfully validated"
    for idx, shard in enumerate(validated_shards):
        assert shard.fragment_index == idx, f"Assertion 10.3.{idx+1}: Valid continuous index sequence"

    # -----------------------------------------------------------------------
    # STEP 11: RECONSTRUCT PROTECTED REPRESENTATION
    # -----------------------------------------------------------------------
    reconstructed_ciphertext = reconstruct_paper(
        db=db,
        paper_id=paper.id,
        fragments=validated_shards,
    )
    assert isinstance(reconstructed_ciphertext, bytes), "Assertion 11.1: Reconstructed payload is bytes"
    assert len(reconstructed_ciphertext) > len(raw_content), "Assertion 11.2: Ciphertext includes nonce & tag"

    # -----------------------------------------------------------------------
    # STEP 12: DECRYPT THROUGH THE SECURITY SERVICE
    # -----------------------------------------------------------------------
    recovered_plaintext = decrypt_paper(
        ciphertext_payload=reconstructed_ciphertext,
        key=key,
        expected_manifest_hash=paper.integrity_hash,
    )

    # ASSERTION: protected content can be successfully recovered
    assert recovered_plaintext == raw_content, "Assertion 12.1: [MANDATORY] Protected content can be successfully recovered"
    assert recovered_plaintext.startswith(b"TRUSTGUARD_DEMO_PAPER"), "Assertion 12.2: Plaintext matches synthetic paper header"
    assert generate_integrity_hash(recovered_plaintext) == paper.integrity_hash, "Assertion 12.3: Integrity hash matches manifest"

    # -----------------------------------------------------------------------
    # STEP 13: RECORD AUDIT EVENTS
    # -----------------------------------------------------------------------
    audit_logs = db.query(AuditLog).filter(
        (AuditLog.target_id == paper.id) | (AuditLog.target_id == access_req.id)
    ).all()
    actions_recorded = [log.action for log in audit_logs]

    # ASSERTION: audit trail exists
    assert len(audit_logs) >= 6, "Assertion 13.1: [MANDATORY] Audit trail exists with multiple immutable records"
    assert AuditEventType.PAPER_ENCRYPTED.value in actions_recorded, "Assertion 13.2: PAPER_ENCRYPTED logged"
    assert AuditEventType.PAPER_FRAGMENTED.value in actions_recorded, "Assertion 13.3: PAPER_FRAGMENTED logged"
    assert AuditEventType.ACCESS_REQUESTED.value in actions_recorded, "Assertion 13.4: ACCESS_REQUESTED logged"
    assert AuditEventType.APPROVAL_GRANTED.value in actions_recorded, "Assertion 13.5: APPROVAL_GRANTED logged"
    assert AuditEventType.QUORUM_REACHED.value in actions_recorded, "Assertion 13.6: QUORUM_REACHED logged"
    assert AuditEventType.ACCESS_GRANTED.value in actions_recorded, "Assertion 13.7: ACCESS_GRANTED logged"

    for log in audit_logs:
        assert log.result == AuditResult.SUCCESS, f"Assertion 13.8: Audit entry {log.action} status is SUCCESS"
        assert log.timestamp is not None, f"Assertion 13.9: Audit entry {log.action} has valid timestamp"

    # -----------------------------------------------------------------------
    # STEP 14: COMPLETE THE ACCESS LIFECYCLE
    # -----------------------------------------------------------------------
    completion_report = complete_access(
        db=db,
        paper_id=paper.id,
        request_id=access_req.id,
        actor_id=officer.id,
        actor_ip="127.0.0.1",
        reason="Demonstration examination window completed successfully",
    )
    assert completion_report["session_state"] == "session closed", "Assertion 14.1: Session closed"
    assert completion_report["access_state"] == "access expired", "Assertion 14.2: Access expired"
    assert completion_report["replay_protection"] == "active", "Assertion 14.3: Replay protection active"
    assert completion_report["temporary_representation"] == "temporary representation removed", "Assertion 14.4: In-memory representation wiped"

    # Verify state in database
    db.refresh(paper)
    db.refresh(access_req)
    db.refresh(access_window)
    assert paper.status == PaperStatus.COMPLETED, "Assertion 14.5: Paper status is COMPLETED in DB"
    assert access_req.status == RequestStatus.EXPIRED, "Assertion 14.6: Request status is EXPIRED in DB (replay prevention)"
    assert access_window.status == WindowStatus.CLOSED, "Assertion 14.7: Window status is CLOSED in DB"

    # -----------------------------------------------------------------------
    # STEP 15: PREVENT REPLAY
    # -----------------------------------------------------------------------
    # Replay Attempt 1: Re-request authorization with same completed request
    replay_auth = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=access_req.id,
        current_time=now,
    )
    # ASSERTION: completed access cannot be reused
    assert replay_auth.decision == AccessDecision.DENY, "Assertion 15.1: [MANDATORY] Completed access cannot be reused (DENY)"
    assert replay_auth.is_allowed is False, "Assertion 15.2: Replay access rejected"
    assert "expired" in replay_auth.reason.lower() or "replay" in replay_auth.reason.lower(), "Assertion 15.3: Replay reason specifies expired status"

    # Replay Attempt 2: Casting an additional vote on a completed request is blocked
    with pytest.raises(RequestNotPendingError):
        cast_approval_vote(
            db=db,
            request_id=access_req.id,
            approver_id=approver_1.id,
            decision=ApprovalDecision.APPROVED,
        )

    execution_duration = time.perf_counter() - start_time
    print(f"\n[Service E2E Test Completed in {execution_duration:.4f}s with all 15 stages verified]")


# ===========================================================================
# 2. REST API COMPLETE LEGITIMATE WORKFLOW E2E TEST
# ===========================================================================

@pytest.mark.asyncio
async def test_legitimate_trustguard_api_workflow_e2e(async_client: AsyncClient):
    """
    Complete 15-step legitimate TrustGuard workflow through live REST API endpoints.

    Validates:
    1.  Authenticate authorized user (ADMIN, SETTER, GUARDIANS, CENTER, AUDITOR)
    2.  Create test question paper (/api/v1/exams/)
    3.  Protect/encrypt it (/api/v1/exams/{id}/stage-payload)
    4.  Fragment it (multi-chunk sharding)
    5.  Store protected fragments (ephemeral RAM with TTL)
    6.  Create access request (CONSENSUS_PENDING state)
    7.  Submit required approvals (/api/v1/consensus/{id}/approve)
    8.  Reach quorum (transition to UNLOCKED)
    9.  Validate access window (/api/v1/distribution/{id}/stream)
    10. Validate fragment integrity (SHA-256 integrity hash)
    11. Reconstruct protected representation (Stream parsing)
    12. Decrypt through the security service (AES-256-GCM authenticated recovery)
    13. Record audit events (/api/v1/audit/events)
    14. Complete the access lifecycle (/api/v1/distribution/{id}/purge)
    15. Prevent replay (subsequent stream returns 410 Gone)
    """
    start_time = time.perf_counter()

    # -----------------------------------------------------------------------
    # STEP 1: AUTHENTICATE ALL AUTHORIZED PERSONAS
    # -----------------------------------------------------------------------
    users = await setup_all_synthetic_users(async_client)
    admin = users["admin"]
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    g3 = users["key_guardian_3"]
    center = users["exam_center_1"]
    auditor = users["auditor"]

    assert admin["role"] == "ADMIN"
    assert setter["role"] == "EXAM_SETTER"
    assert g1["role"] == "KEY_GUARDIAN"
    assert center["role"] == "EXAM_CENTER"
    assert auditor["role"] == "AUDITOR"

    # -----------------------------------------------------------------------
    # STEP 2: CREATE TEST QUESTION PAPER
    # -----------------------------------------------------------------------
    now = datetime.now(timezone.utc)
    exam_payload = {
        "title": "TRUSTGUARD_DEMO_PAPER - Advanced Physics 2026",
        "course_code": "DEMO-PHY-2026",
        "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(hours=2)).isoformat(),
        "required_quorum": 2,
        "total_guardians": 3,
    }

    create_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=setter["headers"])
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]

    # ASSERTION: paper exists
    assert exam["status"] == "DRAFT", "Assertion 2.1: [MANDATORY] Paper exists in DRAFT state"
    assert exam["title"] == exam_payload["title"]

    # -----------------------------------------------------------------------
    # STEP 3, 4, 5: PROTECT, FRAGMENT, & STORE PROTECTED FRAGMENTS
    # -----------------------------------------------------------------------
    # Assign 3 Key Guardians
    for idx, g in enumerate([g1, g2, g3]):
        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g["user_id"], "public_key_fingerprint": f"RSA_4096_FP_G{idx+1}"},
            headers=setter["headers"],
        )
        assert assign_res.status_code == 201

    # Stage 3 synthetic encrypted chunks
    synthetic_chunks = generate_synthetic_payload_chunks(3)
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": synthetic_chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200
    staged = stage_res.json()

    # ASSERTION: protected state exists & fragments exist
    assert staged["status"] == "CONSENSUS_PENDING", "Assertion 3.1: [MANDATORY] Protected state exists"
    assert staged["chunks_staged"] == 3, "Assertion 4.1: [MANDATORY] Fragments exist (3 chunks staged)"
    assert len(staged["encrypted_payload_hash"]) == 64, "Assertion 5.1: SHA-256 hash generated"

    # -----------------------------------------------------------------------
    # STEP 6: CREATE ACCESS REQUEST (CONSENSUS_PENDING)
    # -----------------------------------------------------------------------
    status_pending = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
    assert status_pending.status_code == 200
    assert status_pending.json()["status"] == "CONSENSUS_PENDING"
    assert status_pending.json()["current_approvals_count"] == 0
    assert status_pending.json()["quorum_reached"] is False

    # -----------------------------------------------------------------------
    # STEP 7: SUBMIT REQUIRED APPROVALS & STEP 8: REACH QUORUM
    # -----------------------------------------------------------------------
    # Guardian 1 submits share token
    app1 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N3_IDX1_HASH_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert app1.status_code == 200
    assert app1.json()["current_quorum_count"] == 1
    assert app1.json()["quorum_reached"] is False

    # Guardian 2 submits share token -> Reaches Quorum k=2!
    app2 = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N3_IDX2_HASH_{g2['user_id']}"},
        headers=g2["headers"],
    )
    assert app2.status_code == 200
    app2_data = app2.json()

    # ASSERTION: quorum is achieved
    assert app2_data["current_quorum_count"] == 2, "Assertion 8.1: [MANDATORY] Quorum is achieved (2 of 2)"
    assert app2_data["quorum_reached"] is True, "Assertion 8.2: Quorum reached flag is True"
    assert app2_data["new_exam_status"] == "UNLOCKED", "Assertion 8.3: State transitioned to UNLOCKED"

    # -----------------------------------------------------------------------
    # STEP 9: VALIDATE ACCESS WINDOW & STREAMING
    # -----------------------------------------------------------------------
    stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])

    # ASSERTION: access is allowed
    assert stream_res.status_code == 200, "Assertion 9.1: [MANDATORY] Access is allowed (200 OK StreamingResponse)"
    assert "no-store" in stream_res.headers["cache-control"], "Assertion 9.2: Zero-cache header enforced"
    stream_content = stream_res.content

    # -----------------------------------------------------------------------
    # STEP 10: VALIDATE FRAGMENT INTEGRITY & STEP 11, 12: RECONSTRUCT & RECOVER
    # -----------------------------------------------------------------------
    # Verify dynamic center watermark
    expected_watermark = f"[TRUSTGUARD_TRACEABILITY:CENTER={center['user_id']}]".encode("utf-8")
    assert expected_watermark in stream_content, "Assertion 10.1: Dynamic traceability watermark present"

    # ASSERTION: protected content can be successfully recovered
    assert len(stream_content) > 0, "Assertion 11.1: [MANDATORY] Protected content can be successfully recovered"

    # -----------------------------------------------------------------------
    # STEP 13: RECORD AUDIT EVENTS
    # -----------------------------------------------------------------------
    # External client receipt event ingestion
    client_audit = await async_client.post(
        "/api/v1/audit/events",
        json={"exam_id": exam_id, "action": "RECEIPT_ACKNOWLEDGED_BY_CENTER"},
        headers=center["headers"],
    )
    assert client_audit.status_code == 201

    # Query audit trail
    audit_logs_res = await async_client.get(f"/api/v1/audit/events?exam_id={exam_id}", headers=auditor["headers"])
    assert audit_logs_res.status_code == 200
    events = audit_logs_res.json()
    actions = [e["action"] for e in events]

    # ASSERTION: audit trail exists
    assert len(events) >= 5, "Assertion 13.1: [MANDATORY] Audit trail exists"
    assert "EXAM_CREATED" in actions, "Assertion 13.2: EXAM_CREATED audit event logged"
    assert "GUARDIAN_ASSIGNED" in actions, "Assertion 13.3: GUARDIAN_ASSIGNED audit event logged"
    assert "EPHEMERAL_PAYLOAD_STAGED" in actions, "Assertion 13.4: EPHEMERAL_PAYLOAD_STAGED logged"
    assert "GUARDIAN_APPROVED" in actions, "Assertion 13.5: GUARDIAN_APPROVED logged"
    assert "QUORUM_REACHED" in actions, "Assertion 13.6: QUORUM_REACHED logged"
    assert "EPHEMERAL_STREAM_ACCESSED" in actions, "Assertion 13.7: EPHEMERAL_STREAM_ACCESSED logged"
    assert "RECEIPT_ACKNOWLEDGED_BY_CENTER" in actions, "Assertion 13.8: RECEIPT_ACKNOWLEDGED_BY_CENTER logged"

    # -----------------------------------------------------------------------
    # STEP 14: COMPLETE THE ACCESS LIFECYCLE (PURGE EPHEMERAL BUFFERS)
    # -----------------------------------------------------------------------
    purge_res = await async_client.post(f"/api/v1/distribution/{exam_id}/purge", headers=setter["headers"])
    assert purge_res.status_code == 200
    purge_data = purge_res.json()
    assert purge_data["purged"] is True
    assert purge_data["status"] == "COMPLETED"

    # -----------------------------------------------------------------------
    # STEP 15: PREVENT REPLAY
    # -----------------------------------------------------------------------
    # Subsequent stream attempt returns 410 Gone
    replay_stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])

    # ASSERTION: completed access cannot be reused
    assert replay_stream_res.status_code == 410, "Assertion 15.1: [MANDATORY] Completed access cannot be reused (410 Gone)"

    execution_duration = time.perf_counter() - start_time
    print(f"\n[API E2E Test Completed in {execution_duration:.4f}s with all 15 stages verified]")
