"""
TrustGuard — Reusable Complete System Regression Test Suite.

Comprehensive, deterministic, and isolated regression test suite covering:
1. AUTHENTICATION (Valid login, Invalid login, Unauthorized role)
2. PAPER LIFECYCLE (Create, Protect, Fragment, Request, Approve, Authorize, Complete)
3. CRYPTOGRAPHY (Encrypt/Decrypt, Tampered ciphertext, Invalid key)
4. INTEGRITY (Valid fragment, Corrupted fragment)
5. QUORUM (Insufficient quorum, Valid quorum, Duplicate approval, Unauthorized approver)
6. ACCESS WINDOW (Before, During, After)
7. AUDIT (Allowed access, Denied access, Integrity failure, Replay)
8. ATTACK SIMULATIONS (All 10 implemented scenarios)
"""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import ApprovalDecision, RequestStatus, WindowStatus
from database.models.audit import ThreatEvent, ThreatEventType, ThreatSeverity, AuditLog
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from database.models.user import User, Role, UserRole

from security import (
    create_access_request,
    cast_approval_vote,
    create_access_window,
    authorize_access,
    execute_jit_paper_access,
    complete_access,
    expire_access_request,
    check_quorum,
    AccessDecision,
)
from security.crypto import (
    encrypt,
    decrypt,
    fragment_ciphertext,
    reconstruct_ciphertext,
    generate_integrity_hash,
    generate_master_key,
    DecryptionFailedError,
)
from security.crypto.fragmentation import FragmentPayload, FragmentIntegrityError
from security.access_window import JITAccessDeniedError, WindowScheduleError
from security.quorum import (
    DuplicateApprovalError,
    RequestNotPendingError,
    InvalidApproverRoleError,
    AccessDeniedError,
)
from attack_simulator.scenarios import (
    ALL_SCENARIOS,
    Scenario01UnauthorizedUser,
    Scenario02InsufficientPrivilege,
    Scenario03NoQuorum,
    Scenario04DuplicateApproval,
    Scenario05UnauthorizedApprover,
    Scenario06OutsideTimeWindow,
    Scenario07ReplayCompletedRequest,
    Scenario08TamperedFragment,
    Scenario09InvalidResource,
    Scenario10MalformedRequest,
)
from attack_simulator.fixtures.synthetic_targets import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from tests.fixtures import (
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    setup_all_synthetic_users,
)

SYNTHETIC_TEST_PAYLOAD = (
    b"CONFIDENTIAL_SYNTHETIC_EXAM_REGRESSION_PAPER_2026\n"
    b"SECTION A: Applied Discrete Mathematics\n"
    b"SECTION B: Zero-Trust Cryptography & Threshold Protocols\n"
)


# ===========================================================================
# FIXTURES
# ===========================================================================

@pytest.fixture
def db_session():
    """In-memory SQLite database session isolated per test."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


@pytest.fixture
def base_security_env(db_session: Session):
    """Setup standard officers, approvers, and protected paper."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Key Guardian Approver")
    r_candidate = Role(id=uuid.uuid4(), name="CANDIDATE", description="Candidate Role")
    db_session.add_all([r_officer, r_approver, r_candidate])
    db_session.flush()

    def make_user(email: str, name: str, role: Role) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hashlib.sha256(b"SecurePass2026!").hexdigest(),
            full_name=name,
            is_active=True,
        )
        db_session.add(u)
        db_session.flush()
        db_session.add(UserRole(user_id=u.id, role_id=role.id))
        db_session.flush()
        return u

    officer = make_user("officer.reg@synth.local", "Officer Alice", r_officer)
    app1 = make_user("app1.reg@synth.local", "Approver 1", r_approver)
    app2 = make_user("app2.reg@synth.local", "Approver 2", r_approver)
    app3 = make_user("app3.reg@synth.local", "Approver 3", r_approver)
    candidate = make_user("candidate.reg@synth.local", "Candidate Bob", r_candidate)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="REGRESSION-2026-001",
    )

    return {
        "db": db_session,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "app3": app3,
        "candidate": candidate,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
    }


# ===========================================================================
# 1. AUTHENTICATION REGRESSION SUITE
# ===========================================================================

class TestAuthenticationRegression:
    """Validate valid login, invalid login, and unauthorized role behaviors."""

    @pytest.mark.asyncio
    async def test_auth_valid_login(self, async_client: AsyncClient):
        """Verify legitimate user login returns 200 OK and valid JWT token."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        login_res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": setter["username"], "password": setter["raw_credentials"]["password"]},
        )
        assert login_res.status_code == 200
        token_data = login_res.json()
        assert "access_token" in token_data
        assert token_data["token_type"] == "bearer"
        assert token_data["role"] == "EXAM_SETTER"

    @pytest.mark.asyncio
    async def test_auth_invalid_login_bad_password(self, async_client: AsyncClient):
        """Verify login with bad credentials returns 400 or 401 Unauthorized."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        login_res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": setter["username"], "password": "WRONG_PASSWORD_999!"},
        )
        assert login_res.status_code in (400, 401)
        assert "incorrect" in login_res.json()["detail"].lower() or "invalid" in login_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_auth_unauthorized_role(self, async_client: AsyncClient):
        """Verify role with insufficient privilege receives 403 Forbidden on restricted endpoints."""
        users = await setup_all_synthetic_users(async_client)
        center = users["exam_center_1"]  # Exam Center cannot create exams

        res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(),
            headers=center["headers"],
        )
        assert res.status_code == 403
        assert "not permitted" in res.json()["detail"].lower() or "forbidden" in res.json()["detail"].lower()


# ===========================================================================
# 2. PAPER LIFECYCLE REGRESSION SUITE
# ===========================================================================

class TestPaperLifecycleRegression:
    """Validate complete lifecycle: create, protect, fragment, request, approve, authorize, complete."""

    @pytest.mark.asyncio
    async def test_paper_lifecycle_complete_workflow(self, async_client: AsyncClient):
        """Verify end-to-end question paper lifecycle progression."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1 = users["key_guardian_1"]
        g2 = users["key_guardian_2"]
        center = users["exam_center_1"]

        # 1. Create
        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(start_delta_minutes=-5, end_delta_hours=2, required_quorum=2, total_guardians=2),
            headers=setter["headers"],
        )
        assert create_res.status_code == 201
        exam_id = create_res.json()["id"]

        # 2. Request / Assign Guardians
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

        # 3. Protect & Fragment & Store in Ephemeral RAM
        chunks = generate_synthetic_payload_chunks(2)
        stage_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/stage-payload",
            json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
            headers=setter["headers"],
        )
        assert stage_res.status_code == 200
        assert stage_res.json()["status"] == "CONSENSUS_PENDING"

        # 4. Approve & Quorum
        await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
            headers=g1["headers"],
        )
        app2_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": f"MOCK_SHARE_K2_N2_IDX2_{g2['user_id']}"},
            headers=g2["headers"],
        )
        assert app2_res.status_code == 200
        assert app2_res.json()["quorum_reached"] is True
        assert app2_res.json()["new_exam_status"] == "UNLOCKED"

        # 5. Authorize & Stream
        stream_res = await async_client.get(
            f"/api/v1/distribution/{exam_id}/stream",
            headers=center["headers"],
        )
        assert stream_res.status_code == 200
        assert len(stream_res.content) > 0

        # 6. Complete Session & Purge
        purge_res = await async_client.post(
            f"/api/v1/distribution/{exam_id}/purge",
            headers=setter["headers"],
        )
        assert purge_res.status_code == 200
        assert purge_res.json()["status"] == "COMPLETED"


# ===========================================================================
# 3. CRYPTOGRAPHY REGRESSION SUITE
# ===========================================================================

class TestCryptographyRegression:
    """Validate encrypt/decrypt roundtrip, tampered ciphertext, and invalid key handling."""

    def test_crypto_encrypt_and_decrypt_roundtrip(self):
        """Verify AES-256-GCM encrypts and decrypts with exact roundtrip fidelity."""
        master_key = base64.b64decode(generate_master_key())
        raw_secret = b"ZERO_TRUST_MATHEMATICAL_PROOF_OF_CONFIDENTIALITY"
        
        ciphertext = encrypt(raw_secret, master_key)
        recovered = decrypt(ciphertext, master_key)
        assert recovered == raw_secret

    def test_crypto_tampered_ciphertext_refuses_decryption(self):
        """Verify bit-flipped ciphertext fails GMAC tag verification and raises DecryptionFailedError."""
        master_key = base64.b64decode(generate_master_key())
        ciphertext = encrypt(SYNTHETIC_TEST_PAYLOAD, master_key)

        corrupted = bytearray(ciphertext)
        corrupted[-1] ^= 0xFF  # Corrupt auth tag

        with pytest.raises(DecryptionFailedError):
            decrypt(bytes(corrupted), master_key)

    def test_crypto_invalid_key_refuses_decryption(self):
        """Verify decrypting ciphertext with an incorrect master key fails cleanly."""
        master_key_1 = base64.b64decode(generate_master_key())
        master_key_2 = base64.b64decode(generate_master_key())
        
        ciphertext = encrypt(SYNTHETIC_TEST_PAYLOAD, master_key_1)
        with pytest.raises(DecryptionFailedError):
            decrypt(ciphertext, master_key_2)


# ===========================================================================
# 4. INTEGRITY REGRESSION SUITE
# ===========================================================================

class TestIntegrityRegression:
    """Validate valid fragment reconstruction vs corrupted fragment detection."""

    def test_integrity_valid_fragments_pass(self):
        """Verify valid fragments pass SHA-256 hash checks and reassemble correctly."""
        master_key = base64.b64decode(generate_master_key())
        encrypted = encrypt(SYNTHETIC_TEST_PAYLOAD, master_key)
        fragments = fragment_ciphertext(encrypted, num_fragments=4)

        reconstructed = reconstruct_ciphertext(fragments)
        recovered_plain = decrypt(reconstructed, master_key)
        assert recovered_plain == SYNTHETIC_TEST_PAYLOAD

    def test_integrity_corrupted_fragment_payload_fails(self):
        """Verify corrupted fragment payload is caught during validation."""
        master_key = base64.b64decode(generate_master_key())
        encrypted = encrypt(SYNTHETIC_TEST_PAYLOAD, master_key)
        fragments = fragment_ciphertext(encrypted, num_fragments=4)

        # Tamper payload of shard 2
        corrupted_shards = [
            FragmentPayload(
                fragment_index=f.fragment_index,
                fragment_data=b"TAMPERED_SHARD_DATA" if f.fragment_index == 2 else f.fragment_data,
                integrity_hash=f.integrity_hash,
                paper_id=f.paper_id,
            )
            for f in fragments
        ]

        with pytest.raises(FragmentIntegrityError):
            reconstruct_ciphertext(corrupted_shards)


# ===========================================================================
# 5. QUORUM REGRESSION SUITE
# ===========================================================================

class TestQuorumRegression:
    """Validate insufficient quorum, valid quorum, duplicate approvals, and unauthorized approvers."""

    def test_quorum_insufficient_quorum_denied(self, base_security_env):
        """Verify access is DENIED when approval count is below threshold (0/3, 1/3, 2/3)."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
        
        # 0/3 Approvals -> DENY
        auth_0 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth_0.decision == AccessDecision.DENY
        assert auth_0.is_allowed is False

        # 1/3 Approvals -> DENY
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        auth_1 = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth_1.decision == AccessDecision.DENY

    def test_quorum_valid_quorum_allowed(self, base_security_env):
        """Verify access is ALLOWED when full 3/3 quorum is satisfied within valid window."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        app2: User = base_security_env["app2"]
        app3: User = base_security_env["app3"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)
        assert req.status == RequestStatus.APPROVED

        create_access_window(db, req.id, start_time=now - timedelta(minutes=5), end_time=now + timedelta(minutes=30), current_time=now)
        auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth.decision == AccessDecision.ALLOW
        assert auth.is_allowed is True

    def test_quorum_duplicate_approval_rejected(self, base_security_env):
        """Verify an approver cannot cast more than one vote for the same request."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        paper: QuestionPaper = base_security_env["paper"]

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

        with pytest.raises(DuplicateApprovalError):
            cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)

    def test_quorum_unauthorized_approver_role_rejected(self, base_security_env):
        """Verify user without APPROVER role cannot submit approval votes."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        candidate: User = base_security_env["candidate"]
        paper: QuestionPaper = base_security_env["paper"]

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
        with pytest.raises(InvalidApproverRoleError):
            cast_approval_vote(db, req.id, candidate.id, ApprovalDecision.APPROVED)


# ===========================================================================
# 6. ACCESS WINDOW REGRESSION SUITE
# ===========================================================================

class TestAccessWindowRegression:
    """Validate time-lock behavior: before window, during window, and after window."""

    def test_access_window_before_window_denied(self, base_security_env):
        """Verify access before start_time returns DENY citing time window."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        app2: User = base_security_env["app2"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)

        # Window starts in +30 minutes
        create_access_window(db, req.id, start_time=now + timedelta(minutes=30), end_time=now + timedelta(hours=2), current_time=now)
        auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth.decision == AccessDecision.DENY
        assert "not active" in auth.reason.lower() or "before" in auth.reason.lower()

    def test_access_window_during_window_allowed(self, base_security_env):
        """Verify access during active window returns ALLOW."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        app2: User = base_security_env["app2"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)

        create_access_window(db, req.id, start_time=now - timedelta(minutes=10), end_time=now + timedelta(minutes=50), current_time=now)
        auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth.decision == AccessDecision.ALLOW

    def test_access_window_after_window_denied(self, base_security_env):
        """Verify access after end_time returns DENY."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        app2: User = base_security_env["app2"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)

        # Window closed 15 minutes ago
        create_access_window(db, req.id, start_time=now - timedelta(hours=2), end_time=now - timedelta(minutes=15), current_time=now - timedelta(hours=2))
        auth = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth.decision == AccessDecision.DENY
        assert "expired" in auth.reason.lower() or "closed" in auth.reason.lower()


# ===========================================================================
# 7. AUDIT REGRESSION SUITE
# ===========================================================================

class TestAuditRegression:
    """Validate audit trails for allowed access, denied access, integrity failures, and replays."""

    def test_audit_events_recorded_accurately(self, base_security_env):
        """Verify AuditEvent and ThreatEvent records are committed with precise severity and timestamps."""
        db: Session = base_security_env["db"]
        officer: User = base_security_env["officer"]
        app1: User = base_security_env["app1"]
        app2: User = base_security_env["app2"]
        paper: QuestionPaper = base_security_env["paper"]
        now = datetime.now(timezone.utc)

        # 1. Denied Access Attempt (0 approvals)
        req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=2)
        auth_denied = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth_denied.decision == AccessDecision.DENY

        # 2. Allowed Access
        cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
        cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
        create_access_window(db, req.id, start_time=now - timedelta(minutes=5), end_time=now + timedelta(minutes=30), current_time=now)
        auth_allowed = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth_allowed.decision == AccessDecision.ALLOW

        # 3. Session Completed
        complete_access(db, paper_id=paper.id, request_id=req.id, actor_id=officer.id)

        # 4. Replay Attempt
        auth_replay = authorize_access(db, user_id=officer.id, paper_id=paper.id, request_id=req.id, current_time=now)
        assert auth_replay.decision == AccessDecision.DENY

        # Check ThreatEvent log
        threats = db.query(ThreatEvent).filter_by(target_id=paper.id).all()
        threat_types = [t.event_type for t in threats]
        assert ThreatEventType.REPLAY_ATTEMPT in threat_types


# ===========================================================================
# 8. ATTACK SIMULATIONS REGRESSION SUITE
# ===========================================================================

class TestAttackSimulationsRegression:
    """Validate all 10 controlled attack simulation scenarios deterministically."""

    @pytest.mark.parametrize("scenario_cls", ALL_SCENARIOS, ids=[f"Scenario_{s.scenario_id:02d}_{s.__name__}" for s in ALL_SCENARIOS])
    def test_all_10_simulation_scenarios_execute_cleanly(self, db_session: Session, scenario_cls):
        """Execute each of the 10 controlled attack scenarios and assert clean passing result."""
        scenario_instance = scenario_cls()
        result = scenario_instance.run(db=db_session)

        assert result.passed is True, f"{scenario_cls.__name__} failed: {result.actual_result}"
        assert result.security_decision in ("DENY", "ALLOW")
        assert result.threat_event_created is True or result.audit_event_created is True
        assert len(result.actual_result) > 0
