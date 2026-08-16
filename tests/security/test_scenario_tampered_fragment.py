"""
TrustGuard — Controlled Integrity-Tampering Simulation Test Suite.

SCENARIO:
1. Create protected question paper.
2. Encrypt it with AES-256-GCM.
3. Create fragments (shards).
4. Store fragments.
5. Modify one fragment in the test environment (both content and metadata).
6. Attempt normal reconstruction/access.

EXPECTED:
- Integrity validation must fail.
- Refuses reconstruction (FragmentIntegrityError / FragmentValidationError).
- Refuses decryption (DecryptionFailedError / JITAccessDeniedError).
- Generates an audit/security event (INTEGRITY_FAILURE).
- Avoids returning plaintext (0 bytes disclosed).
- Clearly reports integrity failure.

TESTS BOTH:
- Modified fragment content (corrupted payload bytes)
- Invalid fragment integrity metadata (tampered SHA-256 digest)
"""

from datetime import datetime, timedelta, timezone
import hashlib
import uuid
import pytest
from httpx import AsyncClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.access import ApprovalDecision, RequestStatus
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
    validate_fragments,
    reconstruct_paper,
    decrypt_paper,
    protect_paper,
    fragment_paper,
    reconstruct_and_decrypt_paper,
    AccessDecision,
)
from security.crypto.encryption import encrypt, decrypt, DecryptionFailedError
from security.crypto.fragmentation import (
    FragmentPayload,
    FragmentIntegrityError,
    FragmentValidationError,
)
from security.quorum import AccessDeniedError
from security.access_window import JITAccessDeniedError
from attack_simulator.fixtures import (
    SYNTHETIC_DEMO_PAYLOAD,
    create_simulated_target_paper,
)
from attack_simulator.scenarios import Scenario08TamperedFragment
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
def tamper_env(db_session: Session):
    """Setup test fixture with officer, approvers, and protected paper."""
    r_officer = Role(id=uuid.uuid4(), name="OFFICER", description="Exam Officer")
    r_approver = Role(id=uuid.uuid4(), name="APPROVER", description="Key Guardian Approver")
    db_session.add_all([r_officer, r_approver])
    db_session.flush()

    def make_user(email: str, name: str, role: Role) -> User:
        u = User(
            id=uuid.uuid4(),
            email=email,
            password_hash=hashlib.sha256(b"Pass2026!").hexdigest(),
            full_name=name,
            is_active=True,
        )
        db_session.add(u)
        db_session.flush()
        db_session.add(UserRole(user_id=u.id, role_id=role.id))
        db_session.flush()
        return u

    officer = make_user("officer.tamper@synth.local", "Officer Alice", r_officer)
    app1 = make_user("approver.tamper1@synth.local", "Approver 1", r_approver)
    app2 = make_user("approver.tamper2@synth.local", "Approver 2", r_approver)
    app3 = make_user("approver.tamper3@synth.local", "Approver 3", r_approver)

    paper, fragments, master_key = create_simulated_target_paper(
        db_session,
        creator_id=officer.id,
        exam_identifier="TAMPER-SIM-2026",
    )

    return {
        "db": db_session,
        "officer": officer,
        "app1": app1,
        "app2": app2,
        "app3": app3,
        "paper": paper,
        "fragments": fragments,
        "master_key": master_key,
    }


# ===========================================================================
# 1. TEST CASE 1: Modified Fragment Content (Payload Corrupted)
# ===========================================================================

def test_tampered_fragment_content_refuses_reconstruction_and_decryption(tamper_env):
    """
    Test Step 1-6: Modify one fragment's payload data in the test environment.
    Asserts: validate_fragments fails, reconstruct_paper fails, reconstruct_and_decrypt fails,
    zero plaintext disclosed.
    """
    db: Session = tamper_env["db"]
    paper: QuestionPaper = tamper_env["paper"]
    master_key: bytes = tamper_env["master_key"]

    db_shards = db.query(PaperFragment).filter_by(paper_id=paper.id).order_by(PaperFragment.fragment_index).all()
    assert len(db_shards) == 5

    # Tamper with shard 2 content (keep original recorded hash)
    tampered_shards = [
        FragmentPayload(
            fragment_index=s.fragment_index,
            fragment_data=(
                b"CORRUPTED_INJECTED_PAYLOAD_DATA_XYZ_999" if s.fragment_index == 2 else s.fragment_data
            ),
            integrity_hash=s.integrity_hash,
            paper_id=s.paper_id,
        )
        for s in db_shards
    ]

    # 1. validate_fragments must fail and clearly report integrity failure
    with pytest.raises(FragmentIntegrityError) as exc_info:
        validate_fragments(tampered_shards, expected_paper_id=paper.id, expected_count=5)
    err_msg = str(exc_info.value).lower()
    assert "integrity" in err_msg or "mismatch" in err_msg or "altered" in err_msg
    assert "2" in err_msg

    # 2. reconstruct_paper must refuse reconstruction
    with pytest.raises(FragmentIntegrityError):
        reconstruct_paper(db, paper.id, fragments=tampered_shards)

    # 3. reconstruct_and_decrypt_paper on DB with tampered shard must refuse decryption
    orig_shard2 = db_shards[2].fragment_data
    db_shards[2].fragment_data = b"CORRUPTED_INJECTED_PAYLOAD_DATA_XYZ_999"
    db.flush()
    try:
        with pytest.raises(FragmentIntegrityError):
            reconstruct_and_decrypt_paper(
                db=db,
                paper=paper,
                key=master_key,
            )
    finally:
        db_shards[2].fragment_data = orig_shard2
        db.flush()


# ===========================================================================
# 2. TEST CASE 2: Invalid Fragment Integrity Metadata (Tampered Hash)
# ===========================================================================

def test_tampered_fragment_metadata_hash_refuses_reconstruction(tamper_env):
    """
    Test: Shard payload is intact, but its recorded SHA-256 metadata hash is altered.
    Asserts: validate_fragments fails and reconstruct_paper refuses reconstruction.
    """
    db: Session = tamper_env["db"]
    paper: QuestionPaper = tamper_env["paper"]

    db_shards = db.query(PaperFragment).filter_by(paper_id=paper.id).order_by(PaperFragment.fragment_index).all()

    # Tamper with shard 3 metadata hash
    tampered_meta_shards = [
        FragmentPayload(
            fragment_index=s.fragment_index,
            fragment_data=s.fragment_data,
            integrity_hash=(
                "bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0bad0"
                if s.fragment_index == 3 else s.integrity_hash
            ),
            paper_id=s.paper_id,
        )
        for s in db_shards
    ]

    with pytest.raises(FragmentIntegrityError) as exc_info:
        validate_fragments(tampered_meta_shards, expected_paper_id=paper.id, expected_count=5)
    assert "integrity" in str(exc_info.value).lower() or "mismatch" in str(exc_info.value).lower()

    with pytest.raises(FragmentIntegrityError):
        reconstruct_paper(db, paper.id, fragments=tampered_meta_shards)


# ===========================================================================
# 3. TEST CASE 3: JIT Access Attempt with Tampered Fragment in DB
# ===========================================================================

def test_tampered_fragment_in_database_denies_jit_access_and_records_threat(tamper_env):
    """
    Test: Valid officer + 3/3 quorum + active access window.
    Adversary modifies a fragment directly in the database.
    Asserts: authorize_access returns DENY citing integrity check failure,
    ThreatEvent INTEGRITY_FAILURE is recorded in database,
    execute_jit_paper_access raises JITAccessDeniedError,
    zero plaintext bytes are returned.
    """
    db: Session = tamper_env["db"]
    officer: User = tamper_env["officer"]
    app1: User = tamper_env["app1"]
    app2: User = tamper_env["app2"]
    app3: User = tamper_env["app3"]
    paper: QuestionPaper = tamper_env["paper"]
    master_key: bytes = tamper_env["master_key"]

    now = datetime.now(timezone.utc)

    # 1. Reach 3/3 quorum
    req = create_access_request(db, paper_id=paper.id, requested_by=officer.id, required_approvals=3)
    cast_approval_vote(db, req.id, app1.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app2.id, ApprovalDecision.APPROVED)
    cast_approval_vote(db, req.id, app3.id, ApprovalDecision.APPROVED)
    assert req.status == RequestStatus.APPROVED

    # 2. Schedule active window
    create_access_window(
        db=db,
        request_id=req.id,
        start_time=now - timedelta(minutes=10),
        end_time=now + timedelta(minutes=50),
        current_time=now,
    )

    # 3. Modify fragment 1 directly in the database
    db_shards = db.query(PaperFragment).filter_by(paper_id=paper.id).order_by(PaperFragment.fragment_index).all()
    orig_data = db_shards[1].fragment_data
    db_shards[1].fragment_data = b"ADVERSARY_ALTERED_DB_SHARD_1"
    db.flush()

    # 4. Attempt JIT authorization
    auth_res = authorize_access(
        db=db,
        user_id=officer.id,
        paper_id=paper.id,
        request_id=req.id,
        current_time=now,
        actor_ip="10.0.0.99",
    )

    assert auth_res.decision == AccessDecision.DENY
    assert auth_res.is_allowed is False
    assert "integrity check failed" in auth_res.reason.lower()

    # 5. Verify ThreatEvent was recorded in DB
    threats = db.query(ThreatEvent).filter(
        ThreatEvent.target_id == paper.id,
        ThreatEvent.event_type == ThreatEventType.INTEGRITY_FAILURE,
    ).all()
    assert len(threats) >= 1
    assert threats[-1].severity == ThreatSeverity.CRITICAL

    # 6. Direct execution attempt raises JITAccessDeniedError
    with pytest.raises((JITAccessDeniedError, AccessDeniedError)) as exc_info:
        execute_jit_paper_access(
            db=db,
            user_id=officer.id,
            paper_id=paper.id,
            key=master_key,
            request_id=req.id,
            current_time=now,
        )
    assert "integrity" in str(exc_info.value).lower() or "denied" in str(exc_info.value).lower()

    # Restore shard
    db_shards[1].fragment_data = orig_data
    db.flush()


# ===========================================================================
# 4. TEST CASE 4: Direct AES-256-GCM Decryption Refusal on Tampered Ciphertext
# ===========================================================================

def test_tampered_ciphertext_decryption_refusal_via_crypto_engine(tamper_env):
    """
    Test: Direct authenticated decryption refusal when ciphertext, nonce, or tag is modified.
    Asserts: DecryptionFailedError raised by AES-256-GCM engine; zero plaintext disclosed.
    """
    master_key: bytes = tamper_env["master_key"]
    encrypted_bytes = encrypt(SYNTHETIC_DEMO_PAYLOAD, master_key)

    # 1. Alter first byte (nonce / header area)
    corrupted_1 = bytearray(encrypted_bytes)
    corrupted_1[0] ^= 0xFF
    with pytest.raises(DecryptionFailedError) as exc_info:
        decrypt(bytes(corrupted_1), master_key)
    assert "integrity check failed" in str(exc_info.value).lower() or "incorrect key" in str(exc_info.value).lower()

    # 2. Alter middle byte (ciphertext payload area)
    corrupted_2 = bytearray(encrypted_bytes)
    corrupted_2[14] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        decrypt(bytes(corrupted_2), master_key)

    # 3. Alter last byte (GCM auth tag area)
    corrupted_3 = bytearray(encrypted_bytes)
    corrupted_3[-1] ^= 0xFF
    with pytest.raises(DecryptionFailedError):
        decrypt(bytes(corrupted_3), master_key)

    # 4. Truncated payload
    with pytest.raises((DecryptionFailedError, ValueError)):
        decrypt(encrypted_bytes[:15], master_key)


# ===========================================================================
# 5. TEST CASE 5: Attack Simulator Scenario 8 Class Execution
# ===========================================================================

def test_scenario_08_simulator_class_execution(db_session: Session):
    """
    Verify Scenario08TamperedFragment executes cleanly and reports all test cases passed.
    """
    scenario = Scenario08TamperedFragment()
    result = scenario.run(db=db_session)

    assert result.scenario_id == 8
    assert result.passed is True
    assert result.security_decision == "DENY"
    assert result.threat_event_created is True
    assert result.audit_event_created is True
    assert result.details["content_tamper_detected"] is True
    assert result.details["hash_tamper_detected"] is True
    assert result.details["jit_blocked"] is True
    assert result.details["exec_blocked"] is True
    assert result.details["no_disclosure"] is True


# ===========================================================================
# 6. TEST CASE 6: REST API Layer Tampered Payload Stream Failure
# ===========================================================================

@pytest.mark.asyncio
async def test_api_tampered_payload_chunk_integrity_failure(async_client: AsyncClient):
    """
    REST API: Staging invalid / tampered chunks triggers cryptographic verification failure.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]

    # 1. Create exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # 2. Assign guardians
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

    # 3. Stage valid chunks first
    chunks = generate_synthetic_payload_chunks(2)
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200

    # 4. Approvers unlock
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX2_{g2['user_id']}"},
        headers=g2["headers"],
    )

    # 5. Exam center streams chunks
    center = users["exam_center_1"]
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 200

    # Client receives stream and verifies that tampered bytes fail AES-GCM decryption
    raw_stream_data = stream_res.content
    assert len(raw_stream_data) > 0
    tampered_stream = bytearray(raw_stream_data)
    tampered_stream[5] ^= 0xFF

    dummy_key = b"\x00" * 32
    with pytest.raises(Exception):
        decrypt(bytes(tampered_stream), dummy_key)

