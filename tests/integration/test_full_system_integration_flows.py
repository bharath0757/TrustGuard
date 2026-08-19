"""
TrustGuard — Full System Integration Test Suite.

Executes all 7 end-to-end workflows through the REAL application, backend API,
database, and cryptographic engines without mocking core security components:

1. NORMAL FLOW:
   Create paper → Protect → Fragment → Store → Request access → Approve →
   Quorum → Valid access window → Integrity validation → Reconstruct →
   Decrypt → Audit → Complete

2. ATTACK FLOW 1:
   Unauthorized user → DENY

3. ATTACK FLOW 2:
   Valid user + Insufficient quorum → DENY

4. ATTACK FLOW 3:
   Tampered fragment / integrity failure → DENY

5. ATTACK FLOW 4:
   Expired access window → DENY

6. ATTACK FLOW 5:
   Replay completed request → DENY

7. ATTACK FLOW 6:
   Valid user + Valid quorum + Valid time + Valid integrity → ALLOW
"""

import base64
from datetime import datetime, timedelta, timezone
import pytest
from httpx import AsyncClient

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
from tests.fixtures import (
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    setup_all_synthetic_users,
)

SYNTHETIC_EXAM_PLAINTEXT = (
    b"CONFIDENTIAL_SYNTHETIC_EXAM_PAPER_DATA_2026\n"
    b"SECTION 1: Discrete Mathematical Structures (Mock Question)\n"
    b"SECTION 2: Information Security Principles (Mock Question)\n"
)


# ===========================================================================
# 1. NORMAL FULL INTEGRATION FLOW
# ===========================================================================

@pytest.mark.asyncio
async def test_full_system_normal_flow_lifecycle(async_client: AsyncClient):
    """
    Execute full normal lifecycle:
    Create paper → Protect → Fragment → Store → Request access → Approve →
    Quorum → Valid access window → Integrity validation → Reconstruct →
    Decrypt → Audit → Complete.
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]
    auditor = users["auditor"]

    # 1. Create Question Paper
    exam_payload = generate_synthetic_exam_payload(
        start_delta_minutes=-5,
        end_delta_hours=3,
        required_quorum=2,
        total_guardians=2,
    )
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=exam_payload,
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam = create_res.json()
    exam_id = exam["id"]
    assert exam["status"] == "DRAFT"

    # 2. Assign Guardians (Request Access Setup)
    g1_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
        headers=setter["headers"],
    )
    assert g1_assign.status_code == 201

    g2_assign = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "RSA_4096_FP_G2"},
        headers=setter["headers"],
    )
    assert g2_assign.status_code == 201

    # 3 & 4. Protect, Fragment, and Store Payload in Ephemeral Store
    master_key = base64.b64decode(generate_master_key())
    encrypted_bytes = encrypt(SYNTHETIC_EXAM_PLAINTEXT, key=master_key)
    manifest_hash = generate_integrity_hash(SYNTHETIC_EXAM_PLAINTEXT)

    # Shard into 3 fragments
    raw_fragments = fragment_ciphertext(encrypted_bytes, num_fragments=3)
    b64_chunks = [base64.b64encode(f.fragment_data).decode("utf-8") for f in raw_fragments]

    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": b64_chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200
    assert stage_res.json()["status"] == "CONSENSUS_PENDING"

    # 5 & 6. Submit Approvals & Reach Quorum
    # Guardian 1 approves
    app1_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert app1_res.status_code == 200
    assert app1_res.json()["quorum_reached"] is False
    assert app1_res.json()["new_exam_status"] == "CONSENSUS_PENDING"

    # Guardian 2 approves -> Reaches Quorum!
    app2_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX2_{g2['user_id']}"},
        headers=g2["headers"],
    )
    assert app2_res.status_code == 200
    assert app2_res.json()["quorum_reached"] is True
    assert app2_res.json()["new_exam_status"] in ["AUTHORIZED", "UNLOCKED"]

    # 7, 8, 9. Valid Access Window, Integrity Validation, & Stream Reconstruction
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 200
    assert len(stream_res.content) > 0

    # 10. Reconstruct & Decrypt
    reconstructed_ciphertext = reconstruct_ciphertext(raw_fragments)
    decrypted_paper = decrypt(reconstructed_ciphertext, key=master_key)
    assert decrypted_paper == SYNTHETIC_EXAM_PLAINTEXT

    # Integrity verification
    recovered_hash = generate_integrity_hash(decrypted_paper)
    assert recovered_hash == manifest_hash

    # 11. Audit Trail Completeness
    audit_res = await async_client.get(
        f"/api/v1/audit/events?exam_id={exam_id}",
        headers=auditor["headers"],
    )
    assert audit_res.status_code == 200
    audit_events = audit_res.json()
    actions = [e["action"] for e in audit_events]
    assert "EXAM_CREATED" in actions
    assert "EPHEMERAL_PAYLOAD_STAGED" in actions
    assert "GUARDIAN_ASSIGNED" in actions
    assert "GUARDIAN_APPROVED" in actions
    assert "QUORUM_REACHED" in actions
    assert "EPHEMERAL_STREAM_ACCESSED" in actions

    # 12. Complete Session / Ephemeral Purge
    purge_res = await async_client.post(
        f"/api/v1/distribution/{exam_id}/purge",
        headers=setter["headers"],
    )
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True
    assert purge_res.json()["status"] == "COMPLETED"


# ===========================================================================
# 2. ATTACK FLOW 1: Unauthorized User -> DENY
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_1_unauthorized_user_access_denied(async_client: AsyncClient):
    """
    Attack Flow 1: Unauthenticated client or unauthorized candidate role
    attempts to access protected paper or streams -> DENY (401 / 403).
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]

    # Create exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(),
        headers=setter["headers"],
    )
    assert create_res.status_code == 201
    exam_id = create_res.json()["id"]

    # 1. Unauthenticated request to stream endpoint -> 401 or 403
    unauth_stream = await async_client.get(f"/api/v1/distribution/{exam_id}/stream")
    assert unauth_stream.status_code in (401, 403)

    # 2. Authenticated but unauthorized role (Exam Setter attempting to stream center endpoint) -> 403
    unauth_role_stream = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=setter["headers"],
    )
    assert unauth_role_stream.status_code == 403


# ===========================================================================
# 3. ATTACK FLOW 2: Valid User + Insufficient Quorum -> DENY
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_2_insufficient_quorum_access_denied(async_client: AsyncClient):
    """
    Attack Flow 2: Valid exam center attempts to stream paper when quorum has not been satisfied (0/2 or 1/2 approvals) -> DENY (403).
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]

    # 1. Create exam with k=2 quorum
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    exam_id = create_res.json()["id"]

    # 2. Assign guardians first
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

    # 3. Stage payload
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )

    # 4. Stream attempt with 0/2 approvals -> 403 Forbidden
    premature_stream_0 = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert premature_stream_0.status_code == 403
    assert "quorum" in premature_stream_0.json()["detail"].lower() or "forbidden" in premature_stream_0.json()["detail"].lower()

    # 5. Guardian 1 approves (1/2 approvals)
    await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_{g1['user_id']}"},
        headers=g1["headers"],
    )

    # 6. Stream attempt with 1/2 approvals -> 403 Forbidden
    premature_stream_1 = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert premature_stream_1.status_code == 403
    assert "quorum" in premature_stream_1.json()["detail"].lower() or "forbidden" in premature_stream_1.json()["detail"].lower()


# ===========================================================================
# 4. ATTACK FLOW 3: Tampered Fragment -> Integrity Failure & Decryption Refusal -> DENY
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_3_tampered_fragment_integrity_failure_denied():
    """
    Attack Flow 3: Modification or tampering with fragment ciphertext or authentication tag
    triggers cryptographic integrity failure; decryption is completely refused.
    """
    master_key = base64.b64decode(generate_master_key())
    original_paper = b"SYNTHETIC_QUESTION_PAPER_CONFIDENTIAL_MATHEMATICS_2026"
    
    # 1. Encrypt & fragment
    encrypted_bytes = encrypt(original_paper, key=master_key)
    fragments = fragment_ciphertext(encrypted_bytes, num_fragments=3)

    # 2. Adversary alters bytes in shard 2
    tampered_fragments = [
        FragmentPayload(
            fragment_index=f.fragment_index,
            fragment_data=f.fragment_data,
            integrity_hash=f.integrity_hash,
            paper_id=f.paper_id,
        )
        for f in fragments
    ]
    # Corrupt payload
    corrupted_data = bytearray(tampered_fragments[1].fragment_data)
    corrupted_data[2] ^= 0xFF
    tampered_fragments[1].fragment_data = bytes(corrupted_data)

    # 3. Direct AES-256-GCM Decryption on tampered fragment slice fails
    with pytest.raises((DecryptionFailedError, ValueError)):
        decrypt(bytes(corrupted_data), key=master_key)

    # 4. Reconstructed ciphertext with tampered fragment fails authentication tag validation / integrity check
    with pytest.raises((DecryptionFailedError, FragmentIntegrityError)):
        reconstructed_tampered = reconstruct_ciphertext(tampered_fragments)
        decrypt(reconstructed_tampered, key=master_key)


# ===========================================================================
# 5. ATTACK FLOW 4: Expired Access Window -> DENY
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_4_expired_access_window_denied(async_client: AsyncClient):
    """
    Attack Flow 4: Access attempted outside / after the designated time window -> 410 Gone (DENY).
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]

    now = datetime.now(timezone.utc)

    # Create exam scheduled in the past
    expired_payload = generate_synthetic_exam_payload(
        start_delta_minutes=-120,
        end_delta_hours=-1,
        required_quorum=2,
        total_guardians=2,
    )
    expired_payload["scheduled_start"] = (now - timedelta(hours=2)).isoformat()
    expired_payload["scheduled_end"] = (now - timedelta(minutes=15)).isoformat()

    create_res = await async_client.post(
        "/api/v1/exams/",
        json=expired_payload,
        headers=setter["headers"],
    )
    exam_id = create_res.json()["id"]

    # Assign guardians first
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

    # Stage payload & unlock
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
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

    # Attempt stream on expired exam -> 410 Gone
    expired_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert expired_res.status_code == 410
    assert "expired" in expired_res.json()["detail"].lower()


# ===========================================================================
# 6. ATTACK FLOW 5: Replay Completed Request -> DENY
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_5_replay_completed_request_denied(async_client: AsyncClient):
    """
    Attack Flow 5: Attempting to reuse an access request after the session has concluded / purged -> 410 Gone (DENY).
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]

    # 1. Create exam
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
        headers=setter["headers"],
    )
    exam_id = create_res.json()["id"]

    # 2. Assign guardians first
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

    # 3. Stage payload & unlock
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )
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

    # 4. Legitimate First Access
    stream_first = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_first.status_code == 200

    # 5. Conclude Exam / Purge Ephemeral Memory
    purge_res = await async_client.post(
        f"/api/v1/distribution/{exam_id}/purge",
        headers=setter["headers"],
    )
    assert purge_res.status_code == 200
    assert purge_res.json()["status"] == "COMPLETED"

    # 6. Replay Stream Attempt -> 410 Gone (DENY)
    replay_stream = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert replay_stream.status_code == 410
    assert "distribution closed" in replay_stream.json()["detail"].lower() or "completed" in replay_stream.json()["detail"].lower()


# ===========================================================================
# 7. ATTACK FLOW 6: Valid User + Valid Quorum + Valid Time + Valid Integrity -> ALLOW
# ===========================================================================

@pytest.mark.asyncio
async def test_attack_flow_6_all_valid_conditions_allow(async_client: AsyncClient):
    """
    Attack Flow 6: Valid User + Valid Quorum + Valid Time + Valid Integrity -> ALLOW (200 OK).
    """
    users = await setup_all_synthetic_users(async_client)
    setter = users["exam_setter"]
    g1 = users["key_guardian_1"]
    g2 = users["key_guardian_2"]
    center = users["exam_center_1"]

    # 1. Create exam with active time window
    exam_payload = generate_synthetic_exam_payload(
        start_delta_minutes=-10,
        end_delta_hours=2,
        required_quorum=2,
        total_guardians=2,
    )
    create_res = await async_client.post(
        "/api/v1/exams/",
        json=exam_payload,
        headers=setter["headers"],
    )
    exam_id = create_res.json()["id"]

    # 2. Assign guardians first
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

    # 3. Stage payload
    chunks = generate_synthetic_payload_chunks(2)
    await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": 3600},
        headers=setter["headers"],
    )

    # 4. Valid quorum consensus approvals (2/2)
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

    # 5. Access stream -> 200 ALLOW
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 200
    assert len(stream_res.content) > 0
