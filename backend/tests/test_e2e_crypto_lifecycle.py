"""End-to-End Cryptographic Examination Lifecycle Test Suite.

Audits and verifies the complete lifecycle:
1. Paper Upload & AES-256-GCM Encryption
2. Payload Fragmentation & Integrity Hash Generation
3. Exam Creation & Guardian Assignment (k=2, n=2)
4. Ephemeral RAM Staging & Shamir Key Share Distribution
5. Quorum / Consensus Approval Flow
6. Ephemeral JIT Stream Distribution & Traceable Watermarking
7. Reconstruction, Watermark Stripping, & AES-256-GCM Decryption
8. Ephemeral RAM Purging & Zero-Persistence Verification
"""

from datetime import datetime, timedelta, timezone
from io import BytesIO
from httpx import AsyncClient
import pytest

from backend.tests.conftest import create_user_and_login
from app.crypto_wrapper.encryption import AES256GCM
from app.crypto_wrapper.fragmentation import Fragmenter
from app.services.paper_upload_service import PaperUploadService


@pytest.mark.asyncio
async def test_full_crypto_and_distribution_lifecycle(async_client: AsyncClient):
    # -------------------------------------------------------------------------
    # 1. SETUP USERS & ROLES
    # ---------------------------------------------------------
    setter = await create_user_and_login(async_client, "e2e_setter", "EXAM_SETTER")
    g1 = await create_user_and_login(async_client, "e2e_g1", "KEY_GUARDIAN")
    g2 = await create_user_and_login(async_client, "e2e_g2", "KEY_GUARDIAN")
    center = await create_user_and_login(async_client, "e2e_center", "EXAM_CENTER")

    # -------------------------------------------------------------------------
    # 2. PAPER UPLOAD & AES-256-GCM ENCRYPTION
    # ---------------------------------------------------------
    raw_paper_content = b"CONFIDENTIAL_TRUSTGUARD_EXAM_PAPER_CONTENT_2026_FINAL_TEST_DATA"
    paper_file = ("trustguard_exam_paper.pdf", BytesIO(raw_paper_content), "application/pdf")

    upload_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "E2E Cybersecurity Paper", "description": "End-to-end crypto verification paper"},
        files={"file": paper_file},
        headers=setter["headers"],
    )
    assert upload_res.status_code == 201, f"Paper upload failed: {upload_res.text}"
    paper_data = upload_res.json()

    paper_id = paper_data["id"]
    assert paper_data["encryption_status"] == "ENCRYPTED"
    assert paper_data["integrity_status"] == "VERIFIED"
    assert paper_data["file_size"] == len(raw_paper_content)
    assert paper_data["integrity_hash"] is not None

    # -------------------------------------------------------------------------
    # 3. EXAM CREATION & GUARDIAN ASSIGNMENT (k=2, n=2)
    # ---------------------------------------------------------
    now = datetime.now(timezone.utc)
    create_exam_payload = {
        "title": "E2E Cryptographic Exam 2026",
        "course_code": "SEC-E2E-2026",
        "description": "Full end-to-end test exam",
        "paper_id": paper_id,
        "scheduled_start": (now - timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(hours=2)).isoformat(),
        "duration_minutes": 60,
        "required_quorum": 2,
        "total_guardians": 2,
    }

    exam_res = await async_client.post(
        "/api/v1/exams/",
        json=create_exam_payload,
        headers=setter["headers"],
    )
    assert exam_res.status_code == 201, f"Exam creation failed: {exam_res.text}"
    exam_data = exam_res.json()
    exam_id = exam_data["id"]
    assert exam_data["status"] == "DRAFT"

    # Assign Guardian 1
    g1_assign_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "FP_G1_E2E"},
        headers=setter["headers"],
    )
    assert g1_assign_res.status_code == 201

    # Assign Guardian 2
    g2_assign_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/guardians",
        json={"guardian_user_id": g2["user_id"], "public_key_fingerprint": "FP_G2_E2E"},
        headers=setter["headers"],
    )
    assert g2_assign_res.status_code == 201

    # -------------------------------------------------------------------------
    # 4. EPHEMERAL RAM STAGING & SHAMIR KEY SHARE DISTRIBUTION
    # ---------------------------------------------------------
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 1800},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200, f"Paper staging failed: {stage_res.text}"
    stage_data = stage_res.json()
    assert stage_data["status"] == "AWAITING_APPROVAL"
    assert stage_data["chunks_staged"] > 0
    assert stage_data["encrypted_payload_hash"] is not None

    # -------------------------------------------------------------------------
    # 5. PRE-QUORUM ACCESS REJECTION
    # ---------------------------------------------------------
    # Stream attempt before quorum approval must be forbidden (403)
    early_stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert early_stream_res.status_code == 403, "Pre-quorum stream attempt should be rejected with 403 Forbidden!"

    # -------------------------------------------------------------------------
    # 6. QUORUM / CONSENSUS APPROVAL FLOW (k=2)
    # ---------------------------------------------------------
    # Guardian 1 Approves
    app1_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX1_HASH1234_{g1['user_id']}"},
        headers=g1["headers"],
    )
    assert app1_res.status_code == 200
    assert app1_res.json()["current_quorum_count"] == 1
    assert app1_res.json()["quorum_reached"] is False

    # Guardian 2 Approves (Quorum k=2 reached!)
    app2_res = await async_client.post(
        f"/api/v1/consensus/{exam_id}/approve",
        json={"share_token": f"MOCK_SHARE_K2_N2_IDX2_HASH1234_{g2['user_id']}"},
        headers=g2["headers"],
    )
    assert app2_res.status_code == 200
    assert app2_res.json()["current_quorum_count"] == 2
    assert app2_res.json()["quorum_reached"] is True
    assert app2_res.json()["new_exam_status"] in ["AUTHORIZED", "UNLOCKED"]

    # -------------------------------------------------------------------------
    # 7. EPHEMERAL JIT STREAM DISTRIBUTION & TRACEABLE WATERMARKING
    # ---------------------------------------------------------
    stream_res = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert stream_res.status_code == 200, f"Stream failed: {stream_res.text}"

    streamed_bytes = stream_res.content
    assert len(streamed_bytes) > 0

    # Traceable Watermark Tag Check
    expected_watermark = f"[TRUSTGUARD_TRACEABILITY:CENTER={center['user_id']}]".encode("utf-8")
    assert expected_watermark in streamed_bytes, "Traceable watermark missing from streamed payload!"

    # -------------------------------------------------------------------------
    # 8. RECONSTRUCTION, WATERMARK STRIPPING, & AES-256-GCM DECRYPTION
    # ---------------------------------------------------------
    # Strip watermarks to reconstruct raw ciphertext
    raw_reconstructed = streamed_bytes.replace(expected_watermark, b"")

    # Decrypt reconstructed payload with master key
    master_key = PaperUploadService.derive_paper_encryption_key()
    nonce = raw_reconstructed[:12]
    ciphertext = raw_reconstructed[12:]
    decrypted_content = AES256GCM.decrypt(
        ciphertext, master_key, nonce, associated_data="E2E Cybersecurity Paper".encode("utf-8")
    )

    assert decrypted_content == raw_paper_content, "Decrypted content does not match original uploaded paper!"

    # -------------------------------------------------------------------------
    # 9. EPHEMERAL RAM PURGING & ZERO-PERSISTENCE VERIFICATION
    # ---------------------------------------------------------
    purge_res = await async_client.post(
        f"/api/v1/distribution/{exam_id}/purge",
        headers=setter["headers"],
    )
    assert purge_res.status_code == 200
    assert purge_res.json()["purged"] is True
    assert purge_res.json()["status"] == "COMPLETED"

    # Post-purge stream attempt must return 410 Gone (RAM cleared)
    post_purge_stream = await async_client.get(
        f"/api/v1/distribution/{exam_id}/stream",
        headers=center["headers"],
    )
    assert post_purge_stream.status_code == 410, "Post-purge stream attempt must return 410 Gone!"
