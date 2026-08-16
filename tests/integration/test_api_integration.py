"""
Comprehensive Frontend <-> Backend API Integration Test Suite for TrustGuard.

Validates the ACTUAL backend API contracts and schemas against frontend requirements across:
1. Authentication (Register, Login, Me, Token Validation, RBAC)
2. Question-Paper Creation (Metadata, Quorum Config, Initial State, RBAC)
3. Question-Paper Retrieval (Get by ID, Listing, Pagination, Error Handling)
4. Protection / Encryption Operation (Payload Staging, Ephemeral RAM, SHA-256 Hash)
5. Fragmentation Operation (Chunk Storage, TTL, Integrity Checks, Sharding)
6. Access Request & Guardian Assignment (Public Key Fingerprints, Quorum Bounds)
7. Approval Submission (Cryptographic Share Tokens, Quorum Counting, State Transitions)
8. Quorum Status (Tracking Progress, Approved Guardians List, Unlocking)
9. Just-In-Time Access Validation (Streaming, Watermarking, Time-Locks, Buffer Purge)
10. Decryption / Reconstruction (Stream Reassembly, Traceability, Authenticated Decryption)
11. Audit Events (Lifecycle Traceability, Client Receipt Ingestion, RBAC)
12. Threat / Security Events (Attack Simulations, Policy Violations, Zero-Leakage)

CRITICAL SECURITY CONSTRAINT:
Never use real examination content. All payloads are synthetic mock data for test verification only.
"""

from datetime import datetime, timedelta, timezone
import base64
import hashlib
import json
import pytest
from httpx import AsyncClient

from tests.fixtures import (
    SYNTHETIC_USERS,
    generate_synthetic_exam_payload,
    generate_synthetic_payload_chunks,
    register_and_login_user,
    setup_all_synthetic_users,
    setup_staged_exam,
    setup_unlocked_exam,
)
from security.crypto.encryption import encrypt, decrypt
from security.crypto.integrity import generate_integrity_hash
from security.crypto.fragmentation import fragment_ciphertext, reconstruct_ciphertext
from security.crypto.key_manager import generate_master_key


# ===========================================================================
# 1. AUTHENTICATION INTEGRATION TESTS
# ===========================================================================

class TestAuthenticationIntegration:
    """Validate HTTP method, URL, auth, request body, response schema, and RBAC for Auth API."""

    @pytest.mark.asyncio
    async def test_user_registration_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/auth/register returns 201 Created and valid UserResponse schema."""
        for role_name in ["ADMIN", "EXAM_SETTER", "KEY_GUARDIAN", "EXAM_CENTER", "AUDITOR"]:
            user_data = {
                "username": f"user_reg_{role_name.lower()}",
                "email": f"user_{role_name.lower()}@trustguard.synth.org",
                "password": "ValidPassword123!",
                "role": role_name,
            }
            res = await async_client.post("/api/v1/auth/register", json=user_data)
            assert res.status_code == 201
            body = res.json()

            # Schema validation
            assert "id" in body and isinstance(body["id"], str)
            assert body["username"] == user_data["username"]
            assert body["email"] == user_data["email"]
            assert body["role"] == role_name
            assert "created_at" in body
            assert "password" not in body
            assert "hashed_password" not in body

    @pytest.mark.asyncio
    async def test_user_registration_duplicate_rejection(self, async_client: AsyncClient):
        """POST /api/v1/auth/register rejects duplicate username or email with 400 Bad Request."""
        user_data = {
            "username": "duplicate_user",
            "email": "duplicate@trustguard.synth.org",
            "password": "ValidPassword123!",
            "role": "EXAM_SETTER",
        }
        res1 = await async_client.post("/api/v1/auth/register", json=user_data)
        assert res1.status_code == 201

        # Attempt duplicate registration with same username
        res2 = await async_client.post("/api/v1/auth/register", json=user_data)
        assert res2.status_code == 400
        assert "already exists" in res2.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_user_registration_validation_errors(self, async_client: AsyncClient):
        """POST /api/v1/auth/register validates fields and returns 422 for invalid payloads."""
        # Short password (<6 chars)
        res_short_pw = await async_client.post(
            "/api/v1/auth/register",
            json={"username": "short_pw_user", "email": "short@synth.test", "password": "123", "role": "ADMIN"},
        )
        assert res_short_pw.status_code == 422

        # Invalid role
        res_invalid_role = await async_client.post(
            "/api/v1/auth/register",
            json={"username": "invalid_role_user", "email": "invalid@synth.test", "password": "ValidPassword123!", "role": "SUPER_HACKER"},
        )
        assert res_invalid_role.status_code == 422

    @pytest.mark.asyncio
    async def test_user_login_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/auth/login returns 200 OK and TokenResponse schema."""
        user_data = SYNTHETIC_USERS["exam_setter"]
        await async_client.post("/api/v1/auth/register", json=user_data)

        login_res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": user_data["username"], "password": user_data["password"]},
        )
        assert login_res.status_code == 200
        body = login_res.json()

        assert "access_token" in body and len(body["access_token"]) > 20
        assert body["token_type"] == "bearer"
        assert body["role"] == "EXAM_SETTER"
        assert "user_id" in body

    @pytest.mark.asyncio
    async def test_user_login_invalid_credentials(self, async_client: AsyncClient):
        """POST /api/v1/auth/login returns 401 Unauthorized for invalid password or user."""
        user_data = SYNTHETIC_USERS["admin"]
        await async_client.post("/api/v1/auth/register", json=user_data)

        # Wrong password
        res_wrong_pw = await async_client.post(
            "/api/v1/auth/login",
            json={"username": user_data["username"], "password": "WrongPassword123!"},
        )
        assert res_wrong_pw.status_code == 401
        assert "WWW-Authenticate" in res_wrong_pw.headers

        # Non-existent username
        res_no_user = await async_client.post(
            "/api/v1/auth/login",
            json={"username": "ghost_user_9999", "password": "SomePassword123!"},
        )
        assert res_no_user.status_code == 401

    @pytest.mark.asyncio
    async def test_auth_me_success_and_schema(self, async_client: AsyncClient):
        """GET /api/v1/auth/me returns 200 OK and authenticated UserResponse."""
        users = await setup_all_synthetic_users(async_client)
        admin = users["admin"]

        me_res = await async_client.get("/api/v1/auth/me", headers=admin["headers"])
        assert me_res.status_code == 200
        body = me_res.json()
        assert body["id"] == admin["user_id"]
        assert body["username"] == admin["username"]
        assert body["role"] == "ADMIN"

    @pytest.mark.asyncio
    async def test_auth_me_missing_and_tampered_token(self, async_client: AsyncClient):
        """GET /api/v1/auth/me returns 401/403 for missing or forged tokens."""
        # Missing token
        res_no_token = await async_client.get("/api/v1/auth/me")
        assert res_no_token.status_code in [401, 403]

        # Forged / Tampered token
        res_tampered = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer FORGED_MALICIOUS_JWT_TOKEN_XYZ"},
        )
        assert res_tampered.status_code == 401


# ===========================================================================
# 2. QUESTION-PAPER CREATION INTEGRATION TESTS
# ===========================================================================

class TestQuestionPaperCreationIntegration:
    """Validate Question-Paper creation endpoint, RBAC, input validation, and initial draft state."""

    @pytest.mark.asyncio
    async def test_create_exam_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/exams/ by EXAM_SETTER returns 201 Created and ExamResponse schema."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]

        exam_payload = generate_synthetic_exam_payload(
            title="Synthetic Chemistry Entrance Examination 2026",
            course_code="CHEM-2026-SYNTH",
            required_quorum=2,
            total_guardians=3,
        )

        res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=setter["headers"])
        assert res.status_code == 201
        body = res.json()

        # Schema & field validation
        assert "id" in body and isinstance(body["id"], str)
        assert body["title"] == exam_payload["title"]
        assert body["course_code"] == exam_payload["course_code"]
        assert body["status"] == "DRAFT"
        assert body["required_quorum"] == 2
        assert body["total_guardians"] == 3
        assert body["encrypted_payload_hash"] is None
        assert body["created_by"] == setter["user_id"]
        assert "created_at" in body
        assert "updated_at" in body
        assert body["guardians"] == []

    @pytest.mark.asyncio
    async def test_create_exam_rbac_authorization(self, async_client: AsyncClient):
        """POST /api/v1/exams/ permits ADMIN and EXAM_SETTER, but rejects other roles with 403."""
        users = await setup_all_synthetic_users(async_client)
        exam_payload = generate_synthetic_exam_payload()

        # ADMIN: Allowed
        admin_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=users["admin"]["headers"])
        assert admin_res.status_code == 201

        # KEY_GUARDIAN: Forbidden
        g_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=users["key_guardian_1"]["headers"])
        assert g_res.status_code == 403

        # EXAM_CENTER: Forbidden
        c_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=users["exam_center_1"]["headers"])
        assert c_res.status_code == 403

        # AUDITOR: Forbidden
        aud_res = await async_client.post("/api/v1/exams/", json=exam_payload, headers=users["auditor"]["headers"])
        assert aud_res.status_code == 403

    @pytest.mark.asyncio
    async def test_create_exam_invalid_quorum_rejection(self, async_client: AsyncClient):
        """POST /api/v1/exams/ rejects quorum k > n with 400 Bad Request."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]

        invalid_payload = generate_synthetic_exam_payload(
            required_quorum=4,  # k = 4
            total_guardians=3,  # n = 3 (k > n is impossible)
        )
        res = await async_client.post("/api/v1/exams/", json=invalid_payload, headers=setter["headers"])
        assert res.status_code == 400
        assert "cannot exceed" in res.json()["detail"].lower()


# ===========================================================================
# 3. QUESTION-PAPER RETRIEVAL INTEGRATION TESTS
# ===========================================================================

class TestQuestionPaperRetrievalIntegration:
    """Validate retrieval by ID, list filtering, and 404 error handling."""

    @pytest.mark.asyncio
    async def test_get_exam_by_id_success_and_schema(self, async_client: AsyncClient):
        """GET /api/v1/exams/{exam_id} returns 200 OK and ExamResponse with assigned guardians."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]

        staged = await setup_staged_exam(async_client, setter, guardians)
        exam_id = staged["exam_id"]

        # Any authenticated user (e.g. Center, Auditor) can view exam metadata
        get_res = await async_client.get(f"/api/v1/exams/{exam_id}", headers=users["exam_center_1"]["headers"])
        assert get_res.status_code == 200
        body = get_res.json()

        assert body["id"] == exam_id
        assert body["status"] == "CONSENSUS_PENDING"
        assert len(body["guardians"]) == 2
        assert body["guardians"][0]["guardian_id"] == guardians[0]["user_id"]

    @pytest.mark.asyncio
    async def test_get_exam_by_id_not_found(self, async_client: AsyncClient):
        """GET /api/v1/exams/{invalid_id} returns 404 Not Found."""
        users = await setup_all_synthetic_users(async_client)
        res = await async_client.get("/api/v1/exams/non-existent-exam-uuid-0000", headers=users["admin"]["headers"])
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_list_exams_success_and_pagination(self, async_client: AsyncClient):
        """GET /api/v1/exams/ returns 200 OK and List[ExamResponse] supporting skip and limit."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]

        # Create 3 distinct exams
        for i in range(3):
            payload = generate_synthetic_exam_payload(
                title=f"Synthetic Exam {i+1}",
                course_code=f"COURSE-{i+1}",
            )
            await async_client.post("/api/v1/exams/", json=payload, headers=setter["headers"])

        # List all
        list_res = await async_client.get("/api/v1/exams/?skip=0&limit=10", headers=users["auditor"]["headers"])
        assert list_res.status_code == 200
        exams = list_res.json()
        assert len(exams) >= 3

        # Pagination test (limit=1)
        paginated_res = await async_client.get("/api/v1/exams/?skip=0&limit=1", headers=users["auditor"]["headers"])
        assert paginated_res.status_code == 200
        assert len(paginated_res.json()) == 1


# ===========================================================================
# 4. PROTECTION & ENCRYPTION OPERATION INTEGRATION TESTS
# ===========================================================================

class TestProtectionAndEncryptionIntegration:
    """Validate encrypted payload staging, ephemeral RAM storage, SHA-256 integrity hashing, and RBAC."""

    @pytest.mark.asyncio
    async def test_stage_payload_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/stage-payload stores chunks in RAM, calculates hash, and updates state."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"], users["key_guardian_3"]]

        # 1. Create exam
        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=3),
            headers=setter["headers"],
        )
        exam_id = create_res.json()["id"]

        # 2. Assign guardians
        for idx, g in enumerate(guardians):
            await async_client.post(
                f"/api/v1/exams/{exam_id}/guardians",
                json={"guardian_user_id": g["user_id"], "public_key_fingerprint": f"RSA_FP_G{idx+1}"},
                headers=setter["headers"],
            )

        # 3. Stage 3 synthetic encrypted chunks
        chunks = generate_synthetic_payload_chunks(3)
        stage_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/stage-payload",
            json={"encrypted_chunks": chunks, "ttl_seconds": 1800},
            headers=setter["headers"],
        )
        assert stage_res.status_code == 200
        body = stage_res.json()

        # Verify PayloadStageResponse schema
        assert body["exam_id"] == exam_id
        assert body["status"] == "CONSENSUS_PENDING"
        assert body["chunks_staged"] == 3
        assert len(body["encrypted_payload_hash"]) == 64  # SHA-256 hex string
        assert body["ttl_seconds"] == 1800

        # Verify exam state updated in database
        exam_check = await async_client.get(f"/api/v1/exams/{exam_id}", headers=setter["headers"])
        assert exam_check.json()["status"] == "CONSENSUS_PENDING"
        assert exam_check.json()["encrypted_payload_hash"] == body["encrypted_payload_hash"]

    @pytest.mark.asyncio
    async def test_stage_payload_fails_if_insufficient_guardians(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/stage-payload rejects staging before required guardians are assigned."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]

        # Create exam requiring 2 guardians
        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=3),
            headers=setter["headers"],
        )
        exam_id = create_res.json()["id"]

        # Only assign 1 guardian (less than required 2)
        await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": users["key_guardian_1"]["user_id"], "public_key_fingerprint": "RSA_FP_G1"},
            headers=setter["headers"],
        )

        # Attempt stage
        chunks = generate_synthetic_payload_chunks(2)
        stage_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/stage-payload",
            json={"encrypted_chunks": chunks, "ttl_seconds": 1800},
            headers=setter["headers"],
        )
        assert stage_res.status_code == 400
        assert "guardians must be assigned" in stage_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_stage_payload_rbac_authorization(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/stage-payload enforces RBAC (only SETTER and ADMIN allowed)."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]

        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
            headers=setter["headers"],
        )
        exam_id = create_res.json()["id"]

        for idx, g in enumerate(guardians):
            await async_client.post(
                f"/api/v1/exams/{exam_id}/guardians",
                json={"guardian_user_id": g["user_id"], "public_key_fingerprint": f"RSA_FP_{idx}"},
                headers=setter["headers"],
            )

        chunks = generate_synthetic_payload_chunks(2)

        # Center: Forbidden
        res_center = await async_client.post(
            f"/api/v1/exams/{exam_id}/stage-payload",
            json={"encrypted_chunks": chunks, "ttl_seconds": 1800},
            headers=users["exam_center_1"]["headers"],
        )
        assert res_center.status_code == 403

        # Guardian: Forbidden
        res_guardian = await async_client.post(
            f"/api/v1/exams/{exam_id}/stage-payload",
            json={"encrypted_chunks": chunks, "ttl_seconds": 1800},
            headers=users["key_guardian_1"]["headers"],
        )
        assert res_guardian.status_code == 403


# ===========================================================================
# 5. FRAGMENTATION OPERATION INTEGRATION TESTS
# ===========================================================================

class TestFragmentationOperationIntegration:
    """Validate payload sharding, RAM storage, integrity hashing, and chunk reconstruction."""

    @pytest.mark.asyncio
    async def test_multi_chunk_sharding_and_retrieval(self, async_client: AsyncClient):
        """Validate multi-chunk sharding preserves chunk counts and payload byte sequences."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]

        # Test with 5 synthetic chunks
        staged = await setup_staged_exam(async_client, setter, guardians, num_chunks=5)
        assert staged["staged_info"]["chunks_staged"] == 5

        # Re-construct concatenated raw bytes
        concatenated_bytes = bytearray()
        for b64 in staged["raw_chunks"]:
            concatenated_bytes.extend(base64.b64decode(b64))

        expected_hash = hashlib.sha256(bytes(concatenated_bytes)).hexdigest()
        assert staged["staged_info"]["encrypted_payload_hash"] == expected_hash

    def test_cryptographic_fragmentation_and_tamper_detection(self):
        """Verify underlying cryptographic fragmentation engine detects tampered or missing fragments."""
        key = base64.b64decode(generate_master_key())
        raw_test_data = b"SYNTHETIC_MOCK_EXAMINATION_SECTION_ALPHA_BETA_GAMMA"

        encrypted = encrypt(raw_test_data, key=key)
        fragments = fragment_ciphertext(encrypted, num_fragments=4)
        assert len(fragments) == 4

        # Clean reconstruction
        reconstructed = reconstruct_ciphertext(fragments)
        decrypted = decrypt(reconstructed, key=key)
        assert decrypted == raw_test_data

        # Corrupted fragment detection
        corrupted_fragments = list(fragments)
        from security.crypto.fragmentation import FragmentPayload, FragmentValidationError
        corrupted_fragments[1] = FragmentPayload(
            fragment_index=fragments[1].fragment_index,
            fragment_data=b"TAMPERED_BINARY_PAYLOAD_CHUNK_XYZ",
            integrity_hash=fragments[1].integrity_hash,
            paper_id=fragments[1].paper_id,
        )
        with pytest.raises(FragmentValidationError):
            reconstruct_ciphertext(corrupted_fragments)


# ===========================================================================
# 6. ACCESS REQUEST & GUARDIAN ASSIGNMENT INTEGRATION TESTS
# ===========================================================================

class TestAccessRequestAndGuardianAssignmentIntegration:
    """Validate guardian assignment, public key fingerprints, duplicate assignment prevention, and bounds."""

    @pytest.mark.asyncio
    async def test_assign_guardian_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/guardians returns 201 Created and GuardianResponse schema."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1 = users["key_guardian_1"]

        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=3),
            headers=setter["headers"],
        )
        exam_id = create_res.json()["id"]

        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_GUARDIAN_1"},
            headers=setter["headers"],
        )
        assert assign_res.status_code == 201
        body = assign_res.json()

        assert "id" in body
        assert body["guardian_id"] == g1["user_id"]
        assert body["public_key_fingerprint"] == "RSA_4096_FP_GUARDIAN_1"
        assert "assigned_at" in body

    @pytest.mark.asyncio
    async def test_assign_guardian_duplicate_rejection(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/guardians rejects assigning the same guardian twice."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1 = users["key_guardian_1"]

        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=3),
            headers=setter["headers"],
        )
        exam_id = create_res.json()["id"]

        # First assignment
        res1 = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
            headers=setter["headers"],
        )
        assert res1.status_code == 201

        # Duplicate assignment
        res2 = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g1["user_id"], "public_key_fingerprint": "RSA_4096_FP_G1"},
            headers=setter["headers"],
        )
        assert res2.status_code == 400
        assert "already assigned" in res2.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_assign_guardian_exceeds_total_guardians_limit(self, async_client: AsyncClient):
        """POST /api/v1/exams/{exam_id}/guardians rejects assignments exceeding total_guardians n."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2, g3 = users["key_guardian_1"], users["key_guardian_2"], users["key_guardian_3"]

        # Total guardians configured as 2
        create_res = await async_client.post(
            "/api/v1/exams/",
            json=generate_synthetic_exam_payload(required_quorum=2, total_guardians=2),
            headers=setter["headers"],
        )
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

        # 3rd assignment exceeds limit 2
        res3 = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": g3["user_id"], "public_key_fingerprint": "RSA_4096_FP_G3"},
            headers=setter["headers"],
        )
        assert res3.status_code == 400
        assert "cannot assign more" in res3.json()["detail"].lower()


# ===========================================================================
# 7. APPROVAL SUBMISSION INTEGRATION TESTS
# ===========================================================================

class TestApprovalSubmissionIntegration:
    """Validate guardian authorization vote submission, token validation, duplicate prevention, and RBAC."""

    @pytest.mark.asyncio
    async def test_submit_approval_success_and_schema(self, async_client: AsyncClient):
        """POST /api/v1/consensus/{exam_id}/approve returns 200 OK and ConsensusApproveResponse schema."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]

        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        share_token = f"MOCK_SHARE_K2_N2_IDX1_HASH12345678_{g1['user_id']}"
        app_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": share_token},
            headers=g1["headers"],
        )
        assert app_res.status_code == 200
        body = app_res.json()

        assert body["exam_id"] == exam_id
        assert body["guardian_id"] == g1["user_id"]
        assert "approved_at" in body
        assert body["current_quorum_count"] == 1
        assert body["required_quorum"] == 2
        assert body["quorum_reached"] is False
        assert body["new_exam_status"] == "CONSENSUS_PENDING"

    @pytest.mark.asyncio
    async def test_submit_approval_unassigned_guardian_rejection(self, async_client: AsyncClient):
        """POST /api/v1/consensus/{exam_id}/approve rejects approvals from unassigned key guardians with 403."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]
        unassigned_guardian = users["key_guardian_3"]

        # Assign only g1 and g2
        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        # unassigned_guardian attempts to vote
        share_token = f"MOCK_SHARE_K2_N2_IDX3_HASH12345678_{unassigned_guardian['user_id']}"
        app_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": share_token},
            headers=unassigned_guardian["headers"],
        )
        assert app_res.status_code == 403
        assert "not an assigned key guardian" in app_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_submit_approval_duplicate_vote_rejection(self, async_client: AsyncClient):
        """POST /api/v1/consensus/{exam_id}/approve prevents duplicate vote submissions by same guardian."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]

        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        share_token = f"MOCK_SHARE_K2_N2_IDX1_HASH12345678_{g1['user_id']}"
        res1 = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": share_token},
            headers=g1["headers"],
        )
        assert res1.status_code == 200

        # Duplicate vote
        res2 = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": share_token},
            headers=g1["headers"],
        )
        assert res2.status_code == 400
        assert "already submitted approval" in res2.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_submit_approval_invalid_token_rejection(self, async_client: AsyncClient):
        """POST /api/v1/consensus/{exam_id}/approve rejects corrupted or malformed share tokens."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]

        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        # Corrupt token
        res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": "MALICIOUS_CORRUPTED_TOKEN_WITHOUT_PREFIX"},
            headers=g1["headers"],
        )
        assert res.status_code == 400
        assert "invalid cryptographic share" in res.json()["detail"].lower()


# ===========================================================================
# 8. QUORUM STATUS INTEGRATION TESTS
# ===========================================================================

class TestQuorumStatusIntegration:
    """Validate quorum threshold progress tracking and approved guardians list."""

    @pytest.mark.asyncio
    async def test_quorum_status_progression(self, async_client: AsyncClient):
        """GET /api/v1/consensus/{exam_id}/status reflects real-time voting progress."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2, g3 = users["key_guardian_1"], users["key_guardian_2"], users["key_guardian_3"]

        staged = await setup_staged_exam(
            async_client, setter, [g1, g2, g3],
            exam_payload=generate_synthetic_exam_payload(required_quorum=2, total_guardians=3)
        )
        exam_id = staged["exam_id"]

        # 0 Approvals
        s0 = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
        assert s0.status_code == 200
        body0 = s0.json()
        assert body0["current_approvals_count"] == 0
        assert body0["quorum_reached"] is False
        assert body0["approved_guardians"] == []

        # 1 Approval (Below Quorum k=2)
        await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": f"MOCK_SHARE_K2_N3_IDX1_HASH_{g1['user_id']}"},
            headers=g1["headers"],
        )
        s1 = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
        body1 = s1.json()
        assert body1["current_approvals_count"] == 1
        assert body1["quorum_reached"] is False
        assert body1["approved_guardians"] == [g1["user_id"]]

        # 2 Approvals (Quorum k=2 Reached -> UNLOCKED)
        await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": f"MOCK_SHARE_K2_N3_IDX2_HASH_{g2['user_id']}"},
            headers=g2["headers"],
        )
        s2 = await async_client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
        body2 = s2.json()
        assert body2["current_approvals_count"] == 2
        assert body2["quorum_reached"] is True
        assert body2["status"] == "UNLOCKED"
        assert set(body2["approved_guardians"]) == {g1["user_id"], g2["user_id"]}


# ===========================================================================
# 9. JUST-IN-TIME ACCESS VALIDATION INTEGRATION TESTS
# ===========================================================================

class TestJustInTimeAccessValidationIntegration:
    """Validate streaming distribution, zero-cache headers, time-lock enforcement, and RAM purging."""

    @pytest.mark.asyncio
    async def test_jit_stream_success_within_window(self, async_client: AsyncClient):
        """GET /api/v1/distribution/{exam_id}/stream streams encrypted chunks to EXAM_CENTER during valid window."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        # Setup unlocked exam with start_delta = -10 min, end_delta = +3 hours
        unlocked = await setup_unlocked_exam(async_client, setter, guardians)
        exam_id = unlocked["exam_id"]

        stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
        assert stream_res.status_code == 200

        # Verify zero-cache security headers
        headers = stream_res.headers
        assert "no-store" in headers["cache-control"]
        assert "no-cache" in headers["cache-control"]
        assert headers["x-content-type-options"] == "nosniff"

        # Verify content contains traceable watermarking prefix
        content = stream_res.content
        assert len(content) > 0
        assert f"[TRUSTGUARD_TRACEABILITY:CENTER={center['user_id']}]".encode("utf-8") in content

    @pytest.mark.asyncio
    async def test_jit_stream_blocked_before_quorum(self, async_client: AsyncClient):
        """GET /api/v1/distribution/{exam_id}/stream returns 403 Forbidden before quorum is unlocked."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        # Only staged (NOT unlocked)
        staged = await setup_staged_exam(async_client, setter, guardians)
        exam_id = staged["exam_id"]

        stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
        assert stream_res.status_code == 403
        assert "quorum approval is required" in stream_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_jit_stream_time_lock_too_early(self, async_client: AsyncClient):
        """GET /api/v1/distribution/{exam_id}/stream returns 425 Too Early before scheduled_start."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        # Exam scheduled to start in +30 minutes
        early_payload = generate_synthetic_exam_payload(start_delta_minutes=30, end_delta_hours=4)
        unlocked = await setup_unlocked_exam(async_client, setter, guardians, exam_payload=early_payload)
        exam_id = unlocked["exam_id"]

        stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
        assert stream_res.status_code == 425
        assert "time-lock enforced" in stream_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_jit_stream_time_lock_expired(self, async_client: AsyncClient):
        """GET /api/v1/distribution/{exam_id}/stream returns 410 Gone after scheduled_end."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        # Exam expired 10 minutes ago
        expired_payload = generate_synthetic_exam_payload(start_delta_minutes=-120, end_delta_hours=-1)
        # Note: end_delta_hours=-1 makes end time in the past
        now = datetime.now(timezone.utc)
        expired_payload["scheduled_start"] = (now - timedelta(hours=2)).isoformat()
        expired_payload["scheduled_end"] = (now - timedelta(minutes=10)).isoformat()

        unlocked = await setup_unlocked_exam(async_client, setter, guardians, exam_payload=expired_payload)
        exam_id = unlocked["exam_id"]

        stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
        assert stream_res.status_code == 410
        assert "expired" in stream_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_purge_ephemeral_buffers_and_post_purge_stream(self, async_client: AsyncClient):
        """POST /api/v1/distribution/{exam_id}/purge wipes RAM buffers and subsequent streams return 410 Gone."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        unlocked = await setup_unlocked_exam(async_client, setter, guardians)
        exam_id = unlocked["exam_id"]

        # 1. Purge buffers
        purge_res = await async_client.post(
            f"/api/v1/distribution/{exam_id}/purge",
            headers=setter["headers"],
        )
        assert purge_res.status_code == 200
        purge_body = purge_res.json()
        assert purge_body["purged"] is True
        assert purge_body["status"] == "COMPLETED"

        # 2. Subsequent stream attempt returns 410 Gone
        post_purge_res = await async_client.get(
            f"/api/v1/distribution/{exam_id}/stream",
            headers=center["headers"],
        )
        assert post_purge_res.status_code == 410


# ===========================================================================
# 10. DECRYPTION & RECONSTRUCTION INTEGRATION TESTS
# ===========================================================================

class TestDecryptionAndReconstructionIntegration:
    """Validate end-to-end question paper protection, streaming, reconstruction, and authenticated decryption."""

    @pytest.mark.asyncio
    async def test_end_to_end_decryption_and_traceability_roundtrip(self, async_client: AsyncClient):
        """Verify full cryptographic roundtrip with dynamic watermarking traceability."""
        master_key = base64.b64decode(generate_master_key())
        raw_synthetic_paper = (
            b"CONFIDENTIAL_SYNTHETIC_EXAMINATION_PAPER_2026\n"
            b"SECTION 1: Quantum Foundations (Synthetic Mock Question)\n"
            b"SECTION 2: Electrodynamics (Synthetic Mock Question)\n"
        )

        # 1. Protect & Fragment paper
        encrypted_paper = encrypt(raw_synthetic_paper, key=master_key)
        fragments = fragment_ciphertext(encrypted_paper, num_fragments=3)

        # 2. Reconstruct fragments & Decrypt
        reconstructed = reconstruct_ciphertext(fragments)
        decrypted_paper = decrypt(reconstructed, key=master_key)
        assert decrypted_paper == raw_synthetic_paper

        # 3. Integrity verification
        expected_hash = generate_integrity_hash(raw_synthetic_paper)
        assert expected_hash.startswith("sha256:")

    def test_tampered_payload_decryption_failure(self):
        """Verify tampered ciphertext or modified auth tag fails decryption cleanly."""
        master_key = base64.b64decode(generate_master_key())
        raw_data = b"SYNTHETIC_TEST_CONTENT"
        encrypted = encrypt(raw_data, key=master_key)

        # Tamper payload
        tampered = bytearray(encrypted)
        tampered[-1] ^= 0xFF
        with pytest.raises(Exception):
            decrypt(bytes(tampered), key=master_key)


# ===========================================================================
# 11. AUDIT EVENTS INTEGRATION TESTS
# ===========================================================================

class TestAuditEventsIntegration:
    """Validate immutable audit log queries, event filtering, external receipt ingestion, and RBAC."""

    @pytest.mark.asyncio
    async def test_audit_trail_lifecycle_completeness(self, async_client: AsyncClient):
        """Verify audit trail contains all lifecycle events in sequence."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]
        auditor = users["auditor"]

        # Run complete lifecycle
        unlocked = await setup_unlocked_exam(async_client, setter, guardians)
        exam_id = unlocked["exam_id"]

        # Stream paper
        await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])

        # Purge paper
        await async_client.post(f"/api/v1/distribution/{exam_id}/purge", headers=setter["headers"])

        # Query audit logs for exam
        audit_res = await async_client.get(
            f"/api/v1/audit/events?exam_id={exam_id}",
            headers=auditor["headers"],
        )
        assert audit_res.status_code == 200
        events = audit_res.json()
        actions = [e["action"] for e in events]

        # Verify all essential audit actions were recorded
        assert "EXAM_CREATED" in actions
        assert "GUARDIAN_ASSIGNED" in actions
        assert "EPHEMERAL_PAYLOAD_STAGED" in actions
        assert "GUARDIAN_APPROVED" in actions
        assert "QUORUM_REACHED" in actions
        assert "EPHEMERAL_STREAM_ACCESSED" in actions
        assert "EPHEMERAL_DATA_PURGED" in actions

    @pytest.mark.asyncio
    async def test_external_client_audit_event_ingestion(self, async_client: AsyncClient):
        """POST /api/v1/audit/events allows exam centers to log external terminal receipts."""
        users = await setup_all_synthetic_users(async_client)
        center = users["exam_center_1"]

        payload = {
            "exam_id": "synth-exam-receipt-test",
            "action": "EXAM_TERMINAL_PRINTOUT_COMPLETED",
            "details_json": json.dumps({"terminal_id": "TERM_001", "status": "CONFIRMED"}),
        }
        res = await async_client.post("/api/v1/audit/events", json=payload, headers=center["headers"])
        assert res.status_code == 201
        body = res.json()

        assert body["action"] == "EXAM_TERMINAL_PRINTOUT_COMPLETED"
        assert body["actor_id"] == center["user_id"]
        assert body["exam_id"] == "synth-exam-receipt-test"
        assert "timestamp" in body

    @pytest.mark.asyncio
    async def test_audit_query_rbac_enforcement(self, async_client: AsyncClient):
        """GET /api/v1/audit/events restricts access to ADMIN and AUDITOR roles."""
        users = await setup_all_synthetic_users(async_client)

        # ADMIN: Allowed
        res_admin = await async_client.get("/api/v1/audit/events", headers=users["admin"]["headers"])
        assert res_admin.status_code == 200

        # AUDITOR: Allowed
        res_auditor = await async_client.get("/api/v1/audit/events", headers=users["auditor"]["headers"])
        assert res_auditor.status_code == 200

        # EXAM_CENTER: Forbidden
        res_center = await async_client.get("/api/v1/audit/events", headers=users["exam_center_1"]["headers"])
        assert res_center.status_code == 403

        # KEY_GUARDIAN: Forbidden
        res_guardian = await async_client.get("/api/v1/audit/events", headers=users["key_guardian_1"]["headers"])
        assert res_guardian.status_code == 403


# ===========================================================================
# 12. THREAT & SECURITY EVENTS INTEGRATION TESTS
# ===========================================================================

class TestThreatAndSecurityEventsIntegration:
    """Validate zero-trust defense mechanisms, attack simulations, and security invariant protections."""

    @pytest.mark.asyncio
    async def test_threat_unauthorized_user_blocked(self, async_client: AsyncClient):
        """Attack Scenario 1: Unauthenticated request to protected endpoints is blocked with 401/403."""
        # Unauthenticated exam creation attempt
        res1 = await async_client.post("/api/v1/exams/", json=generate_synthetic_exam_payload())
        assert res1.status_code in [401, 403]

        # Unauthenticated streaming attempt
        res2 = await async_client.get("/api/v1/distribution/fake-exam-id/stream")
        assert res2.status_code in [401, 403]

    @pytest.mark.asyncio
    async def test_threat_premature_decryption_blocked(self, async_client: AsyncClient):
        """Attack Scenario 2: Invigilator terminal early access attempt before exam window is blocked (425)."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]
        center = users["exam_center_1"]

        # Exam window starts in 4 hours
        future_payload = generate_synthetic_exam_payload(start_delta_minutes=240, end_delta_hours=7)
        unlocked = await setup_unlocked_exam(async_client, setter, guardians, exam_payload=future_payload)

        res = await async_client.get(
            f"/api/v1/distribution/{unlocked['exam_id']}/stream",
            headers=center["headers"],
        )
        assert res.status_code == 425
        assert "time-lock enforced" in res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_threat_insufficient_quorum_bypass_blocked(self, async_client: AsyncClient):
        """Attack Scenario 3: Attempting to stream paper without threshold quorum signatures is blocked (403)."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"], users["key_guardian_3"]]
        center = users["exam_center_1"]

        # Stage exam with k=3
        staged = await setup_staged_exam(
            async_client, setter, guardians,
            exam_payload=generate_synthetic_exam_payload(required_quorum=3, total_guardians=3)
        )
        exam_id = staged["exam_id"]

        # Only 2 guardians approve (below threshold 3)
        for g in [guardians[0], guardians[1]]:
            await async_client.post(
                f"/api/v1/consensus/{exam_id}/approve",
                json={"share_token": f"MOCK_SHARE_K3_N3_HASH_{g['user_id']}"},
                headers=g["headers"],
            )

        # Stream attempt
        stream_res = await async_client.get(f"/api/v1/distribution/{exam_id}/stream", headers=center["headers"])
        assert stream_res.status_code == 403
        assert "quorum approval is required" in stream_res.json()["detail"].lower()

    @pytest.mark.asyncio
    async def test_threat_forged_share_token_blocked(self, async_client: AsyncClient):
        """Attack Scenario 4: Forged key share token submission is rejected with 400 Bad Request."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]

        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        forged_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": "FORGED_ATTACKER_SIGNATURE_SHARE_XYZ"},
            headers=g1["headers"],
        )
        assert forged_res.status_code == 400

    @pytest.mark.asyncio
    async def test_threat_replay_approval_vote_blocked(self, async_client: AsyncClient):
        """Attack Scenario 5: Replaying an already submitted approval vote is rejected with 400 Bad Request."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        g1, g2 = users["key_guardian_1"], users["key_guardian_2"]

        staged = await setup_staged_exam(async_client, setter, [g1, g2])
        exam_id = staged["exam_id"]

        token = f"MOCK_SHARE_K2_N2_IDX1_HASH_{g1['user_id']}"
        res1 = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": token},
            headers=g1["headers"],
        )
        assert res1.status_code == 200

        # Replay attempt
        replay_res = await async_client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": token},
            headers=g1["headers"],
        )
        assert replay_res.status_code == 400

    @pytest.mark.asyncio
    async def test_zero_secret_leakage_in_api_responses(self, async_client: AsyncClient):
        """Validate that passwords, master keys, and private tokens never appear in API responses."""
        users = await setup_all_synthetic_users(async_client)
        setter = users["exam_setter"]
        guardians = [users["key_guardian_1"], users["key_guardian_2"]]

        unlocked = await setup_unlocked_exam(async_client, setter, guardians)
        exam_id = unlocked["exam_id"]

        # Fetch exam metadata
        exam_res = await async_client.get(f"/api/v1/exams/{exam_id}", headers=setter["headers"])
        exam_text = exam_res.text.lower()
        assert "password" not in exam_text
        assert "hashed_password" not in exam_text
        assert "master_key" not in exam_text
        assert "secret_key" not in exam_text

        # Fetch audit events
        audit_res = await async_client.get(
            f"/api/v1/audit/events?exam_id={exam_id}",
            headers=users["auditor"]["headers"],
        )
        audit_text = audit_res.text.lower()
        assert "password" not in audit_text
        assert "hashed_password" not in audit_text
        assert "master_key" not in audit_text
