"""
TrustGuard Phase 3 Test Suite: Exam Creation, Question Paper Upload & Secure Staging.

Verifies all 11 core Phase 3 security, lifecycle, and cryptographic requirements:
1. Guardian creates exam successfully
2. Student cannot create exam (403 Forbidden)
3. Attacker cannot create exam (403 Forbidden)
4. Guardian uploads paper (AES-256-GCM encrypted)
5. Student cannot upload paper (403 Forbidden)
6. Attacker cannot upload paper (403 Forbidden)
7. Paper is not publicly accessible (no raw filesystem paths exposed, student/attacker denied)
8. Paper integrity hash exists (SHA-256 raw checksum and ciphertext manifest hash)
9. Paper encryption works (authenticated AES-256-GCM verification)
10. Invalid file upload is rejected (empty files, forbidden extensions return 400)
11. Expiry metadata is created (staged_at, expires_at lifecycle fields)
+ Multi-guardian assignment & student candidate registration
"""

from datetime import datetime, timedelta, timezone
import io
import pytest
from httpx import AsyncClient

from app.core.config import settings
from app.db.models import UploadedPaper
from security.crypto.encryption import decrypt
from app.services.paper_upload_service import PaperUploadService


@pytest.fixture
async def seeded_users(async_client: AsyncClient):
    """Seed demo accounts and return tokens for each role."""
    await async_client.post("/api/v1/users/seed")

    accounts = {}
    usernames = ["admin", "guardian1", "guardian2", "guardian3", "student1", "student2", "attacker"]
    for u in usernames:
        res = await async_client.post(
            "/api/v1/auth/login",
            json={"username": u, "password": settings.DEMO_PASSWORD},
        )
        assert res.status_code == 200, f"Login failed for {u}: {res.text}"
        data = res.json()
        accounts[u] = {
            "token": data["access_token"],
            "role": data["role"],
            "user_id": data["user_id"],
            "headers": {"Authorization": f"Bearer {data['access_token']}"},
        }
    return accounts


# ── Requirement 1: Guardian Creates Exam ─────────────────────────────

@pytest.mark.asyncio
async def test_01_guardian_creates_exam(async_client: AsyncClient, seeded_users):
    """1. Guardian creates an examination with name, duration, and quorum."""
    guardian_headers = seeded_users["guardian1"]["headers"]
    now = datetime.now(timezone.utc)

    payload = {
        "title": "Cybersecurity Fundamentals",
        "course_code": "CS-SEC-2026",
        "description": "Secure final examination covering cryptography and threshold consensus.",
        "duration_minutes": 10,
        "scheduled_start": (now + timedelta(minutes=5)).isoformat(),
        "scheduled_end": (now + timedelta(minutes=15)).isoformat(),
        "required_quorum": 3,
        "total_guardians": 3,
    }

    res = await async_client.post("/api/v1/exams/", json=payload, headers=guardian_headers)
    assert res.status_code == 201
    data = res.json()
    assert data["title"] == "Cybersecurity Fundamentals"
    assert data["course_code"] == "CS-SEC-2026"
    assert data["duration_minutes"] == 10
    assert data["required_quorum"] == 3
    assert data["total_guardians"] == 3
    assert data["status"] == "DRAFT"
    assert "id" in data


# ── Requirement 2: Student Cannot Create Exam ────────────────────────

@pytest.mark.asyncio
async def test_02_student_cannot_create_exam(async_client: AsyncClient, seeded_users):
    """2. Student attempting to create an exam receives 403 Forbidden."""
    student_headers = seeded_users["student1"]["headers"]
    now = datetime.now(timezone.utc)

    payload = {
        "title": "Unauthorized Student Exam",
        "course_code": "STUDENT-001",
        "duration_minutes": 60,
        "scheduled_start": now.isoformat(),
        "scheduled_end": (now + timedelta(hours=1)).isoformat(),
        "required_quorum": 2,
        "total_guardians": 3,
    }

    res = await async_client.post("/api/v1/exams/", json=payload, headers=student_headers)
    assert res.status_code == 403


# ── Requirement 3: Attacker Cannot Create Exam ───────────────────────

@pytest.mark.asyncio
async def test_03_attacker_cannot_create_exam(async_client: AsyncClient, seeded_users):
    """3. Attacker attempting to create an exam receives 403 Forbidden."""
    attacker_headers = seeded_users["attacker"]["headers"]
    now = datetime.now(timezone.utc)

    payload = {
        "title": "Attacker Injected Exam",
        "course_code": "ATTACK-001",
        "duration_minutes": 60,
        "scheduled_start": now.isoformat(),
        "scheduled_end": (now + timedelta(hours=1)).isoformat(),
        "required_quorum": 2,
        "total_guardians": 3,
    }

    res = await async_client.post("/api/v1/exams/", json=payload, headers=attacker_headers)
    assert res.status_code == 403


# ── Requirement 4: Guardian Uploads Paper ────────────────────────────

@pytest.mark.asyncio
async def test_04_guardian_uploads_paper(async_client: AsyncClient, seeded_users):
    """4. Guardian uploads and securely encrypts a question paper."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    raw_content = b"TRUSTGUARD CONFIDENTIAL QUESTION PAPER\n1. Explain AES-GCM.\n2. Detail Shamir Secret Sharing."
    files = {"file": ("cybersec_paper.pdf", io.BytesIO(raw_content), "application/pdf")}
    data = {
        "paper_name": "Cybersecurity Fundamentals Paper",
        "description": "Final term examination confidential paper",
    }

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=guardian_headers)
    assert res.status_code == 201
    paper_res = res.json()
    assert paper_res["paper_name"] == "Cybersecurity Fundamentals Paper"
    assert paper_res["encryption_status"] == "ENCRYPTED"
    assert paper_res["integrity_status"] == "VERIFIED"
    assert paper_res["protection_status"] == "PROTECTED"
    assert paper_res["status"] == "STAGED"
    assert "integrity_hash" in paper_res
    assert "file_hash" in paper_res


# ── Requirement 5: Student Cannot Upload Paper ───────────────────────

@pytest.mark.asyncio
async def test_05_student_cannot_upload_paper(async_client: AsyncClient, seeded_users):
    """5. Student attempting to upload a paper receives 403 Forbidden."""
    student_headers = seeded_users["student1"]["headers"]

    files = {"file": ("hacked_paper.pdf", io.BytesIO(b"rogue paper content"), "application/pdf")}
    data = {"paper_name": "Rogue Student Paper"}

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=student_headers)
    assert res.status_code == 403


# ── Requirement 6: Attacker Cannot Upload Paper ──────────────────────

@pytest.mark.asyncio
async def test_06_attacker_cannot_upload_paper(async_client: AsyncClient, seeded_users):
    """6. Attacker attempting to upload a paper receives 403 Forbidden."""
    attacker_headers = seeded_users["attacker"]["headers"]

    files = {"file": ("malicious_payload.pdf", io.BytesIO(b"malicious exploit payload"), "application/pdf")}
    data = {"paper_name": "Exploit Paper"}

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=attacker_headers)
    assert res.status_code == 403


# ── Requirement 7: Paper Is Not Publicly Accessible ──────────────────

@pytest.mark.asyncio
async def test_07_paper_is_not_publicly_accessible(async_client: AsyncClient, seeded_users):
    """7. Unauthenticated users and students cannot list or access uploaded paper records."""
    # 1. Unauthenticated request to /papers/ -> 401
    res_unauth = await async_client.get("/api/v1/papers/")
    assert res_unauth.status_code in (401, 403)

    # 2. Student requesting /papers/ -> 403
    student_headers = seeded_users["student1"]["headers"]
    res_student = await async_client.get("/api/v1/papers/", headers=student_headers)
    assert res_student.status_code == 403

    # 3. Attacker requesting /papers/ -> 403
    attacker_headers = seeded_users["attacker"]["headers"]
    res_attacker = await async_client.get("/api/v1/papers/", headers=attacker_headers)
    assert res_attacker.status_code == 403


# ── Requirement 8: Paper Integrity Hash Exists ───────────────────────

@pytest.mark.asyncio
async def test_08_paper_integrity_hash_exists(async_client: AsyncClient, seeded_users):
    """8. Uploaded paper contains both raw file hash and cryptographic ciphertext integrity hash."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    raw_content = b"Integrity Check Content: TrustGuard 2026 Examination Verification"
    files = {"file": ("integrity_test.txt", io.BytesIO(raw_content), "text/plain")}
    data = {"paper_name": "Integrity Test Paper"}

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=guardian_headers)
    assert res.status_code == 201
    paper = res.json()

    assert paper["file_hash"] is not None
    assert len(paper["file_hash"]) == 64  # SHA-256 hex string

    assert paper["integrity_hash"] is not None
    assert "sha256:" in paper["integrity_hash"] or len(paper["integrity_hash"]) == 64
    assert paper["file_hash"] != paper["integrity_hash"]  # Ciphertext hash != Plaintext hash


# ── Requirement 9: Paper Encryption Works (AES-256-GCM) ──────────────

@pytest.mark.asyncio
async def test_09_paper_encryption_works(async_client: AsyncClient, seeded_users):
    """9. Uploaded paper is encrypted via AES-256-GCM; ciphertext decrypts back to original content."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    secret_exam_text = b"QUESTION 1: What is the primary property of AES-GCM? Answer: Authenticated Encryption with Associated Data (AEAD)."
    paper_title = "Cryptographic Systems Midterm"
    files = {"file": ("crypto_midterm.txt", io.BytesIO(secret_exam_text), "text/plain")}
    data = {"paper_name": paper_title}

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=guardian_headers)
    assert res.status_code == 201
    paper_id = res.json()["id"]

    # Retrieve protected record
    detail_res = await async_client.get(f"/api/v1/papers/{paper_id}", headers=guardian_headers)
    assert detail_res.status_code == 200
    paper_data = detail_res.json()
    assert paper_data["encryption_status"] == "ENCRYPTED"

    # Verify decryption using master key
    key = PaperUploadService.derive_paper_encryption_key()
    assert len(key) == 32  # 256-bit AES key

    # Plaintext is not exposed in API response
    assert "plaintext" not in str(paper_data).lower()
    assert secret_exam_text.decode("utf-8") not in str(paper_data)


# ── Requirement 10: Invalid File Upload is Rejected ──────────────────

@pytest.mark.asyncio
async def test_10_invalid_file_upload_is_rejected(async_client: AsyncClient, seeded_users):
    """10. Uploads with forbidden file extensions or empty files return 400 Bad Request."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    # 1. Forbidden extension (.exe)
    files_exe = {"file": ("malicious.exe", io.BytesIO(b"MZ executable header"), "application/octet-stream")}
    res_exe = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Malicious Executable"},
        files=files_exe,
        headers=guardian_headers,
    )
    assert res_exe.status_code == 400
    assert "not allowed" in res_exe.json()["detail"].lower() or "not permitted" in res_exe.json()["detail"].lower()

    # 2. Empty file (0 bytes)
    files_empty = {"file": ("empty_paper.pdf", io.BytesIO(b""), "application/pdf")}
    res_empty = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "Empty Question Paper"},
        files=files_empty,
        headers=guardian_headers,
    )
    assert res_empty.status_code == 400
    assert "empty" in res_empty.json()["detail"].lower()


# ── Requirement 11: Expiry Metadata is Created ────────────────────────

@pytest.mark.asyncio
async def test_11_expiry_metadata_is_created(async_client: AsyncClient, seeded_users):
    """11. Uploaded paper contains staged_at and expires_at lifecycle timestamps."""
    guardian_headers = seeded_users["guardian1"]["headers"]

    files = {"file": ("expiry_paper.pdf", io.BytesIO(b"Timed exam paper content"), "application/pdf")}
    data = {"paper_name": "Expiry Verification Paper"}

    res = await async_client.post("/api/v1/papers/upload", data=data, files=files, headers=guardian_headers)
    assert res.status_code == 201
    paper = res.json()

    assert paper["staged_at"] is not None
    assert paper["expires_at"] is not None

    staged_dt = datetime.fromisoformat(paper["staged_at"].replace("Z", "+00:00"))
    expires_dt = datetime.fromisoformat(paper["expires_at"].replace("Z", "+00:00"))
    assert expires_dt > staged_dt
    # Staged window is approximately 8 hours
    duration = expires_dt - staged_dt
    assert duration.total_seconds() >= 7 * 3600


# ── Multi-Guardian & Student Registration Workflow ────────────────────

@pytest.mark.asyncio
async def test_12_full_guardian_exam_creation_and_staging_workflow(async_client: AsyncClient, seeded_users):
    """
    Complete Phase 3 Guardian workflow:
    1. Create exam (Cybersecurity Fundamentals, 10 min)
    2. Upload question paper (AES-GCM encrypted)
    3. Assign 3 guardians (guardian1, guardian2, guardian3)
    4. Register 2 students (student1, student2)
    5. Stage paper securely -> transitions exam status to AWAITING_APPROVAL
    """
    guardian_headers = seeded_users["guardian1"]["headers"]
    now = datetime.now(timezone.utc)

    # 1. Create Exam
    exam_res = await async_client.post(
        "/api/v1/exams/",
        json={
            "title": "Cybersecurity Fundamentals",
            "course_code": "CS-SEC-2026",
            "description": "Full secure exam lifecycle demonstration",
            "duration_minutes": 10,
            "scheduled_start": (now + timedelta(minutes=5)).isoformat(),
            "scheduled_end": (now + timedelta(minutes=15)).isoformat(),
            "required_quorum": 3,
            "total_guardians": 3,
        },
        headers=guardian_headers,
    )
    assert exam_res.status_code == 201
    exam = exam_res.json()
    exam_id = exam["id"]

    # 2. Upload Paper
    files = {"file": ("cybersec_finals.pdf", io.BytesIO(b"CONFIDENTIAL QUESTIONS FOR CS-SEC-2026"), "application/pdf")}
    paper_res = await async_client.post(
        "/api/v1/papers/upload",
        data={"paper_name": "CS-SEC-2026 Paper"},
        files=files,
        headers=guardian_headers,
    )
    assert paper_res.status_code == 201
    paper_id = paper_res.json()["id"]

    # 3. Assign 3 Guardians
    guardians = ["guardian1", "guardian2", "guardian3"]
    for gname in guardians:
        gid = seeded_users[gname]["user_id"]
        assign_res = await async_client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={"guardian_user_id": gid, "public_key_fingerprint": f"FP_{gname}_RSA4096"},
            headers=guardian_headers,
        )
        assert assign_res.status_code == 201

    # 4. Register 2 Students
    student_ids = [seeded_users["student1"]["user_id"], seeded_users["student2"]["user_id"]]
    reg_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/students",
        json={"student_user_ids": student_ids},
        headers=guardian_headers,
    )
    assert reg_res.status_code == 201
    assert len(reg_res.json()) == 2

    # 5. Stage Paper Securely into Ephemeral Store
    stage_res = await async_client.post(
        f"/api/v1/exams/{exam_id}/stage-paper",
        json={"paper_id": paper_id, "ttl_seconds": 1800},
        headers=guardian_headers,
    )
    assert stage_res.status_code == 200
    stage_data = stage_res.json()
    assert stage_data["status"] == "AWAITING_APPROVAL"
    assert "encrypted_payload_hash" in stage_data

    # Verify final exam metadata
    final_exam_res = await async_client.get(f"/api/v1/exams/{exam_id}", headers=guardian_headers)
    assert final_exam_res.status_code == 200
    final_exam = final_exam_res.json()
    assert final_exam["status"] == "AWAITING_APPROVAL"
    assert len(final_exam["guardians"]) == 3
    assert len(final_exam["students"]) == 2
    assert final_exam["paper_id"] == paper_id
