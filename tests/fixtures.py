"""
Reusable test fixtures and synthetic data generators for TrustGuard API Integration Tests.

CRITICAL SECURITY CONSTRAINT:
Never use real examination content. All payloads, question papers, and keys
must be purely synthetic mock data for test verification only.
"""

from datetime import datetime, timedelta, timezone
import base64
import hashlib
from typing import Any, Dict, List
import pytest
from httpx import AsyncClient


# ---------------------------------------------------------------------------
# Synthetic Test User Fixtures (Across All 5 RBAC Roles)
# ---------------------------------------------------------------------------

SYNTHETIC_USERS: Dict[str, Dict[str, str]] = {
    "admin": {
        "username": "synth_admin",
        "email": "admin@trustguard.synth.org",
        "password": "AdminPassword2026!",
        "role": "ADMIN",
    },
    "exam_setter": {
        "username": "synth_exam_setter",
        "email": "setter@trustguard.synth.org",
        "password": "SetterPassword2026!",
        "role": "EXAM_SETTER",
    },
    "key_guardian_1": {
        "username": "synth_guardian_alpha",
        "email": "guardian1@trustguard.synth.org",
        "password": "GuardianPassword1!",
        "role": "KEY_GUARDIAN",
    },
    "key_guardian_2": {
        "username": "synth_guardian_beta",
        "email": "guardian2@trustguard.synth.org",
        "password": "GuardianPassword2!",
        "role": "KEY_GUARDIAN",
    },
    "key_guardian_3": {
        "username": "synth_guardian_gamma",
        "email": "guardian3@trustguard.synth.org",
        "password": "GuardianPassword3!",
        "role": "KEY_GUARDIAN",
    },
    "exam_center_1": {
        "username": "synth_center_north",
        "email": "center.north@trustguard.synth.org",
        "password": "CenterPassword2026!",
        "role": "EXAM_CENTER",
    },
    "exam_center_2": {
        "username": "synth_center_south",
        "email": "center.south@trustguard.synth.org",
        "password": "CenterPassword2026!",
        "role": "EXAM_CENTER",
    },
    "auditor": {
        "username": "synth_auditor_chief",
        "email": "auditor@trustguard.synth.org",
        "password": "AuditorPassword2026!",
        "role": "AUDITOR",
    },
}


# ---------------------------------------------------------------------------
# Synthetic Examination Paper Fixtures
# ---------------------------------------------------------------------------

def generate_synthetic_exam_payload(
    title: str = "Synthetic Test Examination - Advanced Physics",
    course_code: str = "SYNTH-PHY-2026",
    start_delta_minutes: int = -10,
    end_delta_hours: int = 3,
    required_quorum: int = 2,
    total_guardians: int = 3,
) -> Dict[str, Any]:
    """Generate a clean synthetic examination creation payload with configurable time-lock window."""
    now = datetime.now(timezone.utc)
    return {
        "title": title,
        "course_code": course_code,
        "scheduled_start": (now + timedelta(minutes=start_delta_minutes)).isoformat(),
        "scheduled_end": (now + timedelta(hours=end_delta_hours)).isoformat(),
        "required_quorum": required_quorum,
        "total_guardians": total_guardians,
    }


def generate_synthetic_payload_chunks(num_chunks: int = 3) -> List[str]:
    """Generate synthetic base64-encoded encrypted mock paper chunks.
    
    Contains structured synthetic mock test sections (zero real exam content).
    """
    chunks = []
    for i in range(num_chunks):
        synthetic_chunk_data = (
            f"--- SYNTHETIC ENCRYPTED CHUNK {i+1} OF {num_chunks} ---\n"
            f"SECTION: Mock Section {chr(65+i)}\n"
            f"CONTENT: [SYNTHETIC_MOCK_QUESTION_DATA_BLOCK_{i+1}_CHECKSUM={hashlib.sha256(f'chunk_{i}'.encode()).hexdigest()[:16]}]\n"
            f"TIMESTAMP: {datetime.now(timezone.utc).isoformat()}\n"
            f"--- END SYNTHETIC CHUNK {i+1} ---"
        ).encode("utf-8")
        chunks.append(base64.b64encode(synthetic_chunk_data).decode("utf-8"))
    return chunks


# ---------------------------------------------------------------------------
# Helper Functions for Registration, Authentication & Lifecycle Setup
# ---------------------------------------------------------------------------

async def register_and_login_user(
    client: AsyncClient,
    user_data: Dict[str, str],
) -> Dict[str, Any]:
    """Register a synthetic user, log in, and return credentials with auth headers."""
    # 1. Register
    reg_res = await client.post("/api/v1/auth/register", json=user_data)
    assert reg_res.status_code == 201, f"Failed to register user {user_data['username']}: {reg_res.text}"
    user_info = reg_res.json()

    # 2. Login
    login_res = await client.post(
        "/api/v1/auth/login",
        json={"username": user_data["username"], "password": user_data["password"]},
    )
    assert login_res.status_code == 200, f"Failed to login user {user_data['username']}: {login_res.text}"
    token_data = login_res.json()

    return {
        "user_id": user_info["id"],
        "username": user_info["username"],
        "email": user_info["email"],
        "role": user_info["role"],
        "access_token": token_data["access_token"],
        "token_type": token_data["token_type"],
        "headers": {"Authorization": f"Bearer {token_data['access_token']}"},
        "user_info": user_info,
        "raw_credentials": user_data,
    }


async def setup_all_synthetic_users(client: AsyncClient) -> Dict[str, Dict[str, Any]]:
    """Register and authenticate all synthetic role personas."""
    users = {}
    for key, data in SYNTHETIC_USERS.items():
        users[key] = await register_and_login_user(client, data)
    return users


async def setup_staged_exam(
    client: AsyncClient,
    setter: Dict[str, Any],
    guardians: List[Dict[str, Any]],
    exam_payload: Dict[str, Any] = None,
    num_chunks: int = 3,
    ttl_seconds: int = 3600,
) -> Dict[str, Any]:
    """Create exam, assign guardians, and stage encrypted payload chunks in Ephemeral RAM."""
    if exam_payload is None:
        exam_payload = generate_synthetic_exam_payload(
            required_quorum=len(guardians) if len(guardians) < 2 else 2,
            total_guardians=len(guardians),
        )

    # 1. Create exam
    create_res = await client.post("/api/v1/exams/", json=exam_payload, headers=setter["headers"])
    assert create_res.status_code == 201, f"Create exam failed: {create_res.text}"
    exam = create_res.json()
    exam_id = exam["id"]

    # 2. Assign guardians
    guardian_assignments = []
    for idx, g in enumerate(guardians):
        assign_res = await client.post(
            f"/api/v1/exams/{exam_id}/guardians",
            json={
                "guardian_user_id": g["user_id"],
                "public_key_fingerprint": f"RSA_4096_FP_G{idx+1}_{g['username'].upper()}",
            },
            headers=setter["headers"],
        )
        assert assign_res.status_code == 201, f"Assign guardian {g['username']} failed: {assign_res.text}"
        guardian_assignments.append(assign_res.json())

    # 3. Stage payload
    chunks = generate_synthetic_payload_chunks(num_chunks)
    stage_res = await client.post(
        f"/api/v1/exams/{exam_id}/stage-payload",
        json={"encrypted_chunks": chunks, "ttl_seconds": ttl_seconds},
        headers=setter["headers"],
    )
    assert stage_res.status_code == 200, f"Stage payload failed: {stage_res.text}"
    staged_info = stage_res.json()

    # Re-fetch exam
    get_res = await client.get(f"/api/v1/exams/{exam_id}", headers=setter["headers"])
    updated_exam = get_res.json()

    return {
        "exam_id": exam_id,
        "exam": updated_exam,
        "guardians": guardian_assignments,
        "staged_info": staged_info,
        "raw_chunks": chunks,
    }


async def setup_unlocked_exam(
    client: AsyncClient,
    setter: Dict[str, Any],
    guardians: List[Dict[str, Any]],
    exam_payload: Dict[str, Any] = None,
    num_chunks: int = 3,
) -> Dict[str, Any]:
    """Execute complete lifecycle up to UNLOCKED quorum state."""
    staged = await setup_staged_exam(
        client=client,
        setter=setter,
        guardians=guardians,
        exam_payload=exam_payload,
        num_chunks=num_chunks,
    )
    exam_id = staged["exam_id"]
    required_quorum = staged["exam"]["required_quorum"]

    # Submit approvals up to required quorum
    approvals = []
    for idx in range(required_quorum):
        g = guardians[idx]
        share_token = f"MOCK_SHARE_K{required_quorum}_N{len(guardians)}_IDX{idx+1}_HASH12345678_{g['user_id']}"
        app_res = await client.post(
            f"/api/v1/consensus/{exam_id}/approve",
            json={"share_token": share_token},
            headers=g["headers"],
        )
        assert app_res.status_code == 200, f"Approval by {g['username']} failed: {app_res.text}"
        approvals.append(app_res.json())

    # Verify status is AUTHORIZED or UNLOCKED
    status_res = await client.get(f"/api/v1/consensus/{exam_id}/status", headers=setter["headers"])
    assert status_res.status_code == 200
    quorum_status = status_res.json()
    assert quorum_status["quorum_reached"] is True
    assert quorum_status["status"] in ["AUTHORIZED", "UNLOCKED"]

    return {
        **staged,
        "approvals": approvals,
        "quorum_status": quorum_status,
    }
