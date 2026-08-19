"""Automated Test Suite for Blockchain Ledger & Verification Module.

Verifies:
1. Successful Hash Recording
2. Successful Verification
3. Tampered Payload Detection
4. Invalid / Missing Ledger Record
5. Ledger-Chain Integrity Audit
"""

from httpx import AsyncClient
import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from backend.tests.conftest import create_user_and_login
from app.db.models import BlockchainBlock
from app.services.blockchain_service import BlockchainService


@pytest.mark.asyncio
async def test_blockchain_hash_recording_and_retrieval(async_client: AsyncClient):
    """Test recording a payload hash to the immutable ledger and retrieving the block."""
    setter = await create_user_and_login(async_client, "bc_setter1", "EXAM_SETTER")

    exam_id = "test_exam_bc_001"
    paper_id = "test_paper_bc_001"
    payload_hash = "a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890a1b2c3d4e5f67890"

    # POST /api/v1/blockchain/record
    res = await async_client.post(
        "/api/v1/blockchain/record",
        json={"exam_id": exam_id, "paper_id": paper_id, "payload_hash": payload_hash},
        headers=setter["headers"],
    )

    assert res.status_code == 201, f"Recording block failed: {res.text}"
    block_data = res.json()

    assert block_data["index"] >= 1
    assert block_data["exam_id"] == exam_id
    assert block_data["paper_id"] == paper_id
    assert block_data["payload_hash"] == payload_hash
    assert block_data["block_hash"] is not None
    assert block_data["prev_block_hash"] is not None


@pytest.mark.asyncio
async def test_blockchain_successful_verification(async_client: AsyncClient):
    """Test verifying a matching payload hash against the recorded ledger block."""
    setter = await create_user_and_login(async_client, "bc_setter2", "EXAM_SETTER")

    exam_id = "test_exam_bc_002"
    payload_hash = "11223344556677889900aabbccddeeff11223344556677889900aabbccddeeff"

    # Record hash
    await async_client.post(
        "/api/v1/blockchain/record",
        json={"exam_id": exam_id, "payload_hash": payload_hash},
        headers=setter["headers"],
    )

    # GET /api/v1/blockchain/verify/{exam_id}?current_hash=...
    res = await async_client.get(
        f"/api/v1/blockchain/verify/{exam_id}?current_hash={payload_hash}",
    )

    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "VERIFIED"
    assert data["verified"] is True
    assert data["exam_id"] == exam_id
    assert data["recorded_hash"] == payload_hash
    assert data["current_hash"] == payload_hash
    assert data["chain_valid"] is True


@pytest.mark.asyncio
async def test_blockchain_tampered_payload_detection(async_client: AsyncClient):
    """Test that providing a tampered/mismatched hash triggers TAMPER_DETECTED."""
    setter = await create_user_and_login(async_client, "bc_setter3", "EXAM_SETTER")

    exam_id = "test_exam_bc_003"
    original_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
    tampered_hash = "badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad1"

    # Record original hash
    await async_client.post(
        "/api/v1/blockchain/record",
        json={"exam_id": exam_id, "payload_hash": original_hash},
        headers=setter["headers"],
    )

    # Verify with tampered hash
    res = await async_client.get(
        f"/api/v1/blockchain/verify/{exam_id}?current_hash={tampered_hash}",
    )

    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "TAMPER_DETECTED"
    assert data["verified"] is False
    assert data["recorded_hash"] == original_hash
    assert data["current_hash"] == tampered_hash
    assert "CRITICAL INTEGRITY FAILURE" in data["message"]


@pytest.mark.asyncio
async def test_blockchain_missing_ledger_record(async_client: AsyncClient):
    """Test verifying an exam that has no recorded blockchain ledger entry."""
    res = await async_client.get(
        "/api/v1/blockchain/verify/non_existent_exam_id_9999",
    )

    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "MISSING_RECORD"
    assert data["verified"] is False
    assert "No blockchain ledger record found" in data["message"]


@pytest.mark.asyncio
async def test_blockchain_ledger_chain_integrity(async_client: AsyncClient):
    """Test multi-block chaining and verifying overall ledger chain integrity."""
    setter = await create_user_and_login(async_client, "bc_setter4", "EXAM_SETTER")

    # Record 3 sequential blocks
    for i in range(1, 4):
        await async_client.post(
            "/api/v1/blockchain/record",
            json={
                "exam_id": f"chain_exam_{i}",
                "payload_hash": f"hash_value_chain_test_00{i}" * 4,
            },
            headers=setter["headers"],
        )

    # GET /api/v1/blockchain/chain
    res = await async_client.get("/api/v1/blockchain/chain")
    assert res.status_code == 200
    chain_data = res.json()

    assert chain_data["total_blocks"] >= 3
    assert chain_data["chain_valid"] is True
    assert len(chain_data["tampered_blocks"]) == 0
