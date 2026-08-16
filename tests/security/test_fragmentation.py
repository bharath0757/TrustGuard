"""
TrustGuard — Encrypted Fragment Distribution Tests.

Comprehensive security test suite verifying:
  1. Normal fragmentation (configurable fragment counts, index assignments, integrity hashes)
  2. Normal reconstruction (accurate reassembly of protected representation)
  3. Reordered fragments (correct reassembly from shuffled / reverse shard sequences)
  4. Missing fragment detection (raises MissingFragmentError / FragmentCountMismatchError)
  5. Duplicate fragment detection (raises DuplicateFragmentError)
  6. Corrupted fragment detection (raises FragmentIntegrityError on data alteration, CorruptedFragmentError on status)
  7. Fragment from wrong paper detection (raises FragmentPaperMismatchError)
  8. Invalid fragment index (negative or out-of-bounds index raises FragmentValidationError)
  9. Reconstruction failure handling (empty lists, invalid inputs, no silent corruptions)
  10. End-to-end reconstruction + decryption workflow integrated with database models
"""
import copy
import os
import random
import uuid
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from database.base import Base
from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from security.crypto.encryption import encrypt, decrypt, DecryptionFailedError
from security.crypto.integrity import generate_integrity_hash
from security.crypto.fragmentation import (
    FragmentationError,
    FragmentValidationError,
    FragmentPaperMismatchError,
    FragmentCountMismatchError,
    DuplicateFragmentError,
    MissingFragmentError,
    CorruptedFragmentError,
    FragmentIntegrityError,
    FragmentPayload,
    fragment_ciphertext,
    validate_fragments,
    reconstruct_ciphertext,
    protect_and_fragment_paper,
    retrieve_paper_fragments,
    reconstruct_and_decrypt_paper,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def master_key() -> bytes:
    """32-byte AES-256 master key."""
    return os.urandom(32)


@pytest.fixture
def paper_id() -> uuid.UUID:
    """Sample paper UUID."""
    return uuid.uuid4()


@pytest.fixture
def exam_plaintext() -> bytes:
    return (
        b"CONFIDENTIAL NATIONAL BOARD EXAMINATION 2026\n"
        b"SECTION A: Advanced Operating Systems and Zero-Trust Architectures\n"
        b"Question 1: Explain the security model of Encrypted Fragment Distribution."
    )


@pytest.fixture
def encrypted_payload(exam_plaintext, master_key) -> bytes:
    """AES-256-GCM encrypted protected representation."""
    return encrypt(exam_plaintext, master_key)


@pytest.fixture
def db_session():
    """In-memory SQLite database session with all tables created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        yield session
    Base.metadata.drop_all(engine)


# ---------------------------------------------------------------------------
# 1. Normal Fragmentation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("num_fragments", [1, 3, 5, 8, 16])
def test_normal_fragmentation(encrypted_payload, paper_id, num_fragments):
    """Test 1: Normal fragmentation generates deterministic indexes, valid hashes, and correct totals."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=num_fragments, paper_id=paper_id)
    
    assert len(shards) == num_fragments
    
    total_bytes = 0
    for idx, shard in enumerate(shards):
        assert shard.fragment_index == idx
        assert shard.paper_id == paper_id
        assert shard.status == FragmentStatus.STORED
        assert len(shard.fragment_data) > 0
        total_bytes += len(shard.fragment_data)
        
        # Verify individual SHA-256 integrity hash
        expected_hash = generate_integrity_hash(shard.fragment_data)
        assert shard.integrity_hash == expected_hash
        
    assert total_bytes == len(encrypted_payload)


# ---------------------------------------------------------------------------
# 2. Normal Reconstruction
# ---------------------------------------------------------------------------

def test_normal_reconstruction(encrypted_payload, paper_id, master_key, exam_plaintext):
    """Test 2: Normal reconstruction accurately reassembles the protected ciphertext representation."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    reconstructed = reconstruct_ciphertext(shards, expected_paper_id=paper_id, expected_count=5)
    assert reconstructed == encrypted_payload
    
    # Decrypt to ensure reconstructed representation is valid
    recovered_plaintext = decrypt(reconstructed, master_key)
    assert recovered_plaintext == exam_plaintext


# ---------------------------------------------------------------------------
# 3. Reordered Fragments
# ---------------------------------------------------------------------------

def test_reordered_fragments_reconstruction(encrypted_payload, paper_id):
    """Test 3: Fragments provided in reverse or shuffled order reconstruct correctly based on index."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=7, paper_id=paper_id)
    
    # Reverse order
    reversed_shards = list(reversed(shards))
    reconstructed_rev = reconstruct_ciphertext(reversed_shards, expected_paper_id=paper_id, expected_count=7)
    assert reconstructed_rev == encrypted_payload
    
    # Randomly shuffled order
    shuffled_shards = list(shards)
    random.seed(42)
    random.shuffle(shuffled_shards)
    reconstructed_shuffled = reconstruct_ciphertext(shuffled_shards, expected_paper_id=paper_id, expected_count=7)
    assert reconstructed_shuffled == encrypted_payload


# ---------------------------------------------------------------------------
# 4. Missing Fragment Detection
# ---------------------------------------------------------------------------

def test_missing_fragment_detection(encrypted_payload, paper_id):
    """Test 4: Missing shard is detected and raises FragmentValidationError / MissingFragmentError."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    # Remove shard at index 2 (shards: 0, 1, 3, 4)
    incomplete_shards = [s for s in shards if s.fragment_index != 2]
    
    # With expected_count=5 -> raises FragmentCountMismatchError
    with pytest.raises(FragmentCountMismatchError):
        reconstruct_ciphertext(incomplete_shards, expected_paper_id=paper_id, expected_count=5)
        
    # Without expected_count (count=4, but indices are 0, 1, 3, 4) -> raises MissingFragmentError
    with pytest.raises(MissingFragmentError):
        reconstruct_ciphertext(incomplete_shards, expected_paper_id=paper_id)


# ---------------------------------------------------------------------------
# 5. Duplicate Fragment Detection
# ---------------------------------------------------------------------------

def test_duplicate_fragment_detection(encrypted_payload, paper_id):
    """Test 5: Duplicate fragment indexes raise DuplicateFragmentError."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    # Duplicate shard 0 in place of shard 1
    duplicate_shards = [shards[0], copy.deepcopy(shards[0]), shards[2], shards[3], shards[4]]
    
    with pytest.raises(DuplicateFragmentError, match="Duplicate fragment index"):
        reconstruct_ciphertext(duplicate_shards, expected_paper_id=paper_id, expected_count=5)


# ---------------------------------------------------------------------------
# 6. Corrupted Fragment Detection
# ---------------------------------------------------------------------------

def test_corrupted_fragment_data(encrypted_payload, paper_id):
    """Test 6a: Bit-flipped fragment data causes integrity hash verification failure."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    # Corrupt data in shard 3
    tampered_data = bytearray(shards[3].fragment_data)
    tampered_data[0] ^= 0xFF
    shards[3].fragment_data = bytes(tampered_data)
    
    with pytest.raises(FragmentIntegrityError, match="integrity verification failed"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id, expected_count=5)


def test_corrupted_fragment_status(encrypted_payload, paper_id):
    """Test 6b: Fragment with status CORRUPTED or DELETED is rejected."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    shards[2].status = FragmentStatus.CORRUPTED
    
    with pytest.raises(CorruptedFragmentError, match="invalid status CORRUPTED"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id, expected_count=5)

    shards[2].status = FragmentStatus.DELETED
    with pytest.raises(CorruptedFragmentError, match="invalid status DELETED"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id, expected_count=5)


# ---------------------------------------------------------------------------
# 7. Fragment from Wrong Paper
# ---------------------------------------------------------------------------

def test_fragment_from_wrong_paper(encrypted_payload, paper_id):
    """Test 7: Foreign fragment belonging to another paper raises FragmentPaperMismatchError."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    # Assign shard 2 to another paper
    foreign_paper_id = uuid.uuid4()
    shards[2].paper_id = foreign_paper_id
    
    with pytest.raises(FragmentPaperMismatchError, match="belongs to paper"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id, expected_count=5)


# ---------------------------------------------------------------------------
# 8. Invalid Fragment Index
# ---------------------------------------------------------------------------

def test_invalid_fragment_index(encrypted_payload, paper_id):
    """Test 8: Negative or out-of-bounds fragment indexes raise FragmentValidationError."""
    shards = fragment_ciphertext(encrypted_payload, num_fragments=5, paper_id=paper_id)
    
    # Negative index
    shards[0].fragment_index = -1
    with pytest.raises(FragmentValidationError, match="Invalid fragment index"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id)

    # Out-of-bounds index (e.g. index 99 in a 5-fragment set)
    shards[0].fragment_index = 99
    with pytest.raises(MissingFragmentError, match="discontinuous"):
        reconstruct_ciphertext(shards, expected_paper_id=paper_id)


# ---------------------------------------------------------------------------
# 9. Reconstruction Failure Handling
# ---------------------------------------------------------------------------

def test_reconstruction_failure_empty_list():
    """Test 9: Empty fragment sequence raises FragmentValidationError."""
    with pytest.raises(FragmentValidationError, match="empty fragment list"):
        reconstruct_ciphertext([])


def test_fragmentation_invalid_arguments(encrypted_payload):
    """Test 9b: Invalid parameters to fragment_ciphertext raise ValueError."""
    with pytest.raises(ValueError, match="Ciphertext to fragment must be bytes"):
        fragment_ciphertext("not bytes", num_fragments=3)  # type: ignore

    with pytest.raises(ValueError, match="num_fragments must be a positive integer"):
        fragment_ciphertext(encrypted_payload, num_fragments=0)


# ---------------------------------------------------------------------------
# 10. End-to-End Workflow Integrated with Database Models
# ---------------------------------------------------------------------------

def test_database_end_to_end_workflow(db_session: Session, master_key: bytes, exam_plaintext: bytes):
    """Test 10: Complete database lifecycle: Create -> Protect & Fragment -> Persist -> Retrieve -> Reconstruct & Decrypt."""
    # 1. Create QuestionPaper record in CREATED status
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="CS-FINAL-2026",
        paper_name="Advanced Computer Security",
        status=PaperStatus.CREATED,
    )
    db_session.add(paper)
    db_session.commit()

    # 2. Protect and Fragment Paper
    fragments = protect_and_fragment_paper(
        db=db_session,
        paper=paper,
        plaintext_data=exam_plaintext,
        key=master_key,
        num_fragments=5,
    )
    db_session.commit()

    # Verify paper state
    assert paper.status == PaperStatus.FRAGMENTED
    assert paper.total_fragments == 5
    assert paper.integrity_hash is not None
    assert paper.integrity_hash.startswith("sha256:")
    assert paper.protected_at is not None
    assert paper.fragmented_at is not None

    # Verify fragment database records
    db_fragments = db_session.query(PaperFragment).filter_by(paper_id=paper.id).all()
    assert len(db_fragments) == 5
    for idx, f in enumerate(sorted(db_fragments, key=lambda x: x.fragment_index)):
        assert f.fragment_index == idx
        assert f.status == FragmentStatus.STORED
        assert f.integrity_hash == generate_integrity_hash(f.fragment_data)
        # Ensure fragment_data is CIPHERTEXT, not plaintext!
        assert exam_plaintext not in f.fragment_data

    # 3. Retrieve, Reconstruct, and Decrypt
    decrypted_paper = reconstruct_and_decrypt_paper(
        db=db_session,
        paper=paper,
        key=master_key,
    )

    # 4. Assert exact plaintext match
    assert decrypted_paper == exam_plaintext


def test_database_reconstruction_with_wrong_key_fails(db_session: Session, master_key: bytes, exam_plaintext: bytes):
    """Test 10b: Reconstructed ciphertext fails to decrypt when provided with incorrect key."""
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="MATH-2026",
        paper_name="Calculus III",
        status=PaperStatus.CREATED,
    )
    db_session.add(paper)
    db_session.commit()

    protect_and_fragment_paper(db_session, paper, exam_plaintext, master_key, num_fragments=4)
    db_session.commit()

    wrong_key = os.urandom(32)
    with pytest.raises(DecryptionFailedError):
        reconstruct_and_decrypt_paper(db_session, paper, wrong_key)


def test_database_tampered_manifest_hash_fails(db_session: Session, master_key: bytes, exam_plaintext: bytes):
    """Test 10c: If paper manifest integrity hash in DB is tampered with, post-decryption integrity check fails."""
    paper = QuestionPaper(
        id=uuid.uuid4(),
        exam_identifier="PHYS-2026",
        paper_name="Quantum Mechanics",
        status=PaperStatus.CREATED,
    )
    db_session.add(paper)
    db_session.commit()

    protect_and_fragment_paper(db_session, paper, exam_plaintext, master_key, num_fragments=3)
    
    # Tamper with paper manifest hash
    paper.integrity_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"
    db_session.commit()

    with pytest.raises(FragmentIntegrityError, match="Reconstructed paper manifest hash mismatch"):
        reconstruct_and_decrypt_paper(db_session, paper, master_key)
