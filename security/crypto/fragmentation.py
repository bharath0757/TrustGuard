"""
TrustGuard — Encrypted Fragment Distribution Service.

Implements deterministic chunking and distribution of AES-256-GCM ciphertext payloads.

TERMINOLOGY & ARCHITECTURAL NOTE:
---------------------------------
This service implements **Encrypted Fragment Distribution** (slicing an already-encrypted
ciphertext representation into deterministic shards).

It is **NOT** "Threshold Cryptography" or "Secret Sharing" (e.g., Shamir's Secret Sharing).
In this architecture:
1. Plaintext examination content is NEVER fragmented or stored directly.
2. The question paper is first encrypted using AES-256-GCM (Authenticated Encryption).
3. The resulting protected representation (`[Nonce] + [Ciphertext + Tag]`) is partitioned
   into N deterministic shards.
4. Each shard is indexed and tagged with an individual SHA-256 integrity hash.
5. Reconstruction strictly requires all N shards, valid indices, intact integrity digests,
   and matching paper ownership prior to ciphertext reassembly and cryptographic decryption.
"""
from dataclasses import dataclass
from datetime import datetime, timezone
import logging
from typing import Any, List, Optional, Sequence, Union
import uuid

from sqlalchemy.orm import Session

from database.models.paper import QuestionPaper, PaperStatus
from database.models.fragment import PaperFragment, FragmentStatus
from security.crypto.encryption import encrypt, decrypt, DecryptionFailedError
from security.crypto.integrity import generate_integrity_hash


logger = logging.getLogger("trustguard.crypto.fragmentation")


# ---------------------------------------------------------------------------
# Custom Exceptions
# ---------------------------------------------------------------------------

class FragmentationError(Exception):
    """Base exception for all fragmentation and reconstruction failures."""
    pass


class FragmentValidationError(FragmentationError):
    """Raised when fragments fail pre-reconstruction validation."""
    pass


class FragmentPaperMismatchError(FragmentValidationError):
    """Raised when a fragment belongs to a different question paper."""
    pass


class FragmentCountMismatchError(FragmentValidationError):
    """Raised when the number of fragments does not match expected total."""
    pass


class DuplicateFragmentError(FragmentValidationError):
    """Raised when duplicate fragment indexes are detected."""
    pass


class MissingFragmentError(FragmentValidationError):
    """Raised when one or more fragment indexes are missing."""
    pass


class CorruptedFragmentError(FragmentValidationError):
    """Raised when a fragment status is marked CORRUPTED or DELETED."""
    pass


class FragmentIntegrityError(FragmentValidationError):
    """Raised when a fragment's computed hash does not match its recorded integrity hash."""
    pass


# ---------------------------------------------------------------------------
# In-Memory Fragment Container
# ---------------------------------------------------------------------------

@dataclass
class FragmentPayload:
    """
    Lightweight container representing a single encrypted shard.
    Compatible with the `PaperFragment` ORM model interface.
    """
    fragment_index: int
    fragment_data: bytes
    integrity_hash: str
    paper_id: Optional[uuid.UUID] = None
    status: FragmentStatus = FragmentStatus.STORED


FragmentLike = Union[PaperFragment, FragmentPayload]


# ---------------------------------------------------------------------------
# Core Fragmentation Logic (Encrypted Fragment Distribution)
# ---------------------------------------------------------------------------

def fragment_ciphertext(
    ciphertext: bytes,
    num_fragments: int,
    paper_id: Optional[uuid.UUID] = None,
) -> List[FragmentPayload]:
    """
    Partition an encrypted ciphertext payload into N deterministic shards.

    Args:
        ciphertext: The AES-256-GCM protected representation to fragment.
        num_fragments: Number of shards to produce (must be >= 1).
        paper_id: Optional UUID of the associated QuestionPaper.

    Returns:
        List[FragmentPayload]: Ordered list of N fragment payloads with
                               zero-based indexes and individual SHA-256 hashes.

    Raises:
        ValueError: If ciphertext is not bytes or num_fragments is invalid.
    """
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext to fragment must be bytes")
    if not isinstance(num_fragments, int) or num_fragments < 1:
        raise ValueError(f"num_fragments must be a positive integer >= 1, got {num_fragments}")

    total_len = len(ciphertext)
    k, m = divmod(total_len, num_fragments)

    shards: List[FragmentPayload] = []
    start = 0

    for i in range(num_fragments):
        # Distribute remainder bytes evenly across the first m shards
        chunk_len = k + (1 if i < m else 0)
        end = start + chunk_len
        chunk_bytes = ciphertext[start:end]
        start = end

        integrity_digest = generate_integrity_hash(chunk_bytes)

        shards.append(
            FragmentPayload(
                fragment_index=i,
                fragment_data=chunk_bytes,
                integrity_hash=integrity_digest,
                paper_id=paper_id,
                status=FragmentStatus.STORED,
            )
        )

    logger.debug(
        "Fragmented %d bytes of ciphertext into %d shards (paper_id=%s)",
        total_len,
        num_fragments,
        paper_id,
    )
    return shards


# ---------------------------------------------------------------------------
# Validation Logic
# ---------------------------------------------------------------------------

def validate_fragments(
    fragments: Sequence[FragmentLike],
    expected_paper_id: Optional[uuid.UUID] = None,
    expected_count: Optional[int] = None,
) -> List[FragmentLike]:
    """
    Perform strict pre-reconstruction validation across all fragment shards.

    Validates:
    - Non-empty fragment list
    - Paper ID ownership match
    - Expected fragment count
    - Absence of duplicate fragment indexes
    - Completeness of contiguous 0-based indexes [0 ... N-1]
    - Shard lifecycle status (rejects CORRUPTED or DELETED)
    - Fragment-level SHA-256 cryptographic integrity hashes

    Args:
        fragments: Sequence of PaperFragment or FragmentPayload instances.
        expected_paper_id: Expected QuestionPaper UUID.
        expected_count: Expected total fragment count (e.g. from QuestionPaper.total_fragments).

    Returns:
        List[FragmentLike]: The validated fragments, strictly sorted by fragment_index.

    Raises:
        FragmentValidationError: If any validation rule fails.
    """
    if not fragments:
        raise FragmentValidationError("Cannot reconstruct from an empty fragment list")

    actual_count = len(fragments)

    # 1. Validate expected count
    if expected_count is not None and actual_count != expected_count:
        raise FragmentCountMismatchError(
            f"Expected {expected_count} fragments for paper {expected_paper_id}, "
            f"but received {actual_count} fragments"
        )

    seen_indices = set()
    validated_list: List[FragmentLike] = []

    for frag in fragments:
        # 2. Validate paper ownership
        if expected_paper_id is not None and getattr(frag, "paper_id", None) is not None:
            if frag.paper_id != expected_paper_id:
                raise FragmentPaperMismatchError(
                    f"Fragment with index {frag.fragment_index} belongs to paper "
                    f"{frag.paper_id}, expected paper {expected_paper_id}"
                )

        # 3. Validate lifecycle status
        status = getattr(frag, "status", FragmentStatus.STORED)
        if isinstance(status, str):
            status_val = status
        else:
            status_val = getattr(status, "value", str(status))

        if status_val in (FragmentStatus.CORRUPTED.value, FragmentStatus.DELETED.value):
            raise CorruptedFragmentError(
                f"Fragment at index {frag.fragment_index} has invalid status {status_val}"
            )

        # 4. Validate duplicate indexes
        idx = frag.fragment_index
        if not isinstance(idx, int) or idx < 0:
            raise FragmentValidationError(f"Invalid fragment index: {idx}")

        if idx in seen_indices:
            raise DuplicateFragmentError(f"Duplicate fragment index detected: {idx}")
        seen_indices.add(idx)

        # 5. Validate fragment-level integrity hash
        computed_hash = generate_integrity_hash(frag.fragment_data)
        if frag.integrity_hash != computed_hash:
            raise FragmentIntegrityError(
                f"Fragment index {idx} integrity verification failed. "
                f"Recorded: {frag.integrity_hash}, Computed: {computed_hash}"
            )

        validated_list.append(frag)

    # 6. Validate complete index continuity [0, 1, ..., N-1]
    expected_indices = set(range(actual_count))
    missing = expected_indices - seen_indices
    out_of_bounds = seen_indices - expected_indices

    if missing or out_of_bounds:
        raise MissingFragmentError(
            f"Fragment index sequence is discontinuous. "
            f"Missing indexes: {sorted(list(missing))}, Out of bounds: {sorted(list(out_of_bounds))}"
        )

    # Return fragments deterministically sorted by fragment_index
    return sorted(validated_list, key=lambda f: f.fragment_index)


# ---------------------------------------------------------------------------
# Reconstruction Logic
# ---------------------------------------------------------------------------

def reconstruct_ciphertext(
    fragments: Sequence[FragmentLike],
    expected_paper_id: Optional[uuid.UUID] = None,
    expected_count: Optional[int] = None,
) -> bytes:
    """
    Validate and assemble encrypted fragment shards into the original protected representation.

    Args:
        fragments: Sequence of PaperFragment or FragmentPayload instances.
        expected_paper_id: Expected QuestionPaper UUID.
        expected_count: Expected total fragment count.

    Returns:
        bytes: The reconstructed AES-256-GCM protected ciphertext representation.

    Raises:
        FragmentValidationError: If validation fails.
    """
    sorted_fragments = validate_fragments(
        fragments,
        expected_paper_id=expected_paper_id,
        expected_count=expected_count,
    )

    reconstructed_bytes = b"".join(f.fragment_data for f in sorted_fragments)
    logger.debug(
        "Successfully reconstructed %d bytes of ciphertext from %d shards (paper_id=%s)",
        len(reconstructed_bytes),
        len(sorted_fragments),
        expected_paper_id,
    )
    return reconstructed_bytes


# ---------------------------------------------------------------------------
# High-Level Database Integration Service
# ---------------------------------------------------------------------------

def protect_and_fragment_paper(
    db: Session,
    paper: QuestionPaper,
    plaintext_data: bytes,
    key: bytes,
    num_fragments: int = 5,
) -> List[PaperFragment]:
    """
    Full secure workflow to protect and distribute a question paper:
    1. Compute canonical plaintext integrity hash.
    2. Encrypt plaintext using AES-256-GCM (Protected representation).
    3. Update paper state to PROTECTED.
    4. Fragment encrypted ciphertext into N deterministic shards.
    5. Persist PaperFragment records to database (status=STORED).
    6. Transition paper state to FRAGMENTED with total_fragments and timestamps.

    Args:
        db: SQLAlchemy database session.
        paper: QuestionPaper ORM instance.
        plaintext_data: Raw examination question paper bytes.
        key: 32-byte AES-256 master key.
        num_fragments: Number of shards to produce (default: 5).

    Returns:
        List[PaperFragment]: The persisted database fragment records.
    """
    if not isinstance(plaintext_data, bytes):
        raise ValueError("Plaintext data must be bytes")
    if num_fragments < 1:
        raise ValueError(f"num_fragments must be >= 1, got {num_fragments}")

    now = datetime.now(timezone.utc)

    # 1. Compute pre-fragmentation integrity fingerprint of the original manifest
    paper.integrity_hash = generate_integrity_hash(plaintext_data)

    # 2. Encrypt using authenticated encryption (AES-256-GCM)
    ciphertext = encrypt(plaintext_data, key)
    paper.status = PaperStatus.PROTECTED
    paper.protected_at = now

    # 3. Fragment the encrypted representation (Encrypted Fragment Distribution)
    shards = fragment_ciphertext(ciphertext, num_fragments, paper_id=paper.id)

    # 4. Create and persist ORM fragment records
    db_fragments: List[PaperFragment] = []
    for shard in shards:
        db_frag = PaperFragment(
            id=uuid.uuid4(),
            paper_id=paper.id,
            fragment_index=shard.fragment_index,
            fragment_data=shard.fragment_data,
            integrity_hash=shard.integrity_hash,
            status=FragmentStatus.STORED,
        )
        db.add(db_frag)
        db_fragments.append(db_frag)

    # 5. Transition paper status to FRAGMENTED
    paper.status = PaperStatus.FRAGMENTED
    paper.total_fragments = num_fragments
    paper.fragmented_at = now

    db.flush()
    logger.info(
        "Paper %s protected and distributed into %d encrypted fragments",
        paper.id,
        num_fragments,
    )
    return db_fragments


def retrieve_paper_fragments(
    db: Session,
    paper_id: uuid.UUID,
) -> List[PaperFragment]:
    """
    Retrieve all stored fragments for a given question paper from the database.

    Args:
        db: SQLAlchemy database session.
        paper_id: QuestionPaper UUID.

    Returns:
        List[PaperFragment]: List of fragments associated with the paper.
    """
    return db.query(PaperFragment).filter_by(paper_id=paper_id).all()


def reconstruct_and_decrypt_paper(
    db: Session,
    paper: QuestionPaper,
    key: bytes,
) -> bytes:
    """
    Full secure workflow to retrieve, validate, reconstruct, and decrypt a question paper:
    1. Retrieve all stored fragments from database.
    2. Validate fragment ownership, expected count, index sequence, and SHA-256 hashes.
    3. Reassemble the protected ciphertext payload.
    4. Decrypt via AES-256-GCM (which verifies GMAC auth tag).
    5. Verify recovered plaintext matches paper's recorded manifest integrity hash.

    Args:
        db: SQLAlchemy database session.
        paper: QuestionPaper ORM instance.
        key: 32-byte AES-256 master key.

    Returns:
        bytes: Decrypted original plaintext exam question paper.

    Raises:
        FragmentValidationError: If fragment validation or reconstruction fails.
        DecryptionFailedError: If cryptographic authentication or decryption fails.
    """
    # 1. Retrieve all fragments
    fragments = retrieve_paper_fragments(db, paper.id)

    # 2 & 3. Validate and reconstruct protected representation
    ciphertext = reconstruct_ciphertext(
        fragments,
        expected_paper_id=paper.id,
        expected_count=paper.total_fragments,
    )

    # 4. Decrypt protected representation
    plaintext = decrypt(ciphertext, key)

    # 5. Verify integrity against pre-fragmentation manifest hash
    if paper.integrity_hash:
        recovered_hash = generate_integrity_hash(plaintext)
        if recovered_hash != paper.integrity_hash:
            raise FragmentIntegrityError(
                f"Reconstructed paper manifest hash mismatch. "
                f"Expected {paper.integrity_hash}, recovered {recovered_hash}"
            )

    logger.info("Paper %s successfully reconstructed and decrypted", paper.id)
    return plaintext
