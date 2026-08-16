"""
TrustGuard — Integrity Hashing.

Provides SHA-256 cryptographic hashing for question papers and audit verification.

Why is SHA-256 used alongside AES-256-GCM?
-----------------------------------------
1. Pre-Fragmentation Manifest Fingerprinting:
   Before a question paper is encrypted and split into secret shards, TrustGuard
   computes a SHA-256 hash of the complete canonical paper. This hash serves as
   an immutable paper fingerprint stored in the database metadata and audit logs.
   Upon paper reassembly and decryption, this digest confirms that the reassembled
   plaintext exactly matches the original authoring artifact.

2. Zero-Knowledge Integrity & Deduplication:
   Storage nodes and indexing processes can verify paper versions or detect
   duplicate uploads by comparing SHA-256 digests without requiring access to
   the master encryption keys.

3. Cryptographic Separation of Concerns:
   - AES-256-GCM Tag (16 bytes): Protects ciphertext payload authenticity and
     prevents tampering with individual encrypted fragments (AEAD).
   - SHA-256 Digest (32 bytes): Unencrypted cryptographic checksum for high-level
     audit trails and global manifest validation.
"""
import hashlib
import logging


logger = logging.getLogger("trustguard.crypto")


def generate_integrity_hash(data: bytes) -> str:
    """
    Generate a standard SHA-256 integrity hash for the given data bytes.

    Args:
        data: The raw bytes to hash.

    Returns:
        str: Hex-encoded SHA-256 digest formatted as `sha256:<hex_digest>`.

    Raises:
        ValueError: If data is not bytes.
    """
    if not isinstance(data, bytes):
        raise ValueError("Data to hash must be bytes")
        
    digest = hashlib.sha256(data).hexdigest()
    logger.debug("Generated SHA-256 integrity hash for %d bytes", len(data))
    return f"sha256:{digest}"
