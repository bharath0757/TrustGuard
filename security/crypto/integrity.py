"""
TrustGuard — Integrity Hashing.

Provides standard SHA-256 hashing.
"""
import hashlib


def generate_integrity_hash(data: bytes) -> str:
    """
    Generate a SHA-256 integrity hash for the given data.

    Why is this needed when AES-GCM already provides authenticated encryption?
    
    1. Exam Manifest Verification: TrustGuard creates an `integrity_hash` of the 
       entire exam paper manifest *before* fragmentation. This allows the system 
       to verify the structural integrity of the recovered exam (e.g., ensuring 
       no shards are missing or ordered incorrectly) after reconstruction.
    2. Shard Identification: While AES-GCM guarantees a shard hasn't been tampered
       with, the database stores a plain SHA-256 hash alongside the ciphertext
       to quickly detect exact duplicates or verify shard transmission without
       needing the decryption key.

    Args:
        data: The raw bytes to hash.

    Returns:
        str: A hex-encoded string formatted as `sha256:<digest>`.
    """
    if not isinstance(data, bytes):
        raise ValueError("Data to hash must be bytes")
        
    digest = hashlib.sha256(data).hexdigest()
    return f"sha256:{digest}"
