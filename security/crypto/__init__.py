"""
TrustGuard — Cryptographic protection layer.

Provides authenticated encryption (AES-256-GCM), integrity hashing (SHA-256),
key management, and ciphertext fragmentation/reconstruction.
"""
from security.crypto.encryption import (
    encrypt_data,
    decrypt_data,
    encrypt,
    decrypt,
    DecryptionFailedError,
)
from security.crypto.integrity import generate_integrity_hash
from security.crypto.key_manager import get_master_key, generate_master_key
from security.crypto.fragmentation import (
    fragment_ciphertext,
    reconstruct_ciphertext,
    FragmentPayload,
    FragmentIntegrityError,
    FragmentValidationError,
)

__all__ = [
    "encrypt_data",
    "decrypt_data",
    "encrypt",
    "decrypt",
    "DecryptionFailedError",
    "generate_integrity_hash",
    "get_master_key",
    "generate_master_key",
    "fragment_ciphertext",
    "reconstruct_ciphertext",
    "FragmentPayload",
    "FragmentIntegrityError",
    "FragmentValidationError",
]
