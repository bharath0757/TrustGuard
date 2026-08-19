"""
TrustGuard ΓÇö Cryptographic protection layer.

Provides authenticated encryption (AES-256-GCM), integrity hashing (SHA-256),
and basic key management for development.
"""
from security.crypto.encryption import encrypt_data, decrypt_data, encrypt, decrypt
from security.crypto.integrity import generate_integrity_hash
from security.crypto.key_manager import get_master_key

__all__ = [
    "encrypt_data",
    "decrypt_data",
    "encrypt",
    "decrypt",
    "generate_integrity_hash",
    "get_master_key",
]

