"""
TrustGuard — Authenticated Encryption Service.

Implements AES-256-GCM using the `cryptography` library.
Provides confidentiality and integrity for exam paper fragments.

Key properties:
- Uses AES-256-GCM (Galois/Counter Mode).
- Generates a fresh 12-byte cryptographically secure nonce for every encryption.
- Prepends the nonce to the ciphertext for storage (standard practice).
- Guarantees decryption failure if ciphertext, key, or authentication tag is modified.
"""
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# AES-GCM standard nonce size is 12 bytes (96 bits)
NONCE_SIZE = 12


class DecryptionFailedError(Exception):
    """
    Raised when decryption fails due to invalid key, modified ciphertext,
    or tampered authentication tag.
    
    This deliberately masks the underlying cryptography exception to prevent
    information leakage in error logs (e.g., distinguishing between bad key
    and bad tag).
    """
    pass


def encrypt_data(
    plaintext: Optional[bytes] = None,
    key: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
    *,
    data: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt and authenticate data using AES-256-GCM.

    Args:
        plaintext / data: The raw bytes to encrypt.
        key: A 32-byte encryption key.
        associated_data: Optional authenticated data.

    Returns:
        bytes: A payload containing the 12-byte nonce followed by the
               ciphertext and authentication tag.
    
    Raises:
        ValueError: If inputs are not bytes or the key length is incorrect.
    """
    raw = plaintext if plaintext is not None else data
    if raw is None or not isinstance(raw, bytes):
        raise ValueError("Plaintext must be bytes")
    if key is None or not isinstance(key, bytes):
        raise ValueError("Key must be bytes")
    if len(key) != 32:
        raise ValueError(f"AES-256 requires a 32-byte key, got {len(key)}")

    # 1. Generate a cryptographically secure random nonce.
    nonce = os.urandom(NONCE_SIZE)

    # 2. Initialize the cipher and encrypt.
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, raw, associated_data=associated_data)

    # 3. Prepend the nonce to the payload so it can be retrieved for decryption.
    return nonce + ciphertext_with_tag


def decrypt_data(
    encrypted_payload: Optional[bytes] = None,
    key: Optional[bytes] = None,
    associated_data: Optional[bytes] = None,
    *,
    payload: Optional[bytes] = None,
    data: Optional[bytes] = None,
) -> bytes:
    """
    Authenticate and decrypt an AES-256-GCM payload.

    Args:
        encrypted_payload / payload / data: The data returned by `encrypt_data` (nonce + ciphertext + tag).
        key: A 32-byte encryption key.
        associated_data: Optional authenticated data.

    Returns:
        bytes: The original plaintext.
    
    Raises:
        DecryptionFailedError: If authentication fails, the payload is modified,
                               or the key is incorrect.
        ValueError: If inputs are invalid or the payload is too short.
    """
    raw = encrypted_payload if encrypted_payload is not None else (payload if payload is not None else data)
    if raw is None or not isinstance(raw, bytes):
        raise ValueError("Encrypted payload must be bytes")
    if key is None or not isinstance(key, bytes):
        raise ValueError("Key must be bytes")
    
    # Payload must contain at least the 12-byte nonce + 16-byte auth tag
    if len(raw) < NONCE_SIZE + 16:
        raise ValueError("Encrypted payload is too short to be valid")

    nonce = raw[:NONCE_SIZE]
    ciphertext_with_tag = raw[NONCE_SIZE:]

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data=associated_data)
        return plaintext
    except InvalidTag as exc:
        raise DecryptionFailedError("Integrity check failed or incorrect key") from exc


# Aliases for compatibility
encrypt = encrypt_data
decrypt = decrypt_data
