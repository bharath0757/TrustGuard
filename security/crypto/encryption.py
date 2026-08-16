"""
TrustGuard — Authenticated Encryption Service.

Implements AES-256-GCM (Galois/Counter Mode) using the `cryptography` library.
Provides confidentiality and authentication/integrity for exam question papers
and fragments prior to storage or transmission.

Key Properties:
- Algorithm: AES-256-GCM (Authenticated Encryption with Associated Data - AEAD).
- Nonce / IV: Fresh, cryptographically secure 12-byte (96-bit) nonce generated
  via `os.urandom` for every encryption invocation. Nonces are never hardcoded
  and never reused.
- Packaging: Encrypted payload is formatted as `[12-byte Nonce] + [Ciphertext + 16-byte Tag]`.
- Associated Data (AAD): Supports optional associated authenticated data for
  cryptographic binding (e.g., exam ID, version) without encrypting the metadata.
- Safe Failure: Masked `DecryptionFailedError` to prevent side-channel or padding/tag oracle leaks.
- Zero-Leakage: No plaintext or key material is ever logged or exposed in exceptions.
"""
import logging
import os
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


logger = logging.getLogger("trustguard.crypto")

# AES-GCM standard recommended nonce size is 12 bytes (96 bits)
NONCE_SIZE = 12

# Standard AES-GCM authentication tag size is 16 bytes (128 bits)
TAG_SIZE = 16

# Required key length for AES-256 (32 bytes = 256 bits)
KEY_SIZE = 32


class DecryptionFailedError(Exception):
    """
    Raised when decryption or integrity authentication fails.

    This deliberately masks the underlying cryptographic exception (e.g. InvalidTag)
    to prevent information leakage (such as distinguishing between a corrupted key,
    modified ciphertext, modified nonce, or modified associated data).
    """
    pass


def encrypt(
    data: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Encrypt and authenticate data using AES-256-GCM.

    Args:
        data: The raw plaintext bytes to encrypt.
        key: A 32-byte (256-bit) cryptographic key.
        associated_data: Optional bytes to authenticate alongside the ciphertext
                         (not encrypted, but protected against tampering).

    Returns:
        bytes: A combined payload containing the 12-byte nonce followed by
               the ciphertext and the 16-byte authentication tag.

    Raises:
        ValueError: If inputs are invalid types or the key length is incorrect.
    """
    if not isinstance(data, bytes):
        raise ValueError("Plaintext data must be bytes")
    if not isinstance(key, bytes):
        raise ValueError("Encryption key must be bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 requires a {KEY_SIZE}-byte key, got {len(key)} bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes if provided")

    # 1. Generate a cryptographically secure random nonce.
    # NEVER reuse a nonce with the same key in AES-GCM.
    nonce = os.urandom(NONCE_SIZE)

    # 2. Encrypt with AES-256-GCM.
    # The cryptography library automatically appends the 16-byte auth tag to ciphertext.
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(nonce, data, associated_data)

    # Safe logging: log operation metrics only, NEVER log plaintext or key bytes
    logger.debug(
        "Encrypted %d bytes of data (payload size: %d bytes, AAD present: %s)",
        len(data),
        len(nonce) + len(ciphertext_with_tag),
        associated_data is not None,
    )

    # 3. Prepend the nonce to the payload so it can be retrieved for decryption.
    # The nonce is public and safe to store alongside the ciphertext.
    return nonce + ciphertext_with_tag


def decrypt(
    ciphertext: bytes,
    key: bytes,
    associated_data: Optional[bytes] = None,
) -> bytes:
    """
    Authenticate and decrypt an AES-256-GCM payload.

    Args:
        ciphertext: The encrypted payload containing `[12-byte nonce] + [ciphertext + tag]`.
        key: The 32-byte (256-bit) cryptographic key.
        associated_data: Optional bytes that were authenticated during encryption.

    Returns:
        bytes: The decrypted plaintext bytes.

    Raises:
        DecryptionFailedError: If the key is wrong, the ciphertext is tampered with,
                               the authentication tag is invalid, the nonce was altered,
                               or associated data does not match.
        ValueError: If payload format or types are invalid.
    """
    if not isinstance(ciphertext, bytes):
        raise ValueError("Encrypted payload must be bytes")
    if not isinstance(key, bytes):
        raise ValueError("Decryption key must be bytes")
    if len(key) != KEY_SIZE:
        raise ValueError(f"AES-256 requires a {KEY_SIZE}-byte key, got {len(key)} bytes")
    if associated_data is not None and not isinstance(associated_data, bytes):
        raise ValueError("Associated data must be bytes if provided")

    # Payload must contain at least the 12-byte nonce + 16-byte auth tag
    min_required_len = NONCE_SIZE + TAG_SIZE
    if len(ciphertext) < min_required_len:
        raise ValueError(
            f"Encrypted payload is too short ({len(ciphertext)} bytes). "
            f"Minimum valid payload size is {min_required_len} bytes."
        )

    # Extract the nonce (first 12 bytes) and ciphertext + tag
    nonce = ciphertext[:NONCE_SIZE]
    ciphertext_with_tag = ciphertext[NONCE_SIZE:]

    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext_with_tag, associated_data)
        
        # Safe logging: log operation metrics only, NEVER log plaintext or key bytes
        logger.debug(
            "Decrypted payload successfully (recovered %d bytes of plaintext)",
            len(plaintext),
        )
        return plaintext
    except InvalidTag as exc:
        # Mask cryptography exceptions to prevent side-channel disclosures
        logger.warning("Decryption failed: integrity verification or key mismatch")
        raise DecryptionFailedError("Integrity check failed or incorrect key") from exc


# Backward-compatible aliases
encrypt_data = encrypt
decrypt_data = decrypt
