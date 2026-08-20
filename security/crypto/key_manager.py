"""
TrustGuard — Development Key Management.

WARNING:
    This module uses an environment variable (TRUSTGUARD_MASTER_KEY) to load
    the cryptographic master key. This is suitable for DEVELOPMENT and
    PROTOTYPING ONLY.

    In a production environment, this approach MUST be replaced with an integration
    to a dedicated Key Management Service (KMS) or Hardware Security Module (HSM),
    such as AWS KMS, Azure Key Vault, Google Cloud KMS, or HashiCorp Vault.
    
    Environment variables do NOT provide adequate security for production:
    - They are visible to child processes.
    - They can be leaked via crash logs, core dumps, or `/proc` filesystem inspections.
    - They lack automated cryptographic rotation, access auditing, and hardware protection.

Do NOT treat environment variables as production-grade key management.
"""
import base64
import logging
import os
import secrets


logger = logging.getLogger("trustguard.crypto")

# Expected master key length for AES-256 (32 bytes = 256 bits)
MASTER_KEY_LENGTH = 32


def generate_master_key() -> str:
    """
    Generate a new cryptographically secure 256-bit key formatted as Base64.

    Useful for generating initial development environment variables (.env).

    Returns:
        str: Base64-encoded 32-byte key string.
    """
    raw_key = secrets.token_bytes(MASTER_KEY_LENGTH)
    return base64.b64encode(raw_key).decode("utf-8")


def get_master_key() -> bytes:
    """
    Retrieve the 32-byte (256-bit) master encryption key for development.

    The key must be provided via the `TRUSTGUARD_MASTER_KEY` environment
    variable, encoded as a standard Base64 string.

    Returns:
        bytes: The raw 32-byte cryptographic key.

    Raises:
        RuntimeError: If the environment variable is missing.
        ValueError: If the key is not valid base64 or not exactly 32 bytes.
    """
    b64_key = os.environ.get("TRUSTGUARD_MASTER_KEY")
    
    if not b64_key:
        raise RuntimeError(
            "TRUSTGUARD_MASTER_KEY environment variable is not set. "
            "A base64-encoded 32-byte key is required for cryptographic operations. "
            "(Note: This environment-based approach is for development/prototyping only.)"
        )
    
    try:
        raw_key = base64.b64decode(b64_key, validate=True)
    except Exception as exc:
        raise ValueError(
            "TRUSTGUARD_MASTER_KEY is not a valid base64-encoded string."
        ) from exc
    
    if len(raw_key) != MASTER_KEY_LENGTH:
        raise ValueError(
            f"Master key must be exactly {MASTER_KEY_LENGTH} bytes (256 bits) for AES-256. "
            f"Provided key decoded to {len(raw_key)} bytes."
        )
    
    # Safe logging: log confirmation of key readiness, NEVER log key content
    logger.debug("Development master key successfully loaded from environment (%d bytes)", len(raw_key))
    
    return raw_key
