"""
TrustGuard — Development Key Management.

WARNING:
    This module uses an environment variable (TRUSTGUARD_MASTER_KEY) to load
    the cryptographic master key. This is suitable for development and
    prototyping only.

    In a production environment, this module MUST be replaced with an integration
    to a proper Key Management Service (KMS) or Hardware Security Module (HSM),
    such as AWS KMS, Azure Key Vault, or HashiCorp Vault. Environment variables
    do not provide adequate protection against memory dumping, core dumps,
    or unauthorized access on production hosts.
"""
import base64
import os


def get_master_key() -> bytes:
    """
    Retrieve the 32-byte (256-bit) master encryption key.

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
            "(Note: This environment-based approach is for development only.)"
        )
    
    try:
        raw_key = base64.b64decode(b64_key, validate=True)
    except Exception as exc:
        raise ValueError(
            "TRUSTGUARD_MASTER_KEY is not a valid base64-encoded string."
        ) from exc
    
    if len(raw_key) != 32:
        raise ValueError(
            f"Master key must be exactly 32 bytes (256 bits) for AES-256. "
            f"Provided key decoded to {len(raw_key)} bytes."
        )
    
    return raw_key
