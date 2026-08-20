"""
TrustGuard — Development Key Management.

WARNING:
    This module uses an environment variable (TRUSTGUARD_MASTER_KEY) to load
    the cryptographic master key. This is suitable for development and
    prototyping only.
"""
import base64
import os


def generate_master_key() -> str:
    """Generate a fresh Base64-encoded 32-byte (256-bit) cryptographically secure random master key."""
    return base64.b64encode(os.urandom(32)).decode("utf-8")


def get_master_key() -> bytes:
    """
    Retrieve the 32-byte (256-bit) master encryption key.

    The key must be provided via the `TRUSTGUARD_MASTER_KEY` environment
    variable, encoded as a standard Base64 string.

    Returns:
        bytes: The raw 32-byte cryptographic key.
    """
    b64_key = os.environ.get("TRUSTGUARD_MASTER_KEY")
    
    if not b64_key:
        return os.urandom(32)
    
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
