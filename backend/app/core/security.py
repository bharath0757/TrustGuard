"""Security and authentication utilities."""

from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import os
from typing import Any, Optional
import jwt
from app.core.config import settings

PBKDF2_ITERATIONS = 100_000


def hash_password(password: str) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with random 16-byte salt per user."""
    salt = os.urandom(16).hex()
    hash_bytes = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        PBKDF2_ITERATIONS,
    )
    return f"pbkdf2_sha256:{PBKDF2_ITERATIONS}:{salt}:{hash_bytes.hex()}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify plain password against hashed password with constant-time comparison.
    Supports PBKDF2 format with transparent fallback for legacy SHA-256 hashes.
    """
    if not plain_password or not hashed_password:
        return False

    if hashed_password.startswith("pbkdf2_sha256:"):
        try:
            parts = hashed_password.split(":")
            if len(parts) == 4:
                iterations = int(parts[1])
                salt = parts[2]
                expected_hash = parts[3]
                computed = hashlib.pbkdf2_hmac(
                    "sha256",
                    plain_password.encode("utf-8"),
                    salt.encode("utf-8"),
                    iterations,
                ).hex()
                return hmac.compare_digest(computed, expected_hash)
        except Exception:
            return False

    # Backward-compatible fallback for legacy SHA-256 static salt format
    salt = "trustguard_static_salt_v1"
    legacy_hash = hashlib.sha256((plain_password + salt).encode("utf-8")).hexdigest()
    return hmac.compare_digest(legacy_hash, hashed_password)


def create_access_token(data: dict[str, Any], expires_delta: Optional[timedelta] = None) -> str:
    """Create JWT access token."""
    to_encode = data.copy()
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode.update({"exp": expire, "iat": now})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


def decode_access_token(token: str) -> Optional[dict[str, Any]]:
    """Decode JWT access token."""
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        return payload
    except jwt.PyJWTError:
        return None
