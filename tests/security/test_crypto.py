"""
TrustGuard — Cryptographic protection layer tests.

Verifies AES-256-GCM encryption/decryption, integrity hashing,
and key management.

Test coverage:
  TC-01  Encrypt/decrypt round trip succeeds with valid key
  TC-02  Decryption fails with wrong key (raises DecryptionFailedError)
  TC-03  Decryption fails with modified ciphertext
  TC-04  Decryption fails with modified authentication tag
  TC-05  Decryption fails with invalid/truncated payload
  TC-06  Encryption/decryption handles empty input correctly
  TC-07  Encryption/decryption handles arbitrary binary input
  TC-08  Secrets and keys do not appear in DecryptionFailedError messages
  TC-09  Key manager successfully decodes 32-byte base64 key
  TC-10  Key manager raises RuntimeError if env var is missing
  TC-11  Key manager raises ValueError if key is not base64
  TC-12  Key manager raises ValueError if key is wrong length
  TC-13  Integrity hash outputs correct sha256 format
"""
import base64
import os
import pytest

from security.crypto.encryption import (
    encrypt_data,
    decrypt_data,
    DecryptionFailedError,
    NONCE_SIZE,
)
from security.crypto.integrity import generate_integrity_hash
from security.crypto.key_manager import get_master_key


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_key() -> bytes:
    """Generate a random 32-byte key for testing."""
    return os.urandom(32)


@pytest.fixture
def dummy_plaintext() -> bytes:
    return b"CONFIDENTIAL EXAM CONTENT: Q1. What is the meaning of life?"


# ---------------------------------------------------------------------------
# Tests: Encryption / Decryption (AES-256-GCM)
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_round_trip(valid_key, dummy_plaintext):
    """TC-01: Encrypt/decrypt round trip succeeds with valid key."""
    payload = encrypt_data(dummy_plaintext, valid_key)
    
    # Payload should be nonce (12 bytes) + ciphertext + tag (16 bytes)
    assert len(payload) == NONCE_SIZE + len(dummy_plaintext) + 16
    
    # Decrypt should perfectly recover the original data
    recovered = decrypt_data(payload, valid_key)
    assert recovered == dummy_plaintext


def test_decryption_wrong_key(valid_key, dummy_plaintext):
    """TC-02: Decryption fails with wrong key."""
    payload = encrypt_data(dummy_plaintext, valid_key)
    wrong_key = os.urandom(32)
    
    with pytest.raises(DecryptionFailedError):
        decrypt_data(payload, wrong_key)


def test_decryption_modified_ciphertext(valid_key, dummy_plaintext):
    """TC-03: Decryption fails with modified ciphertext."""
    payload = bytearray(encrypt_data(dummy_plaintext, valid_key))
    
    # Flip a bit in the ciphertext portion (after nonce, before tag)
    payload[NONCE_SIZE + 5] ^= 0xFF
    
    with pytest.raises(DecryptionFailedError):
        decrypt_data(bytes(payload), valid_key)


def test_decryption_modified_auth_tag(valid_key, dummy_plaintext):
    """TC-04: Decryption fails with modified authentication tag."""
    payload = bytearray(encrypt_data(dummy_plaintext, valid_key))
    
    # Flip a bit in the authentication tag (last 16 bytes)
    payload[-1] ^= 0xFF
    
    with pytest.raises(DecryptionFailedError):
        decrypt_data(bytes(payload), valid_key)


def test_decryption_invalid_payload_length(valid_key):
    """TC-05: Decryption fails with truncated payload."""
    short_payload = os.urandom(NONCE_SIZE + 5)  # Less than nonce + tag length
    
    with pytest.raises(ValueError, match="too short"):
        decrypt_data(short_payload, valid_key)


def test_empty_input(valid_key):
    """TC-06: Encryption/decryption handles empty input correctly."""
    empty = b""
    payload = encrypt_data(empty, valid_key)
    
    assert len(payload) == NONCE_SIZE + 16  # Just nonce + tag
    recovered = decrypt_data(payload, valid_key)
    assert recovered == empty


def test_binary_input(valid_key):
    """TC-07: Handles arbitrary binary input (e.g., PDF data)."""
    binary_data = os.urandom(1024 * 5)  # 5KB of random bytes
    payload = encrypt_data(binary_data, valid_key)
    recovered = decrypt_data(payload, valid_key)
    
    assert recovered == binary_data


def test_no_secret_leakage_in_exceptions(valid_key, dummy_plaintext):
    """TC-08: Secrets and keys do not appear in DecryptionFailedError."""
    payload = encrypt_data(dummy_plaintext, valid_key)
    wrong_key = os.urandom(32)
    
    try:
        decrypt_data(payload, wrong_key)
        pytest.fail("Decryption should have failed")
    except DecryptionFailedError as exc:
        msg = str(exc)
        # Verify the key or payload doesn't accidentally end up in the exception message
        assert str(valid_key) not in msg
        assert str(wrong_key) not in msg
        assert str(payload) not in msg


# ---------------------------------------------------------------------------
# Tests: Key Manager
# ---------------------------------------------------------------------------

def test_key_manager_valid_key(monkeypatch):
    """TC-09: Successfully decodes 32-byte base64 key."""
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode('utf-8')
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", b64_key)
    
    extracted_key = get_master_key()
    assert extracted_key == raw_key


def test_key_manager_missing_env_var(monkeypatch):
    """TC-10: Raises RuntimeError if env var is missing."""
    monkeypatch.delenv("TRUSTGUARD_MASTER_KEY", raising=False)
    
    with pytest.raises(RuntimeError, match="environment variable is not set"):
        get_master_key()


def test_key_manager_invalid_base64(monkeypatch):
    """TC-11: Raises ValueError if key is not valid base64."""
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", "not-valid-base64!!")
    
    with pytest.raises(ValueError, match="not a valid base64"):
        get_master_key()


def test_key_manager_wrong_length(monkeypatch):
    """TC-12: Raises ValueError if key is wrong length (e.g. 16 bytes)."""
    raw_key_16 = os.urandom(16)
    b64_key = base64.b64encode(raw_key_16).decode('utf-8')
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", b64_key)
    
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        get_master_key()


# ---------------------------------------------------------------------------
# Tests: Integrity
# ---------------------------------------------------------------------------

def test_generate_integrity_hash():
    """TC-13: Integrity hash outputs correct sha256 format."""
    data = b"hello world"
    hash_str = generate_integrity_hash(data)
    
    assert hash_str.startswith("sha256:")
    assert len(hash_str) == 7 + 64  # 'sha256:' + 64 hex chars
    
    # Verify the actual hash is correct for 'hello world'
    expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert hash_str == f"sha256:{expected_hex}"
