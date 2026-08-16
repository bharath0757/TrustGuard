"""
TrustGuard — Cryptographic Protection Layer Tests.

Comprehensive security test suite verifying:
  1. Encrypt/decrypt round trip
  2. Wrong key failure
  3. Modified ciphertext failure
  4. Modified authentication data (AAD) failure
  5. Invalid/modified nonce and truncated payload failure
  6. Empty input handling
  7. Binary input handling (e.g., PDF/image data)
  8. Zero secret leakage in exception messages and log output
  9. Search repository for accidental hardcoded keys
  10. Key manager validations (valid key, generation, missing/invalid env vars)
  11. Integrity SHA-256 hash formatting and deterministic verification
"""
import base64
import logging
import os
import re
import pytest

from security.crypto.encryption import (
    NONCE_SIZE,
    TAG_SIZE,
    KEY_SIZE,
    DecryptionFailedError,
    encrypt,
    decrypt,
    encrypt_data,
    decrypt_data,
)
from security.crypto.integrity import generate_integrity_hash
from security.crypto.key_manager import (
    MASTER_KEY_LENGTH,
    get_master_key,
    generate_master_key,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def valid_key() -> bytes:
    """Generate a fresh random 32-byte key for AES-256."""
    return os.urandom(KEY_SIZE)


@pytest.fixture
def sample_plaintext() -> bytes:
    return b"CONFIDENTIAL EXAM PAPER: Final Examination in Computer Security - Spring 2026"


# ---------------------------------------------------------------------------
# 1. Encrypt / Decrypt Round Trip
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_round_trip(valid_key, sample_plaintext):
    """Test 1: Encrypt and decrypt round trip succeeds with valid key."""
    # Test primary API functions
    payload = encrypt(sample_plaintext, valid_key)
    
    # Payload format: 12-byte Nonce + Ciphertext + 16-byte Auth Tag
    expected_len = NONCE_SIZE + len(sample_plaintext) + TAG_SIZE
    assert len(payload) == expected_len
    
    # Nonce is the first 12 bytes
    nonce = payload[:NONCE_SIZE]
    assert len(nonce) == NONCE_SIZE
    
    # Decrypt and verify exact match
    decrypted = decrypt(payload, valid_key)
    assert decrypted == sample_plaintext

    # Test backward-compatible aliases
    alias_payload = encrypt_data(sample_plaintext, valid_key)
    assert decrypt_data(alias_payload, valid_key) == sample_plaintext


def test_unique_nonce_per_encryption(valid_key, sample_plaintext):
    """Verify that multiple encryptions of the same plaintext produce different nonces and ciphertexts."""
    payload1 = encrypt(sample_plaintext, valid_key)
    payload2 = encrypt(sample_plaintext, valid_key)
    
    nonce1 = payload1[:NONCE_SIZE]
    nonce2 = payload2[:NONCE_SIZE]
    
    # Nonces must NEVER be identical
    assert nonce1 != nonce2
    assert payload1 != payload2
    
    # Both must decrypt to the original plaintext
    assert decrypt(payload1, valid_key) == sample_plaintext
    assert decrypt(payload2, valid_key) == sample_plaintext


# ---------------------------------------------------------------------------
# 2. Wrong Key Failure
# ---------------------------------------------------------------------------

def test_decryption_with_wrong_key(valid_key, sample_plaintext):
    """Test 2: Decryption fails and raises DecryptionFailedError when given wrong key."""
    payload = encrypt(sample_plaintext, valid_key)
    wrong_key = os.urandom(KEY_SIZE)
    
    with pytest.raises(DecryptionFailedError) as exc_info:
        decrypt(payload, wrong_key)
    
    # Ensure error message is generic and does not leak internal cipher details
    assert "Integrity check failed" in str(exc_info.value)


# ---------------------------------------------------------------------------
# 3. Modified Ciphertext Failure
# ---------------------------------------------------------------------------

def test_decryption_with_modified_ciphertext(valid_key, sample_plaintext):
    """Test 3: Decryption fails when ciphertext is tampered with (bit flip)."""
    payload = bytearray(encrypt(sample_plaintext, valid_key))
    
    # Modify a byte inside the ciphertext body (after nonce, before tag)
    payload[NONCE_SIZE + 3] ^= 0xFF
    
    with pytest.raises(DecryptionFailedError):
        decrypt(bytes(payload), valid_key)


# ---------------------------------------------------------------------------
# 4. Modified Authentication Data (AAD)
# ---------------------------------------------------------------------------

def test_associated_authenticated_data_roundtrip_and_tamper(valid_key, sample_plaintext):
    """Test 4: Associated Authenticated Data (AAD) is verified and detects tampering."""
    aad = b"exam_id:CS-501;version:2026-FINAL;classification:TOP_SECRET"
    
    # Encrypt with associated data
    payload = encrypt(sample_plaintext, valid_key, associated_data=aad)
    
    # Decrypt with correct associated data -> Success
    decrypted = decrypt(payload, valid_key, associated_data=aad)
    assert decrypted == sample_plaintext
    
    # Decrypt with modified associated data -> Failure
    tampered_aad = b"exam_id:CS-501;version:2026-FINAL;classification:PUBLIC"
    with pytest.raises(DecryptionFailedError):
        decrypt(payload, valid_key, associated_data=tampered_aad)
        
    # Decrypt with missing associated data -> Failure
    with pytest.raises(DecryptionFailedError):
        decrypt(payload, valid_key, associated_data=None)


# ---------------------------------------------------------------------------
# 5. Invalid Nonce / Malformed Payload
# ---------------------------------------------------------------------------

def test_decryption_with_modified_nonce(valid_key, sample_plaintext):
    """Test 5a: Modifying the nonce causes authentication failure."""
    payload = bytearray(encrypt(sample_plaintext, valid_key))
    
    # Tamper with the nonce (first 12 bytes)
    payload[0] ^= 0x01
    
    with pytest.raises(DecryptionFailedError):
        decrypt(bytes(payload), valid_key)


def test_decryption_with_modified_auth_tag(valid_key, sample_plaintext):
    """Test 5b: Modifying the 16-byte authentication tag causes authentication failure."""
    payload = bytearray(encrypt(sample_plaintext, valid_key))
    
    # Tamper with the authentication tag (last byte)
    payload[-1] ^= 0xAA
    
    with pytest.raises(DecryptionFailedError):
        decrypt(bytes(payload), valid_key)


def test_decryption_with_truncated_payload(valid_key):
    """Test 5c: Payload shorter than NONCE_SIZE + TAG_SIZE raises ValueError."""
    # Valid minimum length is 12 + 16 = 28 bytes
    invalid_short_payload = os.urandom(NONCE_SIZE + TAG_SIZE - 1)
    
    with pytest.raises(ValueError, match="too short"):
        decrypt(invalid_short_payload, valid_key)


def test_invalid_parameter_types(valid_key):
    """Test 5d: Invalid argument types raise ValueError."""
    with pytest.raises(ValueError, match="Plaintext data must be bytes"):
        encrypt("not bytes", valid_key)  # type: ignore
        
    with pytest.raises(ValueError, match="Encryption key must be bytes"):
        encrypt(b"valid", "not bytes key")  # type: ignore
        
    with pytest.raises(ValueError, match="32-byte key"):
        encrypt(b"valid", b"short_key_16_by")
        
    with pytest.raises(ValueError, match="Encrypted payload must be bytes"):
        decrypt("not bytes", valid_key)  # type: ignore


# ---------------------------------------------------------------------------
# 6. Empty Input
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_empty_input(valid_key):
    """Test 6: Empty input (b'') encrypts and decrypts accurately."""
    empty_plaintext = b""
    payload = encrypt(empty_plaintext, valid_key)
    
    # Length must be exactly 12-byte nonce + 16-byte tag = 28 bytes
    assert len(payload) == NONCE_SIZE + TAG_SIZE
    
    recovered = decrypt(payload, valid_key)
    assert recovered == empty_plaintext


# ---------------------------------------------------------------------------
# 7. Binary Input
# ---------------------------------------------------------------------------

def test_encrypt_decrypt_binary_input(valid_key):
    """Test 7: Arbitrary binary data (e.g. simulated PDF / byte sequence) round-trips perfectly."""
    # Test all possible byte values 0x00 to 0xFF
    all_bytes = bytes(range(256))
    payload = encrypt(all_bytes, valid_key)
    assert decrypt(payload, valid_key) == all_bytes
    
    # Test large binary blob (e.g. 64 KB binary file)
    large_binary_data = os.urandom(64 * 1024)
    large_payload = encrypt(large_binary_data, valid_key)
    assert decrypt(large_payload, valid_key) == large_binary_data


# ---------------------------------------------------------------------------
# 8. Verify Secrets Do Not Appear in Logs or Exceptions
# ---------------------------------------------------------------------------

def test_no_secret_leakage_in_logs_and_exceptions(valid_key, sample_plaintext, caplog):
    """Test 8: Neither keys nor plaintext appear in logs or exception messages."""
    caplog.set_level(logging.DEBUG, logger="trustguard.crypto")
    
    secret_marker = b"HIGHLY_CONFIDENTIAL_SECRET_MARKER_98765"
    raw_key = os.urandom(32)
    b64_key = base64.b64encode(raw_key).decode("utf-8")
    
    # 1. Test during successful encryption and decryption
    payload = encrypt(secret_marker, raw_key)
    decrypted = decrypt(payload, raw_key)
    assert decrypted == secret_marker
    
    # 2. Test during failed decryption
    wrong_key = os.urandom(32)
    try:
        decrypt(payload, wrong_key)
    except DecryptionFailedError as exc:
        # Check exception message
        exc_str = str(exc)
        assert secret_marker.decode("utf-8") not in exc_str
        assert str(raw_key) not in exc_str
        assert str(wrong_key) not in exc_str
        assert b64_key not in exc_str
        
    # Check all captured log output
    full_log_text = caplog.text
    assert secret_marker.decode("utf-8") not in full_log_text
    assert str(raw_key) not in full_log_text
    assert str(wrong_key) not in full_log_text
    assert b64_key not in full_log_text


# ---------------------------------------------------------------------------
# 9. Search Repository for Accidental Hardcoded Keys
# ---------------------------------------------------------------------------

def test_no_accidental_hardcoded_keys_in_repository():
    """Test 9: Verify codebase does not contain committed live cryptographic keys or production secrets."""
    repo_root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    
    # Suspicious patterns to flag
    suspicious_patterns = [
        re.compile(r'TRUSTGUARD_MASTER_KEY\s*=\s*["\'][A-Za-z0-9+/]{43}=["\']'),
        re.compile(r'BEGIN (RSA|EC|DSA|OPENSSH|PRIVATE) KEY'),
        re.compile(r'aws_secret_access_key\s*=\s*["\'][A-Za-z0-9/+=]{40}["\']', re.IGNORECASE),
    ]
    
    scanned_files = 0
    for root, dirs, files in os.walk(repo_root):
        # Exclude git, caches, virtualenvs
        dirs[:] = [d for d in dirs if d not in {".git", ".pytest_cache", "__pycache__", "venv", ".venv", "node_modules", "trustguard.egg-info"}]
        
        for file in files:
            if file.endswith((".py", ".env", ".json", ".yaml", ".yml", ".toml")):
                filepath = os.path.join(root, file)
                scanned_files += 1
                with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()
                    for pattern in suspicious_patterns:
                        match = pattern.search(content)
                        assert match is None, f"Potential hardcoded key/secret pattern found in {filepath}: {match.group(0)}"
                        
    assert scanned_files > 10, "Should have scanned repository source files"


# ---------------------------------------------------------------------------
# 10. Key Manager Tests
# ---------------------------------------------------------------------------

def test_key_manager_generate_master_key():
    """Key manager generator produces valid 32-byte base64-encoded keys."""
    b64_key = generate_master_key()
    raw = base64.b64decode(b64_key, validate=True)
    assert len(raw) == MASTER_KEY_LENGTH


def test_key_manager_valid_key(monkeypatch):
    """Key manager successfully retrieves and decodes 32-byte key from environment."""
    raw_key = os.urandom(MASTER_KEY_LENGTH)
    b64_key = base64.b64encode(raw_key).decode("utf-8")
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", b64_key)
    
    loaded_key = get_master_key()
    assert loaded_key == raw_key


def test_key_manager_missing_env_var(monkeypatch):
    """Key manager raises RuntimeError when TRUSTGUARD_MASTER_KEY is not set."""
    monkeypatch.delenv("TRUSTGUARD_MASTER_KEY", raising=False)
    
    with pytest.raises(RuntimeError, match="environment variable is not set"):
        get_master_key()


def test_key_manager_invalid_base64(monkeypatch):
    """Key manager raises ValueError when key is invalid base64."""
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", "invalid!!base64==")
    
    with pytest.raises(ValueError, match="not a valid base64"):
        get_master_key()


def test_key_manager_wrong_byte_length(monkeypatch):
    """Key manager raises ValueError when key length is not 32 bytes."""
    # 16-byte key (AES-128) should be rejected
    raw_16 = os.urandom(16)
    b64_16 = base64.b64encode(raw_16).decode("utf-8")
    monkeypatch.setenv("TRUSTGUARD_MASTER_KEY", b64_16)
    
    with pytest.raises(ValueError, match="must be exactly 32 bytes"):
        get_master_key()


# ---------------------------------------------------------------------------
# 11. Integrity Hashing Tests
# ---------------------------------------------------------------------------

def test_generate_integrity_hash():
    """Integrity hash outputs standard formatted SHA-256 digest."""
    test_data = b"TrustGuard Zero-Trust Examination Security System"
    hash_str = generate_integrity_hash(test_data)
    
    assert hash_str.startswith("sha256:")
    assert len(hash_str) == 7 + 64  # "sha256:" + 64 hex characters
    
    # Test known vector
    known_data = b"hello world"
    known_hash = generate_integrity_hash(known_data)
    expected_hex = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    assert known_hash == f"sha256:{expected_hex}"


def test_generate_integrity_hash_type_validation():
    """Integrity hash raises ValueError for non-byte input."""
    with pytest.raises(ValueError, match="Data to hash must be bytes"):
        generate_integrity_hash("string is not bytes")  # type: ignore
