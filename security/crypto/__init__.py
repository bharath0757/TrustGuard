"""
TrustGuard — Cryptographic Protection & Fragment Distribution Layer.

Provides:
- Authenticated Encryption (AES-256-GCM)
- Integrity Hashing (SHA-256)
- Development Key Management
- Encrypted Fragment Distribution (sharding, validation, reconstruction)
"""
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
from security.crypto.fragmentation import (
    FragmentationError,
    FragmentValidationError,
    FragmentPaperMismatchError,
    FragmentCountMismatchError,
    DuplicateFragmentError,
    MissingFragmentError,
    CorruptedFragmentError,
    FragmentIntegrityError,
    FragmentPayload,
    fragment_ciphertext,
    validate_fragments,
    reconstruct_ciphertext,
    protect_and_fragment_paper,
    retrieve_paper_fragments,
    reconstruct_and_decrypt_paper,
)

__all__ = [
    "NONCE_SIZE",
    "TAG_SIZE",
    "KEY_SIZE",
    "MASTER_KEY_LENGTH",
    "DecryptionFailedError",
    "encrypt",
    "decrypt",
    "encrypt_data",
    "decrypt_data",
    "generate_integrity_hash",
    "get_master_key",
    "generate_master_key",
    # Fragmentation
    "FragmentationError",
    "FragmentValidationError",
    "FragmentPaperMismatchError",
    "FragmentCountMismatchError",
    "DuplicateFragmentError",
    "MissingFragmentError",
    "CorruptedFragmentError",
    "FragmentIntegrityError",
    "FragmentPayload",
    "fragment_ciphertext",
    "validate_fragments",
    "reconstruct_ciphertext",
    "protect_and_fragment_paper",
    "retrieve_paper_fragments",
    "reconstruct_and_decrypt_paper",
]
