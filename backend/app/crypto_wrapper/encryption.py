import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class EncryptionError(Exception):
    """Raised when encryption or decryption fails."""


class AES256GCM:
    """AES-256-GCM authenticated encryption wrapper."""

    KEY_SIZE = 32
    NONCE_SIZE = 12

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 256-bit key."""
        return AESGCM.generate_key(bit_length=256)

    @staticmethod
    def encrypt(
        plaintext: bytes,
        key: bytes,
        associated_data: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        """Encrypt plaintext and return (ciphertext, nonce)."""

        if len(key) != AES256GCM.KEY_SIZE:
            raise EncryptionError("AES-256 key must be exactly 32 bytes.")

        nonce = os.urandom(AES256GCM.NONCE_SIZE)

        try:
            aesgcm = AESGCM(key)
            ciphertext = aesgcm.encrypt(
                nonce,
                plaintext,
                associated_data,
            )
            return ciphertext, nonce

        except Exception as exc:
            raise EncryptionError("Encryption failed.") from exc

    @staticmethod
    def decrypt(
        ciphertext: bytes,
        key: bytes,
        nonce: bytes,
        associated_data: bytes | None = None,
    ) -> bytes:
        """Decrypt and authenticate AES-256-GCM ciphertext."""

        if len(key) != AES256GCM.KEY_SIZE:
            raise EncryptionError("AES-256 key must be exactly 32 bytes.")

        if len(nonce) != AES256GCM.NONCE_SIZE:
            raise EncryptionError("AES-GCM nonce must be exactly 12 bytes.")

        try:
            aesgcm = AESGCM(key)
            return aesgcm.decrypt(
                nonce,
                ciphertext,
                associated_data,
            )

        except Exception as exc:
            raise EncryptionError(
                "Decryption failed or ciphertext authentication failed."
            ) from exc
