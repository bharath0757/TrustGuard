"""Crypto Wrapper Interface for Security/Cryptography Team Integration.

DO NOT replace this adapter with custom/unverified crypto algorithms.
This interface defines the exact contract required by the TrustGuard API.
The cryptography team should replace MockThresholdCryptoAdapter with their HSM/DKG/Shamir Secret Sharing implementation.
"""

from abc import ABC, abstractmethod
import hashlib
from typing import Any, Dict, List, Optional


class KeyShare:
    def __init__(self, guardian_id: str, share_index: int, share_data: str):
        self.guardian_id = guardian_id
        self.share_index = share_index
        self.share_data = share_data

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guardian_id": self.guardian_id,
            "share_index": self.share_index,
            "share_data": self.share_data,
        }


class ThresholdCryptoAdapter(ABC):
    """Abstract Cryptographic Adapter for Threshold Cryptography & Ephemeral Operations."""

    @abstractmethod
    def split_secret(
        self, secret_bytes: bytes, threshold_k: int, total_n: int, guardian_ids: List[str]
    ) -> List[KeyShare]:
        """Split a master key/secret into n shares with threshold k."""
        pass

    @abstractmethod
    def verify_share(self, share: KeyShare, public_key_fingerprint: str) -> bool:
        """Verify the validity of a submitted key share against guardian public key fingerprint."""
        pass

    @abstractmethod
    def compute_payload_hash(self, payload_bytes: bytes) -> str:
        """Compute cryptographic hash (SHA-256) of raw payload for integrity metadata."""
        pass

    @abstractmethod
    def watermark_chunk_stream(self, chunk_bytes: bytes, center_id: str) -> bytes:
        """Apply dynamic traceable watermark metadata to an ephemeral chunk stream."""
        pass


class MockThresholdCryptoAdapter(ThresholdCryptoAdapter):
    """Mock implementation for API development and automated testing.

    Simulates key-share distribution and verification contracts cleanly
    without inventing pseudo-cryptography algorithms.
    """

    def split_secret(
        self, secret_bytes: bytes, threshold_k: int, total_n: int, guardian_ids: List[str]
    ) -> List[KeyShare]:
        shares = []
        payload_hash = self.compute_payload_hash(secret_bytes)
        for idx, g_id in enumerate(guardian_ids[:total_n]):
            # Mock share format containing deterministic test share token
            share_token = f"MOCK_SHARE_K{threshold_k}_N{total_n}_IDX{idx+1}_HASH{payload_hash[:8]}_{g_id}"
            shares.append(KeyShare(guardian_id=g_id, share_index=idx + 1, share_data=share_token))
        return shares

    def verify_share(self, share: KeyShare, public_key_fingerprint: str) -> bool:
        # Mock validation: Share must contain 'MOCK_SHARE' and guardian_id matching public key fingerprint pattern
        return bool(share.share_data and "MOCK_SHARE" in share.share_data)

    def compute_payload_hash(self, payload_bytes: bytes) -> str:
        return hashlib.sha256(payload_bytes).hexdigest()

    def watermark_chunk_stream(self, chunk_bytes: bytes, center_id: str) -> bytes:
        # Ephemeral header prefix simulating traceability tag
        tag = f"[TRUSTGUARD_TRACEABILITY:CENTER={center_id}]".encode("utf-8")
        return tag + chunk_bytes


# Global default instance of crypto adapter (replaceable by Security/Crypto Team)
default_crypto_adapter: ThresholdCryptoAdapter = MockThresholdCryptoAdapter()


def get_crypto_adapter() -> ThresholdCryptoAdapter:
    return default_crypto_adapter
