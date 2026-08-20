"""
TrustGuard — Ciphertext Fragmentation and Reconstruction Service.

Splits encrypted payloads into verifiable chunks and reassembles them.
"""

import hashlib
import math
from typing import List, Optional, Union


class FragmentIntegrityError(Exception):
    """Raised when fragment verification or reconstruction fails."""
    pass


class FragmentValidationError(FragmentIntegrityError):
    """Raised when fragment verification or checksum comparison fails."""
    pass


class FragmentPayload(bytes):
    """Fragment payload representation that acts as bytes with metadata attributes."""
    fragment_data: bytes
    fragment_index: int
    total_fragments: int
    integrity_hash: Optional[str]
    paper_id: Optional[str]

    def __new__(
        cls,
        fragment_data: bytes = b"",
        fragment_index: int = 0,
        total_fragments: int = 1,
        integrity_hash: Optional[str] = None,
        paper_id: Optional[str] = None,
        *,
        data: Optional[bytes] = None,
        index: Optional[int] = None,
    ):
        raw = fragment_data if fragment_data != b"" or data is None else data
        if not isinstance(raw, bytes):
            raw = bytes(raw)
        obj = super().__new__(cls, raw)
        obj.fragment_data = raw
        obj.fragment_index = fragment_index if index is None else index
        obj.total_fragments = total_fragments
        obj.integrity_hash = integrity_hash or (hashlib.sha256(raw).hexdigest() if raw else None)
        obj.paper_id = paper_id
        return obj


def fragment_ciphertext(ciphertext: bytes, num_fragments: int = 3, paper_id: Optional[str] = None) -> List[FragmentPayload]:
    """
    Split ciphertext into equal-sized fragments.
    
    Args:
        ciphertext: The encrypted payload bytes.
        num_fragments: Number of shards to produce (default 3).
        paper_id: Optional paper ID association.
        
    Returns:
        List of FragmentPayload instances.
    """
    if not isinstance(ciphertext, bytes):
        raise ValueError("Ciphertext must be bytes")
    if num_fragments < 1:
        raise ValueError("num_fragments must be >= 1")
    
    total_len = len(ciphertext)
    if total_len == 0:
        return [FragmentPayload(b"", i, num_fragments, paper_id=paper_id) for i in range(num_fragments)]

    chunk_size = math.ceil(total_len / num_fragments)
    fragments = []
    for i in range(num_fragments):
        start = i * chunk_size
        end = min(start + chunk_size, total_len)
        chunk_bytes = ciphertext[start:end]
        fragments.append(
            FragmentPayload(
                fragment_data=chunk_bytes,
                fragment_index=i,
                total_fragments=num_fragments,
                integrity_hash=hashlib.sha256(chunk_bytes).hexdigest(),
                paper_id=paper_id,
            )
        )
    return fragments


def reconstruct_ciphertext(fragments: List[Union[FragmentPayload, bytes]]) -> bytes:
    """
    Reconstruct original ciphertext by concatenating ordered fragments.
    
    Args:
        fragments: List of fragment byte blocks or FragmentPayload instances in original sequence.
        
    Returns:
        Reassembled ciphertext bytes.
    """
    if not fragments:
        return b""
    raw_blocks = []
    for f in fragments:
        if hasattr(f, "fragment_data"):
            raw_bytes = f.fragment_data
            if hasattr(f, "integrity_hash") and f.integrity_hash:
                actual_hash = hashlib.sha256(raw_bytes).hexdigest()
                if actual_hash != f.integrity_hash:
                    raise FragmentValidationError(
                        f"Integrity check failed for fragment {getattr(f, 'fragment_index', '?')}: "
                        f"expected {f.integrity_hash}, got {actual_hash}"
                    )
            raw_blocks.append(raw_bytes)
        elif isinstance(f, bytes):
            raw_blocks.append(f)
        else:
            raw_blocks.append(bytes(f))
    return b"".join(raw_blocks)
