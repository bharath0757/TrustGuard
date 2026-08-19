import hashlib


class FragmentationError(Exception):
    """Raised when fragmentation fails."""


class Fragmenter:
    """Split encrypted payloads and generate integrity hashes."""

    @staticmethod
    def split(data: bytes, fragment_size: int = 1024) -> list[bytes]:
        """
        Split data into fragments.

        Args:
            data: Encrypted payload.
            fragment_size: Maximum size of each fragment in bytes.

        Returns:
            List of byte fragments.
        """
        if not isinstance(data, bytes):
            raise FragmentationError("Data must be bytes.")

        if not data:
            raise FragmentationError("Cannot fragment empty data.")

        if fragment_size <= 0:
            raise FragmentationError("Fragment size must be greater than zero.")

        return [
            data[i:i + fragment_size]
            for i in range(0, len(data), fragment_size)
        ]

    @staticmethod
    def hash_fragment(fragment: bytes) -> str:
        """Generate a SHA-256 hash for one fragment."""
        if not isinstance(fragment, bytes):
            raise FragmentationError("Fragment must be bytes.")

        return hashlib.sha256(fragment).hexdigest()

    @staticmethod
    def hash_fragments(fragments: list[bytes]) -> list[str]:
        """Generate SHA-256 hashes for all fragments."""
        return [
            Fragmenter.hash_fragment(fragment)
            for fragment in fragments
        ]
