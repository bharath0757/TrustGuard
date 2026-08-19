"""Ephemeral RAM Data Store using Redis with TTL and In-Memory Fallback.

Ensures encrypted question paper payload chunks and key shares reside strictly in RAM
and automatically expire after the configured TTL (Time-To-Live).
"""

from datetime import datetime, timezone
import logging
from typing import Any, Dict, List, Optional
import redis.asyncio as redis
from app.core.config import settings

logger = logging.getLogger(__name__)


class InMemoryTTLStore:
    """Thread-safe, RAM-only fallback store when a local Redis service is unavailable."""

    def __init__(self):
        self._store: Dict[str, tuple[Any, float]] = {}

    def _purge_expired(self):
        now = datetime.now(timezone.utc).timestamp()
        expired_keys = [k for k, (_, exp) in self._store.items() if exp < now]
        for k in expired_keys:
            del self._store[k]

    def set(self, key: str, value: Any, ttl_seconds: int):
        self._purge_expired()
        expire_at = datetime.now(timezone.utc).timestamp() + ttl_seconds
        self._store[key] = (value, expire_at)

    def get(self, key: str) -> Optional[Any]:
        self._purge_expired()
        item = self._store.get(key)
        if not item:
            return None
        val, exp = item
        if exp < datetime.now(timezone.utc).timestamp():
            del self._store[key]
            return None
        return val

    def delete_prefix(self, prefix: str):
        self._purge_expired()
        keys_to_del = [k for k in self._store.keys() if k.startswith(prefix)]
        for k in keys_to_del:
            del self._store[k]


class EphemeralStore:
    """Ephemeral Store Abstraction."""

    def __init__(self):
        self.redis_client: Optional[redis.Redis] = None
        self.memory_fallback = InMemoryTTLStore()
        self._use_fallback = False

    async def _get_redis(self) -> Optional[redis.Redis]:
        if self._use_fallback:
            return None
        if self.redis_client is None:
            try:
                client = redis.from_url(settings.REDIS_URL, decode_responses=False)
                await client.ping()
                self.redis_client = client
            except Exception as e:
                logger.warning(f"Redis unavailable ({e}), using in-memory TTL store fallback.")
                self._use_fallback = True
                return None
        return self.redis_client

    async def store_payload_chunks(self, exam_id: str, chunks: List[bytes], ttl_seconds: int = 1800):
        """Store encrypted payload chunks in RAM with automatic TTL."""
        client = await self._get_redis()
        prefix = f"trustguard:ephemeral:exam:{exam_id}:chunk:"
        if client:
            pipe = client.pipeline()
            for idx, chunk in enumerate(chunks):
                key = f"{prefix}{idx}"
                await pipe.set(key, chunk, ex=ttl_seconds)
            await pipe.execute()
            await client.set(f"trustguard:ephemeral:exam:{exam_id}:count", str(len(chunks)), ex=ttl_seconds)
        else:
            for idx, chunk in enumerate(chunks):
                self.memory_fallback.set(f"{prefix}{idx}", chunk, ttl_seconds)
            self.memory_fallback.set(f"trustguard:ephemeral:exam:{exam_id}:count", len(chunks), ttl_seconds)

    async def get_payload_chunks(self, exam_id: str) -> List[bytes]:
        """Fetch encrypted payload chunks from ephemeral store."""
        client = await self._get_redis()
        prefix = f"trustguard:ephemeral:exam:{exam_id}:chunk:"
        chunks = []
        if client:
            count_val = await client.get(f"trustguard:ephemeral:exam:{exam_id}:count")
            if not count_val:
                return []
            count = int(count_val)
            for idx in range(count):
                chunk = await client.get(f"{prefix}{idx}")
                if chunk:
                    chunks.append(chunk)
        else:
            count_val = self.memory_fallback.get(f"trustguard:ephemeral:exam:{exam_id}:count")
            if count_val is None:
                return []
            for idx in range(int(count_val)):
                chunk = self.memory_fallback.get(f"{prefix}{idx}")
                if chunk:
                    chunks.append(chunk)
        return chunks

    async def store_key_share(self, exam_id: str, guardian_id: str, share_data: str, ttl_seconds: int = 1800):
        """Store ephemeral guardian key share."""
        client = await self._get_redis()
        key = f"trustguard:ephemeral:exam:{exam_id}:share:{guardian_id}"
        if client:
            await client.set(key, share_data.encode("utf-8"), ex=ttl_seconds)
        else:
            self.memory_fallback.set(key, share_data.encode("utf-8"), ttl_seconds)

    async def get_key_share(self, exam_id: str, guardian_id: str) -> Optional[str]:
        """Fetch a specific guardian's ephemeral key share."""
        client = await self._get_redis()
        key = f"trustguard:ephemeral:exam:{exam_id}:share:{guardian_id}"
        if client:
            val = await client.get(key)
            if val:
                return val.decode("utf-8") if isinstance(val, bytes) else val
        else:
            val = self.memory_fallback.get(key)
            if val:
                return val.decode("utf-8") if isinstance(val, bytes) else val
        return None

    async def get_key_shares(self, exam_id: str) -> Dict[str, str]:
        """Get all stored ephemeral key shares for an exam."""
        client = await self._get_redis()
        prefix = f"trustguard:ephemeral:exam:{exam_id}:share:"
        shares = {}
        if client:
            keys = await client.keys(f"{prefix}*")
            for k in keys:
                guardian_id = k.decode("utf-8").replace(prefix, "") if isinstance(k, bytes) else k.replace(prefix, "")
                val = await client.get(k)
                if val:
                    shares[guardian_id] = val.decode("utf-8") if isinstance(val, bytes) else val
        else:
            # Check memory fallback
            for k, (v, exp) in list(self.memory_fallback._store.items()):
                if k.startswith(prefix) and exp > datetime.now(timezone.utc).timestamp():
                    guardian_id = k.replace(prefix, "")
                    shares[guardian_id] = v.decode("utf-8") if isinstance(v, bytes) else v
        return shares

    async def purge_exam_data(self, exam_id: str):
        """Purge all ephemeral payload chunks and key shares immediately."""
        client = await self._get_redis()
        prefix = f"trustguard:ephemeral:exam:{exam_id}:"
        if client:
            keys = await client.keys(f"{prefix}*")
            if keys:
                await client.delete(*keys)
        else:
            self.memory_fallback.delete_prefix(prefix)

    # ── Live Exam Session State ───────────────────────────────────────────

    async def store_exam_session_state(self, exam_id: str, state: dict, ttl_seconds: int = 86400):
        """Store live exam session state (metrics, counters) with TTL."""
        import json
        client = await self._get_redis()
        key = f"trustguard:live:exam:{exam_id}:state"
        data = json.dumps(state)
        if client:
            await client.set(key, data.encode("utf-8"), ex=ttl_seconds)
        else:
            self.memory_fallback.set(key, data, ttl_seconds)

    async def get_exam_session_state(self, exam_id: str) -> Optional[dict]:
        """Retrieve live exam session state."""
        import json
        client = await self._get_redis()
        key = f"trustguard:live:exam:{exam_id}:state"
        if client:
            val = await client.get(key)
            if val:
                return json.loads(val.decode("utf-8") if isinstance(val, bytes) else val)
        else:
            val = self.memory_fallback.get(key)
            if val:
                return json.loads(val) if isinstance(val, str) else val
        return None

    async def update_exam_session_metric(self, exam_id: str, metric: str, increment: int = 1):
        """Increment a specific metric counter in the live exam state."""
        state = await self.get_exam_session_state(exam_id)
        if state:
            state[metric] = state.get(metric, 0) + increment
            await self.store_exam_session_state(exam_id, state)

    async def purge_exam_session_state(self, exam_id: str):
        """Remove live exam session state."""
        client = await self._get_redis()
        key = f"trustguard:live:exam:{exam_id}:state"
        if client:
            await client.delete(key)
        else:
            self.memory_fallback._store.pop(key, None)


# Singleton instance of ephemeral store
ephemeral_store = EphemeralStore()


def get_ephemeral_store() -> EphemeralStore:
    return ephemeral_store

