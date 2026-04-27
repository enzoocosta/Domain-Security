from copy import deepcopy
from dataclasses import dataclass
from threading import RLock
from time import monotonic

from app.core.config import settings


@dataclass
class CacheEntry:
    expires_at: float
    payload: dict


class AnalysisCache:
    """Thread-safe in-memory cache with short TTL for completed analyses."""

    def __init__(self, ttl_seconds: int | None = None) -> None:
        self.ttl_seconds = (
            settings.analysis_cache_ttl_seconds
            if ttl_seconds is None
            else max(0, ttl_seconds)
        )
        self._entries: dict[str, CacheEntry] = {}
        self._lock = RLock()

    def get(self, key: str) -> dict | None:
        if self.ttl_seconds <= 0:
            return None
        now = monotonic()
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            if entry.expires_at <= now:
                self._entries.pop(key, None)
                return None
            return deepcopy(entry.payload)

    def set(self, key: str, payload: dict) -> None:
        if self.ttl_seconds <= 0:
            return
        with self._lock:
            self._entries[key] = CacheEntry(
                expires_at=monotonic() + self.ttl_seconds,
                payload=deepcopy(payload),
            )

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
