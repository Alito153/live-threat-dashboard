from __future__ import annotations

from threading import RLock
from time import monotonic
from typing import Any


class TTLCache:
    def __init__(self, ttl_seconds: float, max_items: int = 2048) -> None:
        self.ttl_seconds = max(1.0, float(ttl_seconds))
        self.max_items = max(1, int(max_items))
        self._items: dict[str, tuple[float, Any]] = {}
        self._lock = RLock()

    def get(self, key: str) -> Any | None:
        now = monotonic()
        with self._lock:
            value = self._items.get(key)
            if value is None:
                return None
            expires_at, payload = value
            if expires_at <= now:
                self._items.pop(key, None)
                return None
            return payload

    def set(self, key: str, payload: Any) -> None:
        now = monotonic()
        with self._lock:
            self._evict_expired_locked(now)
            if len(self._items) >= self.max_items:
                self._evict_oldest_locked()
            self._items[key] = (now + self.ttl_seconds, payload)

    def clear(self) -> None:
        with self._lock:
            self._items.clear()

    def _evict_expired_locked(self, now: float) -> None:
        expired_keys = [key for key, (expires_at, _) in self._items.items() if expires_at <= now]
        for key in expired_keys:
            self._items.pop(key, None)

    def _evict_oldest_locked(self) -> None:
        if not self._items:
            return
        oldest_key = min(self._items.items(), key=lambda item: item[1][0])[0]
        self._items.pop(oldest_key, None)
