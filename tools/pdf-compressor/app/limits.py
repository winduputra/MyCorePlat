"""Process-local request guards: per-IP rate limiting and a concurrency cap.

Both are deliberately simple and dependency free. They protect this single
container only; the gateway applies its own limits in front of it.
"""

from __future__ import annotations

import threading
import time
from collections import deque


class RateLimiter:
    """Sliding-window limiter keyed by client IP."""

    def __init__(self, limit: int, window_seconds: float = 60.0, now_fn=time.monotonic):
        self._limit = limit
        self._window = window_seconds
        self._now = now_fn
        self._lock = threading.Lock()
        self._hits: dict[str, deque[float]] = {}

    def allow(self, key: str) -> bool:
        """Record an attempt and report whether it is within the limit.

        Blocked attempts are still recorded so sustained abuse stays throttled
        rather than resetting the window.
        """
        if self._limit <= 0:
            return True
        now = self._now()
        cutoff = now - self._window
        with self._lock:
            bucket = self._hits.setdefault(key, deque())
            while bucket and bucket[0] <= cutoff:
                bucket.popleft()
            if len(bucket) >= self._limit:
                bucket.append(now)
                return False
            bucket.append(now)
            return True

    def retry_after_seconds(self) -> int:
        return max(1, int(self._window))


class ConcurrencyGuard:
    """Non-blocking concurrency cap.

    ``try_acquire`` returns False when every slot is busy, so the caller can
    answer 503 immediately instead of queueing work behind slow compressions.
    """

    def __init__(self, limit: int) -> None:
        self._limit = max(1, limit)
        self._semaphore = threading.BoundedSemaphore(self._limit)

    def try_acquire(self) -> bool:
        return self._semaphore.acquire(blocking=False)

    def release(self) -> None:
        try:
            self._semaphore.release()
        except ValueError:
            # Releasing an unheld semaphore is a programming error elsewhere;
            # ignore it rather than failing the response.
            pass
