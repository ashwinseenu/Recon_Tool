"""Token-bucket style rate limiter, one bucket per module name."""
from __future__ import annotations

import threading
import time
from typing import Dict

from .config import RateLimitConfig


class _Bucket:
    def __init__(self, rps: float) -> None:
        self.interval = 1.0 / max(rps, 0.01)
        self._next = 0.0
        self._lock = threading.Lock()

    def wait(self) -> None:
        with self._lock:
            now = time.monotonic()
            delay = self._next - now
            self._next = max(now, self._next) + self.interval
        if delay > 0:
            time.sleep(delay)


class RateLimiter:
    def __init__(self, cfg: RateLimitConfig) -> None:
        self.cfg = cfg
        self._buckets: Dict[str, _Bucket] = {}
        self._lock = threading.Lock()

    def throttle(self, name: str) -> None:
        with self._lock:
            b = self._buckets.get(name)
            if b is None:
                b = self._buckets[name] = _Bucket(self.cfg.per_module.get(name, self.cfg.default_rps))
        b.wait()
