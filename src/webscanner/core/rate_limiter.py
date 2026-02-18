"""Async token-bucket rate limiter for responsible scanning."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass


@dataclass(frozen=True)
class RateLimiterConfig:
    """Immutable rate limiter configuration."""

    requests_per_second: float = 5.0
    burst_size: int = 10


class AsyncTokenBucketRateLimiter:
    """Async token-bucket rate limiter shared across all scan modules."""

    def __init__(self, config: RateLimiterConfig) -> None:
        self._config = config
        self._tokens: float = float(config.burst_size)
        self._last_refill: float = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Block until a token is available, then consume one."""
        async with self._lock:
            self._refill()
            while self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self._config.requests_per_second
                await asyncio.sleep(wait_time)
                self._refill()
            self._tokens -= 1.0

    def _refill(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_refill
        new_tokens = elapsed * self._config.requests_per_second
        self._tokens = min(float(self._config.burst_size), self._tokens + new_tokens)
        self._last_refill = now

    @property
    def available_tokens(self) -> float:
        """Current available tokens (for monitoring)."""
        return self._tokens
