"""Tests for the async token-bucket rate limiter."""

import asyncio
import time

import pytest

from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter, RateLimiterConfig


class TestRateLimiterConfig:
    def test_defaults(self) -> None:
        config = RateLimiterConfig()
        assert config.requests_per_second == 5.0
        assert config.burst_size == 10

    def test_frozen(self) -> None:
        config = RateLimiterConfig()
        with pytest.raises(AttributeError):
            config.requests_per_second = 100.0  # type: ignore[misc]


class TestAsyncTokenBucketRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire_within_burst(self) -> None:
        limiter = AsyncTokenBucketRateLimiter(
            RateLimiterConfig(requests_per_second=100.0, burst_size=5)
        )
        for _ in range(5):
            await limiter.acquire()

    @pytest.mark.asyncio
    async def test_rate_limiting_slows_requests(self) -> None:
        limiter = AsyncTokenBucketRateLimiter(
            RateLimiterConfig(requests_per_second=100.0, burst_size=2)
        )
        start = time.monotonic()
        for _ in range(4):
            await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed > 0.01

    @pytest.mark.asyncio
    async def test_available_tokens_decreases(self) -> None:
        limiter = AsyncTokenBucketRateLimiter(
            RateLimiterConfig(requests_per_second=1000.0, burst_size=10)
        )
        initial = limiter.available_tokens
        await limiter.acquire()
        assert limiter.available_tokens < initial

    @pytest.mark.asyncio
    async def test_concurrent_acquire(self) -> None:
        limiter = AsyncTokenBucketRateLimiter(
            RateLimiterConfig(requests_per_second=1000.0, burst_size=20)
        )
        tasks = [limiter.acquire() for _ in range(10)]
        await asyncio.gather(*tasks)
