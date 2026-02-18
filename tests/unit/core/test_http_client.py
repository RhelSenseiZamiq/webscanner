"""Tests for the scoped HTTP client."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from webscanner.core.exceptions import NetworkError
from webscanner.core.http_client import HttpClientConfig, ScopedHttpClient, _build_user_agent
from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter, RateLimiterConfig
from webscanner.core.types import ScanTarget


class TestBuildUserAgent:
    def test_basic(self) -> None:
        config = HttpClientConfig()
        assert _build_user_agent(config) == "WebScanner/0.1.0"

    def test_with_program(self) -> None:
        config = HttpClientConfig(program_name="test-bounty")
        ua = _build_user_agent(config)
        assert "Bug Bounty: test-bounty" in ua

    def test_with_contact(self) -> None:
        config = HttpClientConfig(contact_email="test@test.com")
        ua = _build_user_agent(config)
        assert "Contact: test@test.com" in ua


class TestScopedHttpClient:
    @pytest.mark.asyncio
    async def test_rejects_out_of_scope_url(self, sample_target: ScanTarget, fast_rate_limiter: AsyncTokenBucketRateLimiter) -> None:
        client = ScopedHttpClient(
            config=HttpClientConfig(),
            rate_limiter=fast_rate_limiter,
            target=sample_target,
        )
        with pytest.raises(NetworkError, match="outside authorized scope"):
            await client.get("https://evil.com/page")
        await client.close()

    @pytest.mark.asyncio
    async def test_context_manager(self, sample_target: ScanTarget, fast_rate_limiter: AsyncTokenBucketRateLimiter) -> None:
        async with ScopedHttpClient(
            config=HttpClientConfig(),
            rate_limiter=fast_rate_limiter,
            target=sample_target,
        ) as client:
            assert client is not None

    @pytest.mark.asyncio
    async def test_close_without_session(self, sample_target: ScanTarget, fast_rate_limiter: AsyncTokenBucketRateLimiter) -> None:
        client = ScopedHttpClient(
            config=HttpClientConfig(),
            rate_limiter=fast_rate_limiter,
            target=sample_target,
        )
        await client.close()
