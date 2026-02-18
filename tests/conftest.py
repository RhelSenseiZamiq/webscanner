"""Shared test fixtures for the web scanner."""

import pytest

from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter, RateLimiterConfig
from webscanner.core.scope import ScopeConfig
from webscanner.core.types import ScanTarget


@pytest.fixture
def sample_scope_config() -> ScopeConfig:
    return ScopeConfig(
        authorized_domains=frozenset({"example.com", "api.example.com"}),
        excluded_paths=frozenset({"/logout", "/delete-account"}),
        bug_bounty_program="example-bug-bounty",
        authorization_confirmed=True,
    )


@pytest.fixture
def sample_target() -> ScanTarget:
    return ScanTarget(
        base_url="https://example.com",
        authorized_domains=frozenset({"example.com"}),
        excluded_paths=frozenset({"/logout"}),
    )


@pytest.fixture
def fast_rate_limiter() -> AsyncTokenBucketRateLimiter:
    return AsyncTokenBucketRateLimiter(
        RateLimiterConfig(requests_per_second=1000.0, burst_size=100)
    )
