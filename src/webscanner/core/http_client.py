"""Shared async HTTP client factory with retry and rate limiting."""

from __future__ import annotations

import asyncio
import ssl
from dataclasses import dataclass, field
from typing import Any

import aiohttp
import certifi

from webscanner.core.exceptions import NetworkError
from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter
from webscanner.core.scope import is_url_in_scope
from webscanner.core.types import ScanTarget


@dataclass(frozen=True)
class HttpClientConfig:
    """Immutable HTTP client configuration."""

    timeout_seconds: int = 10
    max_retries: int = 3
    retry_base_delay: float = 1.0
    user_agent: str = "WebScanner/0.1.0"
    program_name: str = ""
    contact_email: str = ""
    verify_ssl: bool = True


def _build_user_agent(config: HttpClientConfig) -> str:
    parts = [config.user_agent]
    if config.program_name:
        parts.append(f"(Bug Bounty: {config.program_name})")
    if config.contact_email:
        parts.append(f"(Contact: {config.contact_email})")
    return " ".join(parts)


@dataclass
class ScopedHttpClient:
    """HTTP client that enforces scope checking on every request."""

    config: HttpClientConfig
    rate_limiter: AsyncTokenBucketRateLimiter
    target: ScanTarget
    _session: aiohttp.ClientSession | None = field(default=None, init=False, repr=False)

    async def get(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a scope-checked, rate-limited GET request with retry."""
        return await self._request("GET", url, **kwargs)

    async def post(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a scope-checked, rate-limited POST request with retry."""
        return await self._request("POST", url, **kwargs)

    async def head(self, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a scope-checked, rate-limited HEAD request with retry."""
        return await self._request("HEAD", url, **kwargs)

    async def request(self, method: str, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        """Make a scope-checked, rate-limited request with an arbitrary HTTP method."""
        return await self._request(method, url, **kwargs)

    async def _request(self, method: str, url: str, **kwargs: Any) -> aiohttp.ClientResponse:
        if not is_url_in_scope(url, self.target):
            raise NetworkError(f"URL {url!r} is outside authorized scope")

        await self.rate_limiter.acquire()
        session = await self._get_session()

        last_error: Exception | None = None
        for attempt in range(self.config.max_retries):
            try:
                response = await session.request(method, url, **kwargs)
                return response
            except aiohttp.ClientError as e:
                last_error = e
                if attempt < self.config.max_retries - 1:
                    delay = self.config.retry_base_delay * (2**attempt)
                    await asyncio.sleep(delay)

        raise NetworkError(f"Request to {url!r} failed after {self.config.max_retries} retries: {last_error}")

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout_seconds)
            headers = {
                "User-Agent": _build_user_agent(self.config),
            }
            if self.config.contact_email:
                headers["X-Scanner-Contact"] = self.config.contact_email

            ssl_context: ssl.SSLContext | bool = False
            if self.config.verify_ssl:
                ssl_context = ssl.create_default_context(cafile=certifi.where())

            connector = aiohttp.TCPConnector(ssl=ssl_context)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers=headers,
                connector=connector,
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying session."""
        if self._session and not self._session.closed:
            await self._session.close()

    async def __aenter__(self) -> ScopedHttpClient:
        return self

    async def __aexit__(self, *args: Any) -> None:
        await self.close()
