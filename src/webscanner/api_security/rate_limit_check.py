"""API rate limiting verification scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

BURST_SIZE = 30
AUTH_PATHS: tuple[str, ...] = (
    "/api/v1/login", "/api/login", "/login", "/auth/login",
    "/api/v1/auth/token", "/oauth/token",
)


@dataclass(frozen=True)
class RateLimitScanner:
    """Verifies rate limiting on authentication endpoints."""

    http_client: ScopedHttpClient
    burst_size: int = BURST_SIZE

    @property
    def module_name(self) -> str:
        return "rate_limit_check"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        urls_tested = 0

        for path in AUTH_PATHS:
            url = f"{target.base_url.rstrip('/')}{path}"
            urls_tested += 1
            finding = await self._test_rate_limit(url)
            if finding:
                findings.append(finding)

        return ModuleResult(
            module=ScanModule.API_SECURITY,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_tested,
        )

    async def _test_rate_limit(self, url: str) -> Finding | None:
        responses: list[int] = []

        try:
            first = await self.http_client.get(url)
            if first.status == 404:
                return None
        except Exception:
            return None

        for _ in range(self.burst_size):
            try:
                response = await self.http_client.post(
                    url,
                    data='{"username":"test","password":"test"}',
                    headers={"Content-Type": "application/json"},
                )
                responses.append(response.status)
            except Exception:
                break

        rate_limited = any(status == 429 for status in responses)
        if not rate_limited and len(responses) >= self.burst_size // 2:
            return Finding(
                module=ScanModule.API_SECURITY,
                check_name="no_rate_limiting",
                severity=Severity.MEDIUM,
                title=f"No rate limiting on {url}",
                description=f"Sent {len(responses)} requests without receiving HTTP 429.",
                url=url,
                evidence=f"Status codes: {responses[-5:]}",
                remediation="Implement rate limiting on authentication endpoints.",
                cwe_id="CWE-307",
            )

        return None
