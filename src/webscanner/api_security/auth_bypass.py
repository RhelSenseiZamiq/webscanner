"""API authentication bypass detection scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

AUTH_BYPASS_TESTS: tuple[tuple[str, dict[str, str], str], ...] = (
    ("no_auth", {}, "No Authorization header"),
    ("empty_bearer", {"Authorization": "Bearer "}, "Empty Bearer token"),
    ("invalid_bearer", {"Authorization": "Bearer invalid_token_12345"}, "Invalid Bearer token"),
    ("jwt_none_alg", {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIn0."}, "JWT alg:none"),
)

PROTECTED_INDICATORS: tuple[str, ...] = (
    "users", "profile", "account", "settings",
    "dashboard", "admin", "orders", "payments",
)


@dataclass(frozen=True)
class AuthBypassScanner:
    """Tests API endpoints for authentication bypass vulnerabilities."""

    http_client: ScopedHttpClient
    concurrency: int = 3

    @property
    def module_name(self) -> str:
        return "auth_bypass"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)
        urls_tested = 0

        api_paths = [
            f"/api/v1/{resource}" for resource in PROTECTED_INDICATORS
        ]

        for path in api_paths:
            url = f"{target.base_url.rstrip('/')}{path}"
            for test_name, headers, description in AUTH_BYPASS_TESTS:
                urls_tested += 1
                finding = await self._test_bypass(
                    url, test_name, headers, description, semaphore
                )
                if finding:
                    findings.append(finding)
                    break

        return ModuleResult(
            module=ScanModule.API_SECURITY,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_tested,
        )

    async def _test_bypass(
        self, url: str, test_name: str, headers: dict[str, str],
        description: str, semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        async with semaphore:
            try:
                response = await self.http_client.get(url, headers=headers)
                if response.status == 200:
                    body = await response.text()
                    if len(body) > 50:
                        return Finding(
                            module=ScanModule.API_SECURITY,
                            check_name=f"auth_bypass_{test_name}",
                            severity=Severity.CRITICAL,
                            title=f"Auth bypass: {description}",
                            description=f"API endpoint returned data with {description}.",
                            url=url,
                            evidence=f"HTTP 200 with body ({len(body)} chars), test: {test_name}",
                            remediation="Implement proper authentication middleware on all API endpoints.",
                            cwe_id="CWE-287",
                            cvss_score=9.1,
                        )
            except Exception:
                pass
        return None
