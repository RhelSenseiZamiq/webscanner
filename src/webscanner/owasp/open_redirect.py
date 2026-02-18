"""Open redirect detection scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

REDIRECT_PARAMS: tuple[str, ...] = (
    "redirect", "url", "next", "return", "dest", "destination",
    "redir", "redirect_uri", "redirect_url", "return_url",
    "returnTo", "goto", "continue", "target", "link",
)

REDIRECT_PAYLOADS: tuple[str, ...] = (
    "https://evil.example.com",
    "//evil.example.com",
    "/\\evil.example.com",
    "https://evil.example.com/%2F..",
)


@dataclass(frozen=True)
class OpenRedirectScanner:
    """Detects open redirect vulnerabilities in URL parameters."""

    http_client: ScopedHttpClient
    concurrency: int = 5

    @property
    def module_name(self) -> str:
        return "open_redirect"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)
        urls_tested = 0

        for param_name in REDIRECT_PARAMS:
            for payload in REDIRECT_PAYLOADS:
                urls_tested += 1
                finding = await self._test_redirect(
                    target.base_url, param_name, payload, semaphore
                )
                if finding:
                    findings.append(finding)
                    break

        return ModuleResult(
            module=ScanModule.OWASP,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_tested,
        )

    async def _test_redirect(
        self, base_url: str, param_name: str, payload: str,
        semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        async with semaphore:
            parsed = urlparse(base_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

            try:
                response = await self.http_client.get(test_url)
                location = response.headers.get("Location", "")

                if _is_external_redirect(location, payload):
                    return Finding(
                        module=ScanModule.OWASP,
                        check_name="open_redirect",
                        severity=Severity.MEDIUM,
                        title=f"Open redirect via '{param_name}' parameter",
                        description=f"Parameter '{param_name}' redirects to external URL.",
                        url=base_url,
                        evidence=f"Payload: {payload}, Location: {location}",
                        remediation="Validate redirect URLs against an allowlist of trusted domains.",
                        cwe_id="CWE-601",
                    )

                body = await response.text()
                if "evil.example.com" in body:
                    return Finding(
                        module=ScanModule.OWASP,
                        check_name="open_redirect",
                        severity=Severity.MEDIUM,
                        title=f"Open redirect via '{param_name}' (body-based)",
                        description=f"Redirect payload reflected in response body.",
                        url=base_url,
                        evidence=f"Payload: {payload} found in response body",
                        remediation="Validate redirect URLs against an allowlist of trusted domains.",
                        cwe_id="CWE-601",
                    )
            except Exception:
                pass

            return None


def _is_external_redirect(location: str, payload: str) -> bool:
    """Check if a Location header points to an external attacker-controlled URL."""
    if not location:
        return False
    return "evil.example.com" in location
