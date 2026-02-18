"""Server-Side Request Forgery (SSRF) detection scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

SSRF_PAYLOADS: tuple[str, ...] = (
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://localhost/",
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0.0.0.0/",
    "http://metadata.google.internal/computeMetadata/v1/",
)

URL_PARAM_NAMES: tuple[str, ...] = (
    "url", "uri", "path", "src", "source", "href",
    "link", "page", "site", "fetch", "load", "file",
    "callback", "proxy", "forward", "target",
)

SSRF_INDICATORS: tuple[str, ...] = (
    "ami-id", "instance-id", "hostname",
    "iam", "security-credentials",
    "meta-data", "computeMetadata",
    "169.254.169.254",
)


@dataclass(frozen=True)
class SSRFScanner:
    """Detects SSRF vulnerabilities via URL parameter injection."""

    http_client: ScopedHttpClient
    concurrency: int = 3

    @property
    def module_name(self) -> str:
        return "ssrf"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)
        urls_tested = 0

        for param_name in URL_PARAM_NAMES:
            for payload in SSRF_PAYLOADS:
                urls_tested += 1
                finding = await self._test_ssrf(
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

    async def _test_ssrf(
        self, base_url: str, param_name: str, payload: str,
        semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

        async with semaphore:
            parsed = urlparse(base_url)
            query = parse_qs(parsed.query, keep_blank_values=True)
            query[param_name] = [payload]
            test_url = urlunparse(parsed._replace(query=urlencode(query, doseq=True)))

            try:
                response = await self.http_client.get(test_url)
                body = await response.text()

                for indicator in SSRF_INDICATORS:
                    if indicator in body:
                        return Finding(
                            module=ScanModule.OWASP,
                            check_name="ssrf",
                            severity=Severity.CRITICAL,
                            title=f"SSRF via '{param_name}' parameter",
                            description=f"Internal resource indicator found in response after SSRF payload injection.",
                            url=base_url,
                            evidence=f"Payload: {payload}, Indicator: {indicator}",
                            remediation="Validate and sanitize all URL inputs. Use an allowlist of permitted domains.",
                            cwe_id="CWE-918",
                            cvss_score=9.1,
                        )
            except Exception:
                pass

        return None
