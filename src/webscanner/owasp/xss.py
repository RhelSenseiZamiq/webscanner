"""Cross-site scripting (XSS) detection scanner."""

from __future__ import annotations

import asyncio
import re
import time
import uuid
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

REFLECTED_PAYLOADS: tuple[str, ...] = (
    "<script>alert('{probe}')</script>",
    "\"><script>alert('{probe}')</script>",
    "' onmouseover='alert({probe})'",
    "<img src=x onerror=alert('{probe}')>",
    "<svg/onload=alert('{probe}')>",
    "javascript:alert('{probe}')",
)

DOM_SINK_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern) for pattern in (
        r"document\.write\s*\(",
        r"\.innerHTML\s*=",
        r"\.outerHTML\s*=",
        r"eval\s*\(",
        r"setTimeout\s*\(\s*['\"]",
        r"setInterval\s*\(\s*['\"]",
        r"document\.location\s*=",
        r"window\.location\s*=",
    )
)

DOM_SOURCE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern) for pattern in (
        r"location\.hash",
        r"location\.search",
        r"location\.href",
        r"document\.URL",
        r"document\.referrer",
        r"window\.name",
    )
)


@dataclass(frozen=True)
class XSSScanner:
    """Detects reflected and DOM-based XSS vulnerabilities."""

    http_client: ScopedHttpClient
    concurrency: int = 5

    @property
    def module_name(self) -> str:
        return "xss"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            body = await response.text()

            findings.extend(_check_dom_xss(body, target.base_url))

            from webscanner.owasp.sqli import _extract_params_from_html
            params = _extract_params_from_html(body, target.base_url)

            semaphore = asyncio.Semaphore(self.concurrency)
            for param_url, param_name in params:
                reflected = await self._test_reflected(
                    param_url, param_name, semaphore
                )
                findings.extend(reflected)

            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=len(params) + 1,
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )

    async def _test_reflected(
        self, url: str, param_name: str, semaphore: asyncio.Semaphore
    ) -> list[Finding]:
        findings: list[Finding] = []
        for payload_template in REFLECTED_PAYLOADS:
            probe = str(uuid.uuid4())[:8]
            payload = payload_template.format(probe=probe)

            async with semaphore:
                from webscanner.owasp.sqli import _inject_param
                test_url = _inject_param(url, param_name, payload)
                try:
                    response = await self.http_client.get(test_url)
                    body = await response.text()
                    if probe in body and payload in body:
                        findings.append(
                            Finding(
                                module=ScanModule.OWASP,
                                check_name="xss_reflected",
                                severity=Severity.HIGH,
                                title=f"Reflected XSS in '{param_name}'",
                                description="Injected payload reflected unescaped in response.",
                                url=url,
                                evidence=f"Payload: {payload[:100]}, Param: {param_name}",
                                remediation="Sanitize and encode all user input before output.",
                                cwe_id="CWE-79",
                                cvss_score=6.1,
                            )
                        )
                        return findings
                except Exception:
                    continue
        return findings


def _check_dom_xss(html: str, url: str) -> list[Finding]:
    """Static analysis for DOM-based XSS patterns."""
    findings: list[Finding] = []
    has_source = any(p.search(html) for p in DOM_SOURCE_PATTERNS)
    if not has_source:
        return findings

    for pattern in DOM_SINK_PATTERNS:
        match = pattern.search(html)
        if match:
            findings.append(
                Finding(
                    module=ScanModule.OWASP,
                    check_name="xss_dom",
                    severity=Severity.MEDIUM,
                    title="Potential DOM-based XSS",
                    description=f"Found dangerous sink with user-controllable source: {match.group()}",
                    url=url,
                    evidence=f"Sink: {match.group()}, Sources: location.hash/search/href",
                    remediation="Avoid using innerHTML/document.write with user input. Use textContent instead.",
                    cwe_id="CWE-79",
                )
            )
            break

    return findings
