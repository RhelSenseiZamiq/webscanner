"""SQL injection detection scanner."""

from __future__ import annotations

import asyncio
import re
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

ERROR_BASED_PAYLOADS: tuple[str, ...] = (
    "'", "\"", ")", "';--", "' OR '1'='1", "\" OR \"1\"=\"1",
    "1' AND '1'='1", "1 AND 1=1", "' UNION SELECT NULL--",
)

TIME_BASED_PAYLOADS: tuple[tuple[str, float], ...] = (
    ("' OR SLEEP(3)--", 3.0),
    ("'; WAITFOR DELAY '0:0:3'--", 3.0),
    ("' OR pg_sleep(3)--", 3.0),
)

SQL_ERROR_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern, re.IGNORECASE) for pattern in (
        r"SQL syntax.*?near",
        r"Syntax error.*?in query",
        r"mysql_fetch",
        r"ORA-\d{5}",
        r"Microsoft OLE DB Provider for SQL Server",
        r"Unclosed quotation mark",
        r"PostgreSQL.*?ERROR",
        r"Warning.*?mysql_",
        r"SQLSTATE\[",
        r"sqlite3\.OperationalError",
        r"com\.mysql\.jdbc",
        r"org\.postgresql\.util\.PSQLException",
    )
)


@dataclass(frozen=True)
class SQLInjectionScanner:
    """Detects SQL injection vulnerabilities."""

    http_client: ScopedHttpClient
    concurrency: int = 5

    @property
    def module_name(self) -> str:
        return "sqli"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            body = await response.text()
            params = _extract_params_from_html(body, target.base_url)

            semaphore = asyncio.Semaphore(self.concurrency)

            for param_url, param_name in params:
                error_findings = await self._test_error_based(
                    param_url, param_name, semaphore
                )
                findings.extend(error_findings)

                time_findings = await self._test_time_based(
                    param_url, param_name, semaphore
                )
                findings.extend(time_findings)

            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=len(params),
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )

    async def _test_error_based(
        self, url: str, param_name: str, semaphore: asyncio.Semaphore
    ) -> list[Finding]:
        findings: list[Finding] = []
        for payload in ERROR_BASED_PAYLOADS:
            async with semaphore:
                test_url = _inject_param(url, param_name, payload)
                try:
                    response = await self.http_client.get(test_url)
                    body = await response.text()
                    for pattern in SQL_ERROR_PATTERNS:
                        if pattern.search(body):
                            findings.append(
                                Finding(
                                    module=ScanModule.OWASP,
                                    check_name="sqli_error_based",
                                    severity=Severity.CRITICAL,
                                    title=f"SQL Injection (error-based) in '{param_name}'",
                                    description="SQL error message detected in response after injecting payload.",
                                    url=url,
                                    evidence=f"Payload: {payload}, Pattern: {pattern.pattern}",
                                    remediation="Use parameterized queries or prepared statements.",
                                    cwe_id="CWE-89",
                                    cvss_score=9.8,
                                )
                            )
                            return findings
                except Exception:
                    continue
        return findings

    async def _test_time_based(
        self, url: str, param_name: str, semaphore: asyncio.Semaphore
    ) -> list[Finding]:
        findings: list[Finding] = []
        for payload, expected_delay in TIME_BASED_PAYLOADS:
            async with semaphore:
                test_url = _inject_param(url, param_name, payload)
                try:
                    request_start = time.monotonic()
                    await self.http_client.get(test_url)
                    elapsed = time.monotonic() - request_start
                    if elapsed >= expected_delay * 0.8:
                        findings.append(
                            Finding(
                                module=ScanModule.OWASP,
                                check_name="sqli_time_based",
                                severity=Severity.CRITICAL,
                                title=f"SQL Injection (time-based) in '{param_name}'",
                                description=f"Response delayed by {elapsed:.1f}s with time-based payload.",
                                url=url,
                                evidence=f"Payload: {payload}, Delay: {elapsed:.1f}s",
                                remediation="Use parameterized queries or prepared statements.",
                                cwe_id="CWE-89",
                                cvss_score=9.8,
                            )
                        )
                        return findings
                except Exception:
                    continue
        return findings


def _extract_params_from_html(html: str, base_url: str) -> list[tuple[str, str]]:
    """Extract URL parameters from forms and links in HTML."""
    from urllib.parse import parse_qs, urljoin, urlparse

    from bs4 import BeautifulSoup

    params: list[tuple[str, str]] = []
    soup = BeautifulSoup(html, "lxml")

    for form in soup.find_all("form"):
        action = form.get("action", "")
        form_url = urljoin(base_url, action) if action else base_url
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                params.append((form_url, name))

    for link in soup.find_all("a", href=True):
        href = link["href"]
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        for param_name in parse_qs(parsed.query):
            params.append((full_url, param_name))

    return params


def _inject_param(url: str, param_name: str, payload: str) -> str:
    """Inject a payload into a URL parameter."""
    from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    query_params[param_name] = [payload]
    new_query = urlencode(query_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
