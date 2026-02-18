"""OS command injection scanner.

Tests URL parameters for command injection vulnerabilities using both output-based
and time-based detection. Only run against targets you have explicit authorization to test.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

# Output-based payloads — detect known strings in response
_OUTPUT_PAYLOADS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("; id", re.compile(r"uid=\d+\(", re.IGNORECASE)),
    ("| id", re.compile(r"uid=\d+\(", re.IGNORECASE)),
    ("&& id", re.compile(r"uid=\d+\(", re.IGNORECASE)),
    ("`id`", re.compile(r"uid=\d+\(", re.IGNORECASE)),
    ("$(id)", re.compile(r"uid=\d+\(", re.IGNORECASE)),
    ("; whoami", re.compile(r"\b(root|www-data|apache|nginx|nobody)\b", re.IGNORECASE)),
    ("| whoami", re.compile(r"\b(root|www-data|apache|nginx|nobody)\b", re.IGNORECASE)),
    ("& whoami", re.compile(r"nt authority\\system|administrator", re.IGNORECASE)),
)

# Time-based payloads — detect response delay
_TIME_PAYLOADS: tuple[tuple[str, float], ...] = (
    ("; sleep 5", 4.5),
    ("| sleep 5", 4.5),
    ("&& sleep 5", 4.5),
    ("$(sleep 5)", 4.5),
    ("`sleep 5`", 4.5),
    ("; ping -c 5 127.0.0.1", 4.5),
)


@dataclass(frozen=True)
class CommandInjectionScanner:
    """Detects OS command injection vulnerabilities in URL parameters."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "command_injection"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            html = await response.text()
            params = _extract_params(html, target.base_url)

            for param_url, param_name in params:
                # Try output-based first (faster)
                output_finding = await self._test_output_based(param_url, param_name)
                if output_finding:
                    findings.append(output_finding)
                    continue

                # Fall back to time-based
                time_finding = await self._test_time_based(param_url, param_name)
                if time_finding:
                    findings.append(time_finding)

            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=len(params),
            )
        except Exception as exc:
            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(exc),
            )

    async def _test_output_based(self, url: str, param_name: str) -> Finding | None:
        for payload, pattern in _OUTPUT_PAYLOADS:
            test_url = _inject_param(url, param_name, payload)
            try:
                resp = await self.http_client.get(test_url)
                body = await resp.text()
                if pattern.search(body):
                    return Finding(
                        module=ScanModule.OWASP,
                        check_name="command_injection_output",
                        severity=Severity.CRITICAL,
                        title=f"OS Command Injection in parameter '{param_name}'",
                        description=(
                            "The server executed an OS command and returned its output. "
                            "An attacker can run arbitrary commands on the server."
                        ),
                        url=url,
                        evidence=f"Payload: {payload!r} → output matched: {pattern.pattern}",
                        remediation=(
                            "Never pass user-controlled data to shell commands. "
                            "Use safe APIs (e.g. subprocess with a list, not shell=True). "
                            "Apply strict input validation and allow-listing."
                        ),
                        cwe_id="CWE-78",
                        cvss_score=10.0,
                    )
            except Exception:
                continue
        return None

    async def _test_time_based(self, url: str, param_name: str) -> Finding | None:
        for payload, min_delay in _TIME_PAYLOADS:
            test_url = _inject_param(url, param_name, payload)
            try:
                t0 = time.monotonic()
                await self.http_client.get(test_url)
                elapsed = time.monotonic() - t0
                if elapsed >= min_delay:
                    return Finding(
                        module=ScanModule.OWASP,
                        check_name="command_injection_time",
                        severity=Severity.CRITICAL,
                        title=f"OS Command Injection (time-based) in parameter '{param_name}'",
                        description=(
                            f"Response delayed by {elapsed:.1f}s after injecting a sleep "
                            "command, indicating blind OS command injection."
                        ),
                        url=url,
                        evidence=f"Payload: {payload!r} → delay: {elapsed:.1f}s",
                        remediation=(
                            "Never pass user-controlled data to shell commands. "
                            "Use safe APIs (e.g. subprocess with a list, not shell=True). "
                            "Apply strict input validation and allow-listing."
                        ),
                        cwe_id="CWE-78",
                        cvss_score=10.0,
                    )
            except Exception:
                continue
        return None


def _extract_params(html: str, base_url: str) -> list[tuple[str, str]]:
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
    parsed = urlparse(url)
    query_params = parse_qs(parsed.query, keep_blank_values=True)
    query_params[param_name] = [payload]
    new_query = urlencode(query_params, doseq=True)
    return urlunparse(parsed._replace(query=new_query))
