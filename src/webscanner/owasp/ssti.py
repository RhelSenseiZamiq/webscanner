"""Server-Side Template Injection (SSTI) scanner.

Injects mathematical expressions into URL parameters and detects whether the
template engine evaluates them. Only run against targets you have authorization to test.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

# Each tuple: (payload, expected_result_substring, engine_hint)
_PROBES: tuple[tuple[str, str, str], ...] = (
    ("{{7*7}}", "49", "Jinja2/Twig/Pebble"),
    ("${7*7}", "49", "Thymeleaf/FreeMarker/Spring EL"),
    ("<%= 7*7 %>", "49", "ERB (Ruby) / EJS (Node)"),
    ("#{7*7}", "49", "Pebble/Ruby"),
    ("{{7*'7'}}", "7777777", "Jinja2 (string multiply)"),
    ("{7*7}", "49", "Smarty/Go templates"),
    ("${{7*7}}", "49", "FreeMarker/Groovy"),
    ("[%= 7*7 %]", "49", "Mako"),
)


@dataclass(frozen=True)
class SSTIScanner:
    """Detects server-side template injection vulnerabilities."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "ssti"

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
                # Get baseline response first to avoid false positives
                baseline_url = _inject_param(param_url, param_name, "7")
                try:
                    baseline_resp = await self.http_client.get(baseline_url)
                    baseline_body = await baseline_resp.text()
                except Exception:
                    baseline_body = ""

                for payload, expected, engine in _PROBES:
                    # Skip if the expected string appears in baseline (pre-existing "49")
                    if expected in baseline_body:
                        continue
                    test_url = _inject_param(param_url, param_name, payload)
                    try:
                        resp = await self.http_client.get(test_url)
                        body = await resp.text()
                        if expected in body:
                            findings.append(Finding(
                                module=ScanModule.OWASP,
                                check_name="ssti",
                                severity=Severity.HIGH,
                                title=f"SSTI in parameter '{param_name}' ({engine})",
                                description=(
                                    f"The server evaluated the template expression {payload!r} "
                                    f"and returned '{expected}', indicating server-side template "
                                    "injection. This can often be escalated to remote code execution."
                                ),
                                url=param_url,
                                evidence=f"Payload: {payload!r} → response contains: {expected!r}",
                                remediation=(
                                    "Never render user input directly as a template. "
                                    "Use sandboxed template environments, pass user data as "
                                    "template variables, and upgrade to a framework version "
                                    "that disables dangerous template features."
                                ),
                                cwe_id="CWE-94",
                                cvss_score=8.8,
                            ))
                            break  # One finding per parameter is enough
                    except Exception:
                        continue

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
