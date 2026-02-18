"""HTTP method tampering / dangerous method scanner.

Checks for insecure HTTP methods (TRACE, PUT, DELETE, PATCH) that should not be
enabled on production servers. Only run against targets you have authorization to test.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

# Probe path used for PUT/DELETE checks — unlikely to exist, so 200/201 is suspicious
_PROBE_PATH = "/webscanner-method-probe-do-not-use"


@dataclass(frozen=True)
class HttpMethodScanner:
    """Detects dangerous or misconfigured HTTP methods on the target."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "http_methods"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        urls_scanned = 0

        # --- TRACE ---
        try:
            resp = await self.http_client.request("TRACE", target.base_url)
            urls_scanned += 1
            body = await resp.text()
            # TRACE echoes the request back in the body; look for our method in response
            if resp.status == 200 and "TRACE" in (body or "").upper():
                findings.append(Finding(
                    module=ScanModule.OWASP,
                    check_name="http_trace_enabled",
                    severity=Severity.MEDIUM,
                    title="HTTP TRACE method enabled",
                    description=(
                        "The server responds to TRACE requests and echoes the request body. "
                        "TRACE can be used in Cross-Site Tracing (XST) attacks to steal "
                        "HttpOnly cookies and authentication headers."
                    ),
                    url=target.base_url,
                    evidence=f"TRACE {target.base_url} → HTTP {resp.status}",
                    remediation=(
                        "Disable TRACE in your web server configuration. "
                        "Apache: TraceEnable Off. Nginx: deny TRACE in server block."
                    ),
                    cwe_id="CWE-16",
                    cvss_score=5.8,
                ))
        except Exception:
            pass

        # --- OPTIONS — check Allow header for dangerous methods ---
        try:
            resp = await self.http_client.request("OPTIONS", target.base_url)
            urls_scanned += 1
            allow_header = resp.headers.get("Allow", "") or resp.headers.get("allow", "")
            dangerous = [m for m in ("TRACE", "PUT", "DELETE") if m in allow_header.upper()]
            if dangerous:
                findings.append(Finding(
                    module=ScanModule.OWASP,
                    check_name="http_dangerous_methods_allowed",
                    severity=Severity.MEDIUM,
                    title=f"Dangerous HTTP methods in Allow header: {', '.join(dangerous)}",
                    description=(
                        "The OPTIONS response advertises potentially dangerous HTTP methods. "
                        "PUT and DELETE may allow unauthorized file creation/deletion; "
                        "TRACE enables Cross-Site Tracing attacks."
                    ),
                    url=target.base_url,
                    evidence=f"OPTIONS Allow: {allow_header}",
                    remediation=(
                        "Restrict the HTTP methods your server accepts to only those "
                        "required by your application (typically GET, POST, HEAD)."
                    ),
                    cwe_id="CWE-749",
                    cvss_score=5.3,
                ))
        except Exception:
            pass

        # --- PUT — try to upload to a non-existent path ---
        try:
            probe_url = target.base_url.rstrip("/") + _PROBE_PATH
            resp = await self.http_client.request(
                "PUT", probe_url, data=b"webscanner-probe"
            )
            urls_scanned += 1
            if resp.status in (200, 201, 204):
                findings.append(Finding(
                    module=ScanModule.OWASP,
                    check_name="http_put_enabled",
                    severity=Severity.HIGH,
                    title="HTTP PUT method accepted — arbitrary file upload possible",
                    description=(
                        f"The server accepted a PUT request to {probe_url} with HTTP {resp.status}. "
                        "This may allow unauthenticated file uploads or content replacement."
                    ),
                    url=probe_url,
                    evidence=f"PUT {probe_url} → HTTP {resp.status}",
                    remediation=(
                        "Disable PUT method unless explicitly required by your REST API. "
                        "Require authentication and authorisation for all write operations."
                    ),
                    cwe_id="CWE-650",
                    cvss_score=8.1,
                ))
        except Exception:
            pass

        # --- DELETE — attempt to delete the probe path ---
        try:
            probe_url = target.base_url.rstrip("/") + _PROBE_PATH
            resp = await self.http_client.request("DELETE", probe_url)
            urls_scanned += 1
            if resp.status in (200, 204):
                findings.append(Finding(
                    module=ScanModule.OWASP,
                    check_name="http_delete_enabled",
                    severity=Severity.HIGH,
                    title="HTTP DELETE method accepted — arbitrary file deletion possible",
                    description=(
                        f"The server accepted a DELETE request to {probe_url} with HTTP {resp.status}. "
                        "This may allow unauthenticated deletion of server-side resources."
                    ),
                    url=probe_url,
                    evidence=f"DELETE {probe_url} → HTTP {resp.status}",
                    remediation=(
                        "Disable DELETE method unless required by your REST API. "
                        "Require authentication and authorisation for all write operations."
                    ),
                    cwe_id="CWE-650",
                    cvss_score=8.1,
                ))
        except Exception:
            pass

        return ModuleResult(
            module=ScanModule.OWASP,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_scanned,
        )
