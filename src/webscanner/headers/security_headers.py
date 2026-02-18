"""Security header analysis scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

REQUIRED_HEADERS: tuple[tuple[str, str, Severity, str], ...] = (
    (
        "Content-Security-Policy",
        "Controls resources the browser is allowed to load",
        Severity.HIGH,
        "Add a Content-Security-Policy header to prevent XSS and data injection attacks.",
    ),
    (
        "Strict-Transport-Security",
        "Enforces HTTPS connections",
        Severity.HIGH,
        "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
    ),
    (
        "X-Frame-Options",
        "Prevents clickjacking via framing",
        Severity.MEDIUM,
        "Add X-Frame-Options: DENY or SAMEORIGIN header.",
    ),
    (
        "X-Content-Type-Options",
        "Prevents MIME type sniffing",
        Severity.MEDIUM,
        "Add X-Content-Type-Options: nosniff header.",
    ),
    (
        "Referrer-Policy",
        "Controls referrer information sent with requests",
        Severity.LOW,
        "Add Referrer-Policy: strict-origin-when-cross-origin header.",
    ),
    (
        "Permissions-Policy",
        "Controls browser feature permissions",
        Severity.LOW,
        "Add a Permissions-Policy header to restrict browser features.",
    ),
)

DANGEROUS_CSP_DIRECTIVES: tuple[tuple[str, str, Severity], ...] = (
    ("unsafe-inline", "Allows inline scripts, weakening XSS protection", Severity.HIGH),
    ("unsafe-eval", "Allows eval(), enabling code injection", Severity.HIGH),
    ("*", "Wildcard source allows loading from any origin", Severity.MEDIUM),
)


@dataclass(frozen=True)
class SecurityHeadersScanner:
    """Checks for presence and configuration of security headers."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "security_headers"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            headers = response.headers

            findings.extend(_check_missing_headers(headers, target.base_url))
            findings.extend(_check_csp_quality(headers, target.base_url))
            findings.extend(_check_deprecated_headers(headers, target.base_url))

            return ModuleResult(
                module=ScanModule.HEADERS,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=1,
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.HEADERS,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )


def _check_missing_headers(headers: dict[str, str], url: str) -> list[Finding]:
    findings: list[Finding] = []
    for header_name, description, severity, remediation in REQUIRED_HEADERS:
        if header_name.lower() not in {k.lower() for k in headers}:
            findings.append(
                Finding(
                    module=ScanModule.HEADERS,
                    check_name="missing_security_header",
                    severity=severity,
                    title=f"Missing {header_name} header",
                    description=f"{header_name}: {description}",
                    url=url,
                    evidence=f"Header '{header_name}' not found in response",
                    remediation=remediation,
                )
            )
    return findings


def _check_csp_quality(headers: dict[str, str], url: str) -> list[Finding]:
    findings: list[Finding] = []
    csp_value = None
    for key, value in headers.items():
        if key.lower() == "content-security-policy":
            csp_value = value
            break

    if csp_value is None:
        return findings

    for directive, description, severity in DANGEROUS_CSP_DIRECTIVES:
        if directive in csp_value:
            findings.append(
                Finding(
                    module=ScanModule.HEADERS,
                    check_name="weak_csp",
                    severity=severity,
                    title=f"CSP contains '{directive}'",
                    description=description,
                    url=url,
                    evidence=f"Content-Security-Policy: {csp_value[:200]}",
                    remediation=f"Remove '{directive}' from CSP and use nonces or hashes instead.",
                )
            )
    return findings


def _check_deprecated_headers(headers: dict[str, str], url: str) -> list[Finding]:
    findings: list[Finding] = []
    header_names_lower = {k.lower() for k in headers}
    if "x-xss-protection" in header_names_lower:
        findings.append(
            Finding(
                module=ScanModule.HEADERS,
                check_name="deprecated_header",
                severity=Severity.INFO,
                title="Deprecated X-XSS-Protection header present",
                description="X-XSS-Protection is deprecated. Use CSP instead.",
                url=url,
                evidence="X-XSS-Protection header found in response",
                remediation="Remove X-XSS-Protection and rely on Content-Security-Policy.",
            )
        )
    return findings
