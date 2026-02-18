"""Security misconfiguration detection scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

DEBUG_INDICATORS: tuple[tuple[str, str], ...] = (
    ("Traceback (most recent call last)", "Python/Django debug page"),
    ("DJANGO_SETTINGS_MODULE", "Django settings exposed"),
    ("Laravel", "Laravel debug mode"),
    ("Whoops!", "Laravel Whoops error handler"),
    ("<b>Fatal error</b>", "PHP fatal error with details"),
    ("Stack Trace:", "Application stack trace exposed"),
    ("X-Debug-Token", "Symfony debug toolbar"),
)

CORS_CHECKS: tuple[str, ...] = (
    "Access-Control-Allow-Origin",
)


@dataclass(frozen=True)
class MisconfigurationScanner:
    """Detects common security misconfigurations."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "misconfiguration"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            body = await response.text()
            headers = response.headers

            findings.extend(_check_debug_mode(body, target.base_url))
            findings.extend(_check_cors(headers, target.base_url))
            findings.extend(_check_directory_listing(body, target.base_url))
            findings.extend(_check_error_pages(target.base_url, self.http_client))

            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=1,
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )


def _check_debug_mode(body: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for indicator, description in DEBUG_INDICATORS:
        if indicator in body:
            findings.append(
                Finding(
                    module=ScanModule.OWASP,
                    check_name="debug_mode_enabled",
                    severity=Severity.HIGH,
                    title=f"Debug mode detected: {description}",
                    description=f"Application appears to be running in debug mode.",
                    url=url,
                    evidence=f"Found indicator: {indicator[:100]}",
                    remediation="Disable debug mode in production. Set DEBUG=False.",
                    cwe_id="CWE-215",
                )
            )
            break
    return findings


def _check_cors(headers: dict[str, str], url: str) -> list[Finding]:
    findings: list[Finding] = []
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        findings.append(
            Finding(
                module=ScanModule.OWASP,
                check_name="cors_wildcard",
                severity=Severity.MEDIUM,
                title="CORS wildcard (*) allows any origin",
                description="Access-Control-Allow-Origin is set to *, allowing any website to make requests.",
                url=url,
                evidence=f"Access-Control-Allow-Origin: {acao}",
                remediation="Restrict CORS to specific trusted origins.",
                cwe_id="CWE-942",
            )
        )

    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acac.lower() == "true" and acao == "*":
        findings.append(
            Finding(
                module=ScanModule.OWASP,
                check_name="cors_credentials_wildcard",
                severity=Severity.HIGH,
                title="CORS allows credentials with wildcard origin",
                description="Credentials allowed with wildcard origin — severe misconfiguration.",
                url=url,
                evidence=f"ACAO: {acao}, ACAC: {acac}",
                remediation="Never use Access-Control-Allow-Credentials: true with wildcard origin.",
                cwe_id="CWE-942",
            )
        )

    return findings


def _check_directory_listing(body: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    listing_indicators = ("Index of /", "Directory listing for", "[To Parent Directory]")
    for indicator in listing_indicators:
        if indicator in body:
            findings.append(
                Finding(
                    module=ScanModule.OWASP,
                    check_name="directory_listing",
                    severity=Severity.MEDIUM,
                    title="Directory listing enabled",
                    description="Server exposes directory contents to browsers.",
                    url=url,
                    evidence=f"Found indicator: {indicator}",
                    remediation="Disable directory listing in the web server configuration.",
                    cwe_id="CWE-548",
                )
            )
            break
    return findings


def _check_error_pages(url: str, client: ScopedHttpClient) -> list[Finding]:
    return []
