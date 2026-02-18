"""SSL/TLS configuration analysis scanner."""

from __future__ import annotations

import ssl
import time
from dataclasses import dataclass
from datetime import datetime, timezone

from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

WEAK_PROTOCOLS: tuple[tuple[str, int, Severity], ...] = (
    ("TLSv1", ssl.PROTOCOL_TLS, Severity.CRITICAL),
    ("TLSv1.1", ssl.PROTOCOL_TLS, Severity.CRITICAL),
)

WEAK_CIPHERS: frozenset[str] = frozenset({
    "RC4", "DES", "3DES", "DES-CBC3", "EXPORT", "NULL", "MD5",
})


@dataclass(frozen=True)
class SSLTLSScanner:
    """Checks SSL/TLS configuration for security issues."""

    @property
    def module_name(self) -> str:
        return "ssl_tls"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        from urllib.parse import urlparse
        parsed = urlparse(target.base_url)

        if parsed.scheme != "https":
            findings.append(
                Finding(
                    module=ScanModule.HEADERS,
                    check_name="no_https",
                    severity=Severity.HIGH,
                    title="Site not using HTTPS",
                    description="The target URL uses HTTP instead of HTTPS.",
                    url=target.base_url,
                    evidence=f"Scheme: {parsed.scheme}",
                    remediation="Enable HTTPS with a valid TLS certificate.",
                )
            )
            return ModuleResult(
                module=ScanModule.HEADERS,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=1,
            )

        host = parsed.netloc.split(":")[0]
        port = int(parsed.netloc.split(":")[1]) if ":" in parsed.netloc else 443

        try:
            import asyncio
            ctx = ssl.create_default_context()
            _, writer = await asyncio.open_connection(host, port, ssl=ctx)
            ssl_object = writer.transport.get_extra_info("ssl_object")

            if ssl_object:
                findings.extend(_check_protocol_version(ssl_object, target.base_url))
                findings.extend(_check_certificate(ssl_object, target.base_url, host))

            writer.close()
            await writer.wait_closed()
        except ssl.SSLError as e:
            findings.append(
                Finding(
                    module=ScanModule.HEADERS,
                    check_name="ssl_error",
                    severity=Severity.CRITICAL,
                    title="SSL/TLS connection error",
                    description=f"Could not establish secure connection: {e}",
                    url=target.base_url,
                    evidence=str(e),
                    remediation="Fix the SSL/TLS configuration on the server.",
                )
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.HEADERS,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )

        return ModuleResult(
            module=ScanModule.HEADERS,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=1,
        )


def _check_protocol_version(ssl_object: ssl.SSLObject, url: str) -> list[Finding]:
    findings: list[Finding] = []
    version = ssl_object.version()
    if version and version in ("TLSv1", "TLSv1.1"):
        findings.append(
            Finding(
                module=ScanModule.HEADERS,
                check_name="weak_tls_version",
                severity=Severity.CRITICAL,
                title=f"Weak TLS version: {version}",
                description=f"Server supports {version} which has known vulnerabilities.",
                url=url,
                evidence=f"Negotiated protocol: {version}",
                remediation="Disable TLS 1.0 and 1.1. Require TLS 1.2 or higher.",
                cwe_id="CWE-326",
            )
        )
    return findings


def _check_certificate(ssl_object: ssl.SSLObject, url: str, hostname: str) -> list[Finding]:
    findings: list[Finding] = []
    cert = ssl_object.getpeercert()
    if not cert:
        return findings

    not_after = cert.get("notAfter")
    if not_after:
        from email.utils import parsedate_to_datetime
        try:
            expiry = parsedate_to_datetime(not_after)
            now = datetime.now(timezone.utc)
            days_until_expiry = (expiry - now).days
            if days_until_expiry < 0:
                findings.append(
                    Finding(
                        module=ScanModule.HEADERS,
                        check_name="expired_certificate",
                        severity=Severity.CRITICAL,
                        title="SSL certificate has expired",
                        description=f"Certificate expired {abs(days_until_expiry)} days ago.",
                        url=url,
                        evidence=f"notAfter: {not_after}",
                        remediation="Renew the SSL certificate immediately.",
                    )
                )
            elif days_until_expiry < 30:
                findings.append(
                    Finding(
                        module=ScanModule.HEADERS,
                        check_name="expiring_certificate",
                        severity=Severity.MEDIUM,
                        title="SSL certificate expiring soon",
                        description=f"Certificate expires in {days_until_expiry} days.",
                        url=url,
                        evidence=f"notAfter: {not_after}",
                        remediation="Renew the SSL certificate before expiry.",
                    )
                )
        except (ValueError, TypeError):
            pass

    return findings
