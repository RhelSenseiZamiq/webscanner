"""Technology fingerprinting via HTTP headers and HTML content."""

from __future__ import annotations

import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

HEADER_SIGNATURES: tuple[tuple[str, str, str], ...] = (
    ("Server", "Apache", "Apache HTTP Server"),
    ("Server", "nginx", "Nginx"),
    ("Server", "Microsoft-IIS", "Microsoft IIS"),
    ("Server", "cloudflare", "Cloudflare CDN"),
    ("X-Powered-By", "PHP", "PHP"),
    ("X-Powered-By", "Express", "Express.js"),
    ("X-Powered-By", "ASP.NET", "ASP.NET"),
    ("X-Powered-By", "Django", "Django"),
    ("X-Powered-By", "Next.js", "Next.js"),
    ("X-Generator", "WordPress", "WordPress"),
    ("X-Generator", "Drupal", "Drupal"),
    ("X-Drupal-Cache", "", "Drupal"),
    ("X-Django-Debug", "", "Django (Debug Mode)"),
)

HTML_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("wp-content", "WordPress"),
    ("wp-includes", "WordPress"),
    ("/sites/default/files", "Drupal"),
    ("laravel_session", "Laravel"),
    ("csrfmiddlewaretoken", "Django"),
    ("__next", "Next.js"),
    ("_nuxt", "Nuxt.js"),
    ("react-root", "React"),
    ("ng-version", "Angular"),
    ("data-reactroot", "React"),
)


@dataclass(frozen=True)
class FingerprintScanner:
    """Identifies technologies used by the target via headers and HTML."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "fingerprint"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        detected: set[str] = set()

        try:
            response = await self.http_client.get(target.base_url)
            headers = response.headers
            body = await response.text()

            for header_name, pattern, tech_name in HEADER_SIGNATURES:
                value = headers.get(header_name, "")
                if pattern and pattern.lower() in value.lower():
                    detected.add(tech_name)
                elif not pattern and header_name.lower() in {k.lower() for k in headers}:
                    detected.add(tech_name)

            for pattern, tech_name in HTML_SIGNATURES:
                if pattern in body:
                    detected.add(tech_name)

            _check_server_info_leak(headers, target.base_url, findings)

            for tech in sorted(detected):
                findings.append(
                    Finding(
                        module=ScanModule.RECON,
                        check_name="technology_detected",
                        severity=Severity.INFO,
                        title=f"Technology detected: {tech}",
                        description=f"The target appears to use {tech}.",
                        url=target.base_url,
                        evidence=f"Fingerprint match for {tech}",
                        remediation="Consider if technology version disclosure aids attackers.",
                    )
                )

            return ModuleResult(
                module=ScanModule.RECON,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=1,
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.RECON,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=0,
                error=str(e),
            )


def _check_server_info_leak(
    headers: dict[str, str], url: str, findings: list[Finding]
) -> None:
    server = headers.get("Server", "")
    if server and any(c.isdigit() for c in server):
        findings.append(
            Finding(
                module=ScanModule.RECON,
                check_name="server_version_disclosure",
                severity=Severity.LOW,
                title="Server version disclosed",
                description=f"Server header reveals version: {server}",
                url=url,
                evidence=f"Server: {server}",
                remediation="Remove or obscure the Server header version information.",
            )
        )

    x_powered = headers.get("X-Powered-By", "")
    if x_powered:
        findings.append(
            Finding(
                module=ScanModule.RECON,
                check_name="technology_disclosure",
                severity=Severity.LOW,
                title="X-Powered-By header exposes technology",
                description=f"X-Powered-By reveals: {x_powered}",
                url=url,
                evidence=f"X-Powered-By: {x_powered}",
                remediation="Remove the X-Powered-By header from responses.",
            )
        )
