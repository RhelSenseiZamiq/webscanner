"""Directory and path discovery via wordlist scanning."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

DEFAULT_PATHS: tuple[str, ...] = (
    "/admin", "/login", "/dashboard", "/api", "/api/v1",
    "/wp-admin", "/wp-login.php", "/.env", "/.git/config",
    "/robots.txt", "/sitemap.xml", "/backup", "/config",
    "/phpmyadmin", "/debug", "/test", "/staging",
    "/swagger.json", "/openapi.json", "/.well-known/security.txt",
    "/server-status", "/server-info", "/.htaccess",
    "/graphql", "/graphiql", "/console", "/actuator",
    "/actuator/health", "/metrics", "/trace",
)

SENSITIVE_PATHS: frozenset[str] = frozenset({
    "/.env", "/.git/config", "/.htaccess", "/backup",
    "/debug", "/server-status", "/server-info",
    "/actuator", "/console", "/trace",
})

INTERESTING_STATUS_CODES: frozenset[int] = frozenset({200, 301, 302, 307, 308, 401, 403})


@dataclass(frozen=True)
class DirectoryScanner:
    """Discovers paths and directories via wordlist-driven requests."""

    http_client: ScopedHttpClient
    paths: tuple[str, ...] = DEFAULT_PATHS
    concurrency: int = 10

    @property
    def module_name(self) -> str:
        return "directory"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_path(path: str) -> Finding | None:
            url = f"{target.base_url.rstrip('/')}{path}"
            async with semaphore:
                try:
                    response = await self.http_client.get(url)
                    if response.status in INTERESTING_STATUS_CODES:
                        return _create_path_finding(url, path, response.status)
                    return None
                except Exception:
                    return None

        tasks = [check_path(path) for path in self.paths]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        return ModuleResult(
            module=ScanModule.RECON,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=len(self.paths),
        )


def _create_path_finding(url: str, path: str, status: int) -> Finding:
    is_sensitive = path in SENSITIVE_PATHS

    if is_sensitive and status == 200:
        severity = Severity.HIGH
        title = f"Sensitive path exposed: {path} (HTTP {status})"
        remediation = f"Restrict access to {path} or remove it from production."
    elif status in (401, 403):
        severity = Severity.INFO
        title = f"Protected path found: {path} (HTTP {status})"
        remediation = "Verify access controls are properly configured."
    else:
        severity = Severity.LOW if is_sensitive else Severity.INFO
        title = f"Path discovered: {path} (HTTP {status})"
        remediation = "Review if this path should be publicly accessible."

    return Finding(
        module=ScanModule.RECON,
        check_name="directory_found",
        severity=severity,
        title=title,
        description=f"Discovered accessible path: {path} with status {status}.",
        url=url,
        evidence=f"HTTP {status} response for {path}",
        remediation=remediation,
    )
