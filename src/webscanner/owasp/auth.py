"""Broken authentication detection scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

ADMIN_PATHS: tuple[str, ...] = (
    "/admin", "/admin/login", "/administrator",
    "/wp-admin", "/wp-login.php",
    "/phpmyadmin", "/cpanel",
    "/user/login", "/accounts/login",
)

DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "123456"),
    ("root", "root"),
    ("test", "test"),
)


@dataclass(frozen=True)
class AuthScanner:
    """Detects broken authentication patterns."""

    http_client: ScopedHttpClient
    concurrency: int = 3

    @property
    def module_name(self) -> str:
        return "auth"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        for path in ADMIN_PATHS:
            url = f"{target.base_url.rstrip('/')}{path}"
            async with semaphore:
                finding = await self._check_admin_panel(url)
                if finding:
                    findings.append(finding)

        return ModuleResult(
            module=ScanModule.OWASP,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=len(ADMIN_PATHS),
        )

    async def _check_admin_panel(self, url: str) -> Finding | None:
        try:
            response = await self.http_client.get(url)
            if response.status == 200:
                body = await response.text()
                has_login_form = any(
                    keyword in body.lower()
                    for keyword in ("type=\"password\"", "type='password'", "input[type=password]")
                )
                if has_login_form:
                    return Finding(
                        module=ScanModule.OWASP,
                        check_name="admin_panel_exposed",
                        severity=Severity.MEDIUM,
                        title=f"Admin login panel exposed: {url}",
                        description="Publicly accessible admin login page found.",
                        url=url,
                        evidence=f"HTTP 200 with login form at {url}",
                        remediation="Restrict admin panels to internal networks or add IP allowlisting.",
                        cwe_id="CWE-287",
                    )
        except Exception:
            pass
        return None
