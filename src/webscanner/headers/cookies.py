"""Cookie security analysis scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

SESSION_COOKIE_NAMES: frozenset[str] = frozenset({
    "sessionid", "session", "sid", "sess", "phpsessid",
    "jsessionid", "asp.net_sessionid", "connect.sid",
    "csrf_token", "csrftoken", "_csrf",
})


@dataclass(frozen=True)
class CookieScanner:
    """Analyzes Set-Cookie headers for security flags."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "cookies"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            set_cookie_headers = response.headers.getall("Set-Cookie", [])

            for cookie_header in set_cookie_headers:
                findings.extend(_analyze_cookie(cookie_header, target.base_url))

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


def _analyze_cookie(cookie_header: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    parts = cookie_header.split(";")
    if not parts:
        return findings

    name_value = parts[0].strip()
    cookie_name = name_value.split("=")[0].strip().lower()

    is_session = cookie_name in SESSION_COOKIE_NAMES
    severity = Severity.MEDIUM if is_session else Severity.LOW

    flags_lower = {p.strip().lower() for p in parts[1:]}
    flag_names = {f.split("=")[0].strip() for f in flags_lower}

    if "secure" not in flag_names:
        findings.append(
            Finding(
                module=ScanModule.HEADERS,
                check_name="cookie_missing_secure",
                severity=severity,
                title=f"Cookie '{cookie_name}' missing Secure flag",
                description="Cookie can be sent over unencrypted HTTP connections.",
                url=url,
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                remediation="Add the Secure flag to this cookie.",
            )
        )

    if "httponly" not in flag_names:
        findings.append(
            Finding(
                module=ScanModule.HEADERS,
                check_name="cookie_missing_httponly",
                severity=severity,
                title=f"Cookie '{cookie_name}' missing HttpOnly flag",
                description="Cookie is accessible via JavaScript, increasing XSS risk.",
                url=url,
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                remediation="Add the HttpOnly flag to this cookie.",
            )
        )

    has_samesite = any("samesite" in f for f in flag_names)
    if not has_samesite:
        findings.append(
            Finding(
                module=ScanModule.HEADERS,
                check_name="cookie_missing_samesite",
                severity=Severity.LOW,
                title=f"Cookie '{cookie_name}' missing SameSite attribute",
                description="Cookie lacks SameSite attribute, may be vulnerable to CSRF.",
                url=url,
                evidence=f"Set-Cookie: {cookie_header[:200]}",
                remediation="Add SameSite=Lax or SameSite=Strict attribute.",
            )
        )

    return findings
