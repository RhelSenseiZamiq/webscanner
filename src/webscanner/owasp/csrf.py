"""CSRF (Cross-Site Request Forgery) detection scanner."""

from __future__ import annotations

import time
from dataclasses import dataclass
from urllib.parse import urljoin

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

CSRF_TOKEN_NAMES: frozenset[str] = frozenset({
    "csrf_token", "csrftoken", "_csrf", "csrf",
    "csrfmiddlewaretoken", "_token", "authenticity_token",
    "__requestverificationtoken", "antiforgery",
})


@dataclass(frozen=True)
class CSRFScanner:
    """Detects missing CSRF protection on state-changing forms."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "csrf"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        try:
            response = await self.http_client.get(target.base_url)
            body = await response.text()
            soup = BeautifulSoup(body, "lxml")

            for form in soup.find_all("form"):
                method = (form.get("method", "get")).upper()
                if method not in ("POST", "PUT", "DELETE", "PATCH"):
                    continue

                action = form.get("action", "")
                form_url = urljoin(target.base_url, action) if action else target.base_url

                has_csrf_token = _form_has_csrf_token(form)
                if not has_csrf_token:
                    findings.append(
                        Finding(
                            module=ScanModule.OWASP,
                            check_name="csrf_missing_token",
                            severity=Severity.HIGH,
                            title=f"Missing CSRF token on {method} form",
                            description=f"Form at {form_url} submits via {method} without CSRF protection.",
                            url=form_url,
                            evidence=f"Form action: {action or '(self)'}, method: {method}",
                            remediation="Add a CSRF token to all state-changing forms.",
                            cwe_id="CWE-352",
                        )
                    )

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


def _form_has_csrf_token(form: BeautifulSoup) -> bool:
    """Check if a form contains a hidden input with a CSRF token name."""
    for inp in form.find_all("input", attrs={"type": "hidden"}):
        name = (inp.get("name") or "").lower()
        if name in CSRF_TOKEN_NAMES:
            return True
    return False
