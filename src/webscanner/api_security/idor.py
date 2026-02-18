"""IDOR (Insecure Direct Object Reference) detection scanner."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

IDOR_PATHS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("/api/v1/users/{id}", ("1", "2", "100", "999")),
    ("/api/v1/orders/{id}", ("1", "2", "100")),
    ("/api/v1/profiles/{id}", ("1", "2", "100")),
    ("/api/users/{id}", ("1", "2", "100")),
    ("/users/{id}", ("1", "2")),
)


@dataclass(frozen=True)
class IDORScanner:
    """Detects insecure direct object reference vulnerabilities."""

    http_client: ScopedHttpClient
    concurrency: int = 3

    @property
    def module_name(self) -> str:
        return "idor"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)
        urls_tested = 0

        for path_template, ids in IDOR_PATHS:
            accessible_ids: list[str] = []
            for id_val in ids:
                path = path_template.replace("{id}", id_val)
                url = f"{target.base_url.rstrip('/')}{path}"
                urls_tested += 1

                async with semaphore:
                    try:
                        response = await self.http_client.get(url)
                        if response.status == 200:
                            body = await response.text()
                            if len(body) > 20:
                                accessible_ids.append(id_val)
                    except Exception:
                        continue

            if len(accessible_ids) >= 2:
                findings.append(
                    Finding(
                        module=ScanModule.API_SECURITY,
                        check_name="idor",
                        severity=Severity.HIGH,
                        title=f"Potential IDOR: {path_template}",
                        description=f"Multiple resource IDs accessible without proper authorization check.",
                        url=f"{target.base_url.rstrip('/')}{path_template}",
                        evidence=f"Accessible IDs: {', '.join(accessible_ids)}",
                        remediation="Implement object-level authorization checks for all resource access.",
                        cwe_id="CWE-639",
                        cvss_score=7.5,
                    )
                )

        return ModuleResult(
            module=ScanModule.API_SECURITY,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_tested,
        )
