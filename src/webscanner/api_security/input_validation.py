"""API input validation testing scanner."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

MALFORMED_PAYLOADS: tuple[tuple[str, str, str], ...] = (
    ('{"id": "string_instead_of_int"}', "type_confusion", "Type confusion: string where int expected"),
    ('{"id": null}', "null_injection", "Null value injection"),
    ('{"id": -1}', "negative_id", "Negative ID value"),
    ('{"id": 99999999999}', "overflow", "Integer overflow attempt"),
    ('{"a":' + '"x"' * 1000 + '}', "large_payload", "Oversized JSON payload"),
    ('not-json-at-all', "invalid_json", "Completely invalid JSON"),
)

STACK_TRACE_INDICATORS: tuple[str, ...] = (
    "Traceback (most recent call last)",
    "at java.", "at com.", "at org.",
    "NullPointerException", "ClassNotFoundException",
    "SyntaxError:", "TypeError:", "ValueError:",
    "System.NullReferenceException",
    "500 Internal Server Error",
)


@dataclass(frozen=True)
class InputValidationScanner:
    """Tests API endpoints for input validation issues."""

    http_client: ScopedHttpClient
    concurrency: int = 3

    @property
    def module_name(self) -> str:
        return "input_validation"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)
        urls_tested = 0

        api_paths = ("/api/v1/users", "/api/v1/search", "/api/users", "/api/search")

        for path in api_paths:
            url = f"{target.base_url.rstrip('/')}{path}"
            for payload, test_name, description in MALFORMED_PAYLOADS:
                urls_tested += 1
                finding = await self._test_input(
                    url, payload, test_name, description, semaphore
                )
                if finding:
                    findings.append(finding)

        return ModuleResult(
            module=ScanModule.API_SECURITY,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=urls_tested,
        )

    async def _test_input(
        self, url: str, payload: str, test_name: str,
        description: str, semaphore: asyncio.Semaphore,
    ) -> Finding | None:
        async with semaphore:
            try:
                response = await self.http_client.post(
                    url,
                    data=payload,
                    headers={"Content-Type": "application/json"},
                )
                body = await response.text()

                if response.status >= 500:
                    for indicator in STACK_TRACE_INDICATORS:
                        if indicator in body:
                            return Finding(
                                module=ScanModule.API_SECURITY,
                                check_name=f"input_validation_{test_name}",
                                severity=Severity.HIGH,
                                title=f"Stack trace leaked: {description}",
                                description=f"Server returned 500 with stack trace for {description}.",
                                url=url,
                                evidence=f"HTTP {response.status}, indicator: {indicator}",
                                remediation="Implement proper input validation and generic error responses.",
                                cwe_id="CWE-209",
                            )

                    return Finding(
                        module=ScanModule.API_SECURITY,
                        check_name=f"input_validation_{test_name}",
                        severity=Severity.MEDIUM,
                        title=f"Server error on malformed input: {description}",
                        description=f"Server returned HTTP {response.status} for {description}.",
                        url=url,
                        evidence=f"HTTP {response.status}, payload: {payload[:100]}",
                        remediation="Validate all API inputs before processing. Return 400 for invalid input.",
                        cwe_id="CWE-20",
                    )
            except Exception:
                pass

        return None
