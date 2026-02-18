"""Sensitive data exposure detection scanner."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

SENSITIVE_PATTERNS: tuple[tuple[str, re.Pattern[str], Severity, str], ...] = (
    (
        "email_exposure",
        re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"),
        Severity.LOW,
        "Email addresses found in page source.",
    ),
    (
        "api_key_exposure",
        re.compile(r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?[a-zA-Z0-9]{20,}"),
        Severity.CRITICAL,
        "API key or secret found in page source.",
    ),
    (
        "aws_key_exposure",
        re.compile(r"AKIA[0-9A-Z]{16}"),
        Severity.CRITICAL,
        "AWS access key found in page source.",
    ),
    (
        "private_key_exposure",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
        Severity.CRITICAL,
        "Private key found in page source.",
    ),
    (
        "internal_ip_exposure",
        re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b"),
        Severity.LOW,
        "Internal IP address found in page source.",
    ),
    (
        "sql_connection_string",
        re.compile(r"(?:jdbc:|Server=|Data Source=|mongodb://|postgres://|mysql://)[^\s'\"]+", re.IGNORECASE),
        Severity.HIGH,
        "Database connection string found in page source.",
    ),
)

SENSITIVE_PATHS: tuple[tuple[str, Severity], ...] = (
    ("/.env", Severity.CRITICAL),
    ("/.git/config", Severity.HIGH),
    ("/wp-config.php.bak", Severity.CRITICAL),
    ("/config.php.bak", Severity.CRITICAL),
    ("/database.yml", Severity.HIGH),
    ("/.aws/credentials", Severity.CRITICAL),
)


@dataclass(frozen=True)
class SensitiveDataScanner:
    """Detects sensitive data exposure in responses."""

    http_client: ScopedHttpClient

    @property
    def module_name(self) -> str:
        return "sensitive_data"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        urls_scanned = 0

        try:
            response = await self.http_client.get(target.base_url)
            body = await response.text()
            urls_scanned += 1

            findings.extend(_scan_body_for_secrets(body, target.base_url))

            for path, severity in SENSITIVE_PATHS:
                url = f"{target.base_url.rstrip('/')}{path}"
                try:
                    resp = await self.http_client.get(url)
                    urls_scanned += 1
                    if resp.status == 200:
                        resp_body = await resp.text()
                        if len(resp_body) > 0:
                            findings.append(
                                Finding(
                                    module=ScanModule.OWASP,
                                    check_name="sensitive_file_exposed",
                                    severity=severity,
                                    title=f"Sensitive file accessible: {path}",
                                    description=f"File {path} is publicly accessible and may contain secrets.",
                                    url=url,
                                    evidence=f"HTTP 200, body length: {len(resp_body)}",
                                    remediation=f"Remove or restrict access to {path} in production.",
                                    cwe_id="CWE-200",
                                )
                            )
                except Exception:
                    continue

            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=urls_scanned,
            )
        except Exception as e:
            return ModuleResult(
                module=ScanModule.OWASP,
                findings=tuple(findings),
                duration_seconds=time.monotonic() - start,
                urls_scanned=urls_scanned,
                error=str(e),
            )


def _scan_body_for_secrets(body: str, url: str) -> list[Finding]:
    findings: list[Finding] = []
    for check_name, pattern, severity, description in SENSITIVE_PATTERNS:
        matches = pattern.findall(body)
        if matches:
            sample = matches[0][:100] if matches else ""
            findings.append(
                Finding(
                    module=ScanModule.OWASP,
                    check_name=check_name,
                    severity=severity,
                    title=f"Sensitive data found: {check_name.replace('_', ' ')}",
                    description=description,
                    url=url,
                    evidence=f"Match: {sample}",
                    remediation="Remove sensitive data from public-facing responses.",
                    cwe_id="CWE-200",
                )
            )
    return findings
