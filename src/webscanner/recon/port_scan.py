"""TCP port scanning via asyncio."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass
from urllib.parse import urlparse

from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

DEFAULT_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445,
    993, 995, 1433, 1521, 3306, 3389, 5432, 5900,
    6379, 8080, 8443, 8888, 9090, 27017,
)

DANGEROUS_SERVICES: dict[int, tuple[str, Severity]] = {
    21: ("FTP", Severity.MEDIUM),
    23: ("Telnet", Severity.HIGH),
    25: ("SMTP", Severity.LOW),
    445: ("SMB", Severity.HIGH),
    1433: ("MSSQL", Severity.MEDIUM),
    3306: ("MySQL", Severity.MEDIUM),
    3389: ("RDP", Severity.HIGH),
    5432: ("PostgreSQL", Severity.MEDIUM),
    5900: ("VNC", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
}


@dataclass(frozen=True)
class PortScanner:
    """Async TCP port scanner."""

    rate_limiter: AsyncTokenBucketRateLimiter
    ports: tuple[int, ...] = DEFAULT_PORTS
    concurrency: int = 20
    timeout_seconds: float = 3.0

    @property
    def module_name(self) -> str:
        return "port_scan"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []

        parsed = urlparse(target.base_url)
        host = parsed.netloc.split(":")[0]
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_port(port: int) -> Finding | None:
            async with semaphore:
                await self.rate_limiter.acquire()
                try:
                    _, writer = await asyncio.wait_for(
                        asyncio.open_connection(host, port),
                        timeout=self.timeout_seconds,
                    )
                    writer.close()
                    await writer.wait_closed()
                    return _create_port_finding(host, port, target.base_url)
                except (OSError, asyncio.TimeoutError):
                    return None

        tasks = [check_port(port) for port in self.ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        return ModuleResult(
            module=ScanModule.RECON,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=len(self.ports),
        )


def _create_port_finding(host: str, port: int, base_url: str) -> Finding:
    service_info = DANGEROUS_SERVICES.get(port)
    if service_info:
        service_name, severity = service_info
        title = f"Open port {port} ({service_name}) on {host}"
        remediation = f"Verify {service_name} on port {port} is intentionally exposed and properly secured."
    else:
        severity = Severity.INFO
        title = f"Open port {port} on {host}"
        service_name = "unknown"
        remediation = "Review if this port should be publicly accessible."

    return Finding(
        module=ScanModule.RECON,
        check_name="open_port",
        severity=severity,
        title=title,
        description=f"TCP port {port} ({service_name}) is open on {host}.",
        url=base_url,
        evidence=f"TCP connection to {host}:{port} succeeded",
        remediation=remediation,
    )
