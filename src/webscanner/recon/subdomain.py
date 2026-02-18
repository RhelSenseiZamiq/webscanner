"""Subdomain enumeration via DNS and certificate transparency."""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import aiohttp

from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter
from webscanner.core.scope import is_url_in_scope
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

DEFAULT_SUBDOMAINS: tuple[str, ...] = (
    "www", "mail", "ftp", "admin", "api", "dev", "staging",
    "test", "beta", "cdn", "app", "portal", "m", "mobile",
    "shop", "blog", "docs", "status", "monitor", "grafana",
)


@dataclass(frozen=True)
class SubdomainScanner:
    """Discovers subdomains via DNS resolution and crt.sh CT logs."""

    rate_limiter: AsyncTokenBucketRateLimiter
    wordlist: tuple[str, ...] = DEFAULT_SUBDOMAINS
    concurrency: int = 10

    @property
    def module_name(self) -> str:
        return "subdomain"

    @property
    def is_active_probe(self) -> bool:
        return False

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        parsed = urlparse(target.base_url)
        base_domain = parsed.netloc.split(":")[0]

        discovered: set[str] = set()

        dns_results = await self._dns_brute_force(base_domain, target)
        discovered.update(dns_results)

        ct_results = await self._query_ct_logs(base_domain, target)
        discovered.update(ct_results)

        for subdomain in sorted(discovered):
            url = f"https://{subdomain}"
            if is_url_in_scope(url, target):
                findings.append(
                    Finding(
                        module=ScanModule.RECON,
                        check_name="subdomain_discovered",
                        severity=Severity.INFO,
                        title=f"Subdomain discovered: {subdomain}",
                        description=f"Active subdomain found: {subdomain}",
                        url=url,
                        evidence=f"Resolved via DNS/CT: {subdomain}",
                        remediation="Review if this subdomain should be publicly accessible.",
                    )
                )

        return ModuleResult(
            module=ScanModule.RECON,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=len(self.wordlist),
        )

    async def _dns_brute_force(
        self, base_domain: str, target: ScanTarget
    ) -> set[str]:
        discovered: set[str] = set()
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_subdomain(prefix: str) -> str | None:
            fqdn = f"{prefix}.{base_domain}"
            async with semaphore:
                await self.rate_limiter.acquire()
                try:
                    loop = asyncio.get_event_loop()
                    await loop.getaddrinfo(fqdn, None)
                    return fqdn
                except (OSError, asyncio.TimeoutError):
                    return None

        tasks = [check_subdomain(prefix) for prefix in self.wordlist]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, str):
                discovered.add(result)

        return discovered

    async def _query_ct_logs(
        self, base_domain: str, target: ScanTarget
    ) -> set[str]:
        discovered: set[str] = set()
        await self.rate_limiter.acquire()

        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://crt.sh/?q=%.{base_domain}&output=json"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=15)) as resp:
                    if resp.status == 200:
                        data = await resp.json(content_type=None)
                        for entry in data:
                            name = entry.get("name_value", "")
                            for line in name.split("\n"):
                                clean = line.strip().lstrip("*.")
                                if clean and clean.endswith(base_domain):
                                    check_url = f"https://{clean}"
                                    if is_url_in_scope(check_url, target):
                                        discovered.add(clean)
        except Exception:
            pass

        return discovered
