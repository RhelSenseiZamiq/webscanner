"""Scan engine that orchestrates all scan modules."""

from __future__ import annotations

import asyncio
import logging
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone

from webscanner.core.http_client import HttpClientConfig, ScopedHttpClient
from webscanner.core.rate_limiter import AsyncTokenBucketRateLimiter, RateLimiterConfig
from webscanner.core.scope import ScopeConfig, validate_scope
from webscanner.core.types import ModuleResult, ScanModule, ScanResult, ScanTarget

from webscanner.api_security.auth_bypass import AuthBypassScanner
from webscanner.api_security.endpoint_discovery import EndpointDiscoveryScanner
from webscanner.api_security.idor import IDORScanner
from webscanner.api_security.input_validation import InputValidationScanner
from webscanner.api_security.rate_limit_check import RateLimitScanner
from webscanner.headers.cookies import CookieScanner
from webscanner.headers.security_headers import SecurityHeadersScanner
from webscanner.headers.ssl_tls import SSLTLSScanner
from webscanner.owasp.auth import AuthScanner
from webscanner.owasp.command_injection import CommandInjectionScanner
from webscanner.owasp.csrf import CSRFScanner
from webscanner.owasp.http_methods import HttpMethodScanner
from webscanner.owasp.misconfiguration import MisconfigurationScanner
from webscanner.owasp.open_redirect import OpenRedirectScanner
from webscanner.owasp.path_traversal import PathTraversalScanner
from webscanner.owasp.sensitive_data import SensitiveDataScanner
from webscanner.owasp.sqli import SQLInjectionScanner
from webscanner.owasp.ssrf import SSRFScanner
from webscanner.owasp.ssti import SSTIScanner
from webscanner.owasp.xss import XSSScanner
from webscanner.recon.directory import DirectoryScanner
from webscanner.recon.fingerprint import FingerprintScanner
from webscanner.recon.port_scan import PortScanner
from webscanner.recon.subdomain import SubdomainScanner
from webscanner.bruteforce.http_auth import HttpAuthBruteForce
from webscanner.bruteforce.form_login import FormLoginBruteForce

logger = logging.getLogger("webscanner.engine")


@dataclass(frozen=True)
class ScanConfig:
    """Immutable scan configuration."""

    target_url: str
    scope_config: ScopeConfig
    rate_limit: float = 5.0
    modules: frozenset[str] = field(
        default_factory=lambda: frozenset({"recon", "headers", "owasp", "api"})
    )
    passive_only: bool = False
    timeout_seconds: int = 10
    program_name: str = ""
    contact_email: str = ""
    bruteforce_wordlist: str = ""
    bruteforce_usernames: str = ""
    bruteforce_max_attempts: int = 300


async def run_scan(
    config: ScanConfig,
    on_progress: Callable[[int, str], None] | None = None,
) -> ScanResult:
    """Execute a full vulnerability scan with the given configuration."""

    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    target = validate_scope(config.target_url, config.scope_config)
    scan_id = str(uuid.uuid4())
    started_at = datetime.now(timezone.utc)

    logger.info("Starting scan %s against %s", scan_id, target.base_url)
    emit(0, f"Starting scan against {target.base_url}…")

    rate_limiter = AsyncTokenBucketRateLimiter(
        RateLimiterConfig(
            requests_per_second=config.rate_limit,
            burst_size=max(10, int(config.rate_limit * 2)),
        )
    )

    http_config = HttpClientConfig(
        timeout_seconds=config.timeout_seconds,
        program_name=config.program_name,
        contact_email=config.contact_email,
    )

    async with ScopedHttpClient(
        config=http_config,
        rate_limiter=rate_limiter,
        target=target,
    ) as http_client:
        module_results: list[ModuleResult] = []

        if "recon" in config.modules:
            logger.info("Phase 1: Reconnaissance")
            emit(5, "Recon: enumerating subdomains…")
            recon_results = await _run_recon(target, rate_limiter, http_client, config, emit)
            module_results.extend(recon_results)
            emit(30, "Recon complete — launching parallel analysis modules")

        parallel_tasks: list[asyncio.Task[list[ModuleResult]]] = []

        if "headers" in config.modules:
            emit(35, "Starting: Security Headers / SSL / Cookies analysis")
            parallel_tasks.append(
                asyncio.create_task(_run_headers(target, http_client))
            )

        if "owasp" in config.modules:
            emit(40, "Starting: OWASP checks (SQLi, XSS, CSRF, SSRF, path traversal, command injection, SSTI, HTTP methods…)")
            parallel_tasks.append(
                asyncio.create_task(_run_owasp(target, http_client, config))
            )

        if "api" in config.modules:
            emit(45, "Starting: API security checks (endpoints, auth bypass, IDOR, rate limits…)")
            parallel_tasks.append(
                asyncio.create_task(_run_api_security(target, http_client, config))
            )

        if "bruteforce" in config.modules and not config.passive_only:
            emit(50, "Starting: Brute force (HTTP auth + login form detection…)")
            parallel_tasks.append(
                asyncio.create_task(_run_bruteforce(target, http_client, config))
            )

        if parallel_tasks:
            logger.info("Phase 2: Running %d modules in parallel", len(parallel_tasks))
            emit(55, f"Running {len(parallel_tasks)} module(s) in parallel…")
            results = await asyncio.gather(*parallel_tasks, return_exceptions=True)
            for result in results:
                if isinstance(result, list):
                    module_results.extend(result)
                elif isinstance(result, Exception):
                    logger.error("Module failed: %s", result)

    finished_at = datetime.now(timezone.utc)
    logger.info("Scan %s completed", scan_id)

    all_findings_count = sum(len(mr.findings) for mr in module_results)
    emit(100, f"Scan complete — {all_findings_count} finding(s) found")

    return ScanResult(
        target=target,
        scan_id=scan_id,
        started_at=started_at,
        finished_at=finished_at,
        module_results=tuple(module_results),
        scanner_version="0.1.0",
    )


async def _run_recon(
    target: ScanTarget,
    rate_limiter: AsyncTokenBucketRateLimiter,
    http_client: ScopedHttpClient,
    config: ScanConfig,
    emit: Callable[[int, str], None] = lambda _p, _m: None,
) -> list[ModuleResult]:
    results: list[ModuleResult] = []

    emit(5, "Recon: subdomain enumeration (DNS + crt.sh)…")
    subdomain = SubdomainScanner(rate_limiter=rate_limiter)
    results.append(await subdomain.scan(target))

    if not config.passive_only:
        emit(15, "Recon: port scanning…")
        port_scanner = PortScanner(rate_limiter=rate_limiter)
        results.append(await port_scanner.scan(target))

    emit(20, "Recon: directory discovery…")
    dir_scanner = DirectoryScanner(http_client=http_client)
    results.append(await dir_scanner.scan(target))

    emit(25, "Recon: tech stack fingerprinting…")
    fingerprint = FingerprintScanner(http_client=http_client)
    results.append(await fingerprint.scan(target))

    return results


async def _run_headers(
    target: ScanTarget, http_client: ScopedHttpClient
) -> list[ModuleResult]:
    results: list[ModuleResult] = []

    headers_scanner = SecurityHeadersScanner(http_client=http_client)
    results.append(await headers_scanner.scan(target))

    ssl_scanner = SSLTLSScanner()
    results.append(await ssl_scanner.scan(target))

    cookie_scanner = CookieScanner(http_client=http_client)
    results.append(await cookie_scanner.scan(target))

    return results


async def _run_owasp(
    target: ScanTarget, http_client: ScopedHttpClient, config: ScanConfig
) -> list[ModuleResult]:
    results: list[ModuleResult] = []

    if not config.passive_only:
        scanners = [
            OpenRedirectScanner(http_client=http_client),
            CSRFScanner(http_client=http_client),
            MisconfigurationScanner(http_client=http_client),
            SensitiveDataScanner(http_client=http_client),
            AuthScanner(http_client=http_client),
            XSSScanner(http_client=http_client),
            SQLInjectionScanner(http_client=http_client),
            SSRFScanner(http_client=http_client),
            PathTraversalScanner(http_client=http_client),
            CommandInjectionScanner(http_client=http_client),
            SSTIScanner(http_client=http_client),
            HttpMethodScanner(http_client=http_client),
        ]
        for scanner in scanners:
            try:
                result = await scanner.scan(target)
                results.append(result)
            except Exception as e:
                logger.error("Scanner %s failed: %s", scanner.module_name, e)

    return results


async def _run_bruteforce(
    target: ScanTarget, http_client: ScopedHttpClient, config: ScanConfig
) -> list[ModuleResult]:
    results: list[ModuleResult] = []
    from pathlib import Path

    password_wl = Path(config.bruteforce_wordlist) if config.bruteforce_wordlist else None
    username_wl = Path(config.bruteforce_usernames) if config.bruteforce_usernames else None
    max_att = config.bruteforce_max_attempts

    scanners = [
        HttpAuthBruteForce(http_client=http_client, password_wordlist=password_wl,
                           username_wordlist=username_wl, max_attempts=max_att),
        FormLoginBruteForce(http_client=http_client, password_wordlist=password_wl,
                            username_wordlist=username_wl, max_attempts=max_att),
    ]
    for scanner in scanners:
        try:
            result = await scanner.scan(target)
            results.append(result)
        except Exception as e:
            logger.error("Brute force scanner %s failed: %s", type(scanner).__name__, e)

    return results


async def _run_api_security(
    target: ScanTarget, http_client: ScopedHttpClient, config: ScanConfig
) -> list[ModuleResult]:
    results: list[ModuleResult] = []

    discovery = EndpointDiscoveryScanner(http_client=http_client)
    results.append(await discovery.scan(target))

    if not config.passive_only:
        scanners = [
            RateLimitScanner(http_client=http_client),
            AuthBypassScanner(http_client=http_client),
            InputValidationScanner(http_client=http_client),
            IDORScanner(http_client=http_client),
        ]
        for scanner in scanners:
            try:
                result = await scanner.scan(target)
                results.append(result)
            except Exception as e:
                logger.error("Scanner %s failed: %s", scanner.module_name, e)

    return results
