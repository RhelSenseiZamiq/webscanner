"""HTTP Basic and Digest authentication brute force scanner.

For authorized testing only. Requires a valid scope file.
All requests go through the ScopedHttpClient, which enforces per-URL
scope validation before any packet is sent.
"""

from __future__ import annotations

import base64
import logging
import time
from pathlib import Path

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

logger = logging.getLogger("webscanner.bruteforce.http_auth")

ACTIVE_PROBE = True

_WORDLISTS_DIR = Path(__file__).parent.parent.parent.parent.parent / "wordlists"
_DEFAULT_PASSWORDS = _WORDLISTS_DIR / "common_passwords.txt"
_DEFAULT_USERNAMES = _WORDLISTS_DIR / "common_usernames.txt"

_BUILTIN_USERNAMES = [
    "admin", "administrator", "root", "user", "guest",
    "test", "operator", "manager", "support", "info",
]


def _load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        logger.warning("Wordlist not found: %s", path)
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _basic_auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


class HttpAuthBruteForce:
    """Detects and brute-forces HTTP Basic authentication endpoints."""

    module_name = ScanModule.BRUTEFORCE

    def __init__(
        self,
        http_client: ScopedHttpClient,
        password_wordlist: Path | None = None,
        username_wordlist: Path | None = None,
        max_attempts: int = 500,
    ) -> None:
        self._client = http_client
        self._passwords = _load_wordlist(password_wordlist or _DEFAULT_PASSWORDS)
        self._usernames = _load_wordlist(username_wordlist or _DEFAULT_USERNAMES) or _BUILTIN_USERNAMES
        self._max_attempts = max_attempts

    async def scan(self, target: ScanTarget) -> ModuleResult:
        started = time.monotonic()
        findings: list[Finding] = []

        try:
            auth_urls = await self._find_auth_protected_urls(target)
            for url in auth_urls:
                result = await self._brute_force_url(url, target)
                if result:
                    findings.append(result)
        except Exception as e:
            logger.error("HTTP auth brute force failed: %s", e)
            return ModuleResult(
                module=ScanModule.BRUTEFORCE,
                findings=(),
                duration_seconds=time.monotonic() - started,
                urls_scanned=0,
                error=str(e),
            )

        return ModuleResult(
            module=ScanModule.BRUTEFORCE,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - started,
            urls_scanned=len(findings),
        )

    async def _find_auth_protected_urls(self, target: ScanTarget) -> list[str]:
        """Find URLs that respond with 401 WWW-Authenticate: Basic."""
        candidates = [target.base_url]
        auth_urls: list[str] = []

        common_auth_paths = ["/admin", "/manager", "/api", "/secure", "/private", "/dashboard"]
        for path in common_auth_paths:
            from urllib.parse import urljoin
            candidates.append(urljoin(target.base_url, path))

        for url in candidates:
            try:
                status, headers, _ = await self._client.get(url)
                if status == 401:
                    www_auth = headers.get("WWW-Authenticate", "")
                    if "Basic" in www_auth or "Digest" in www_auth:
                        logger.info("Found HTTP auth at %s: %s", url, www_auth)
                        auth_urls.append(url)
            except Exception:
                pass

        return auth_urls

    async def _brute_force_url(self, url: str, target: ScanTarget) -> Finding | None:
        """Try username/password combinations against a Basic-auth protected URL."""
        attempts = 0

        for username in self._usernames:
            for password in self._passwords:
                if attempts >= self._max_attempts:
                    logger.warning("Reached max_attempts=%d for %s", self._max_attempts, url)
                    return None

                attempts += 1
                auth_header = _basic_auth_header(username, password)
                try:
                    status, _, _ = await self._client.get(
                        url,
                        headers={"Authorization": auth_header},
                    )
                    if status in (200, 301, 302, 303):
                        logger.warning(
                            "VALID CREDENTIALS at %s — %s:%s", url, username, password
                        )
                        return Finding(
                            module=ScanModule.BRUTEFORCE,
                            check_name="http_basic_auth_weak_credentials",
                            severity=Severity.CRITICAL,
                            title="Weak HTTP Basic Auth Credentials",
                            description=(
                                "The HTTP Basic authentication endpoint accepted a common "
                                "username/password combination from a public wordlist. "
                                "An attacker with network access could gain unauthorized access."
                            ),
                            url=url,
                            evidence=f"Login succeeded with username='{username}' password='{password}' "
                                     f"(HTTP {status}) after {attempts} attempts.",
                            remediation=(
                                "Use a strong, unique password of at least 16 characters. "
                                "Consider replacing HTTP Basic Auth with OAuth2 or API tokens. "
                                "Enable account lockout after 5–10 failed attempts."
                            ),
                            cwe_id="CWE-521",
                            cvss_score=9.8,
                        )
                except Exception as e:
                    logger.debug("Request error for %s: %s", url, e)

        logger.info("No valid credentials found for %s after %d attempts", url, attempts)
        return None
