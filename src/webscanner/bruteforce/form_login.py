"""Form-based login brute force scanner.

Automatically detects HTML login forms, extracts field names and CSRF tokens,
then tests username/password combinations from a wordlist.

For authorized testing only. Scope is enforced by ScopedHttpClient.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

logger = logging.getLogger("webscanner.bruteforce.form_login")

ACTIVE_PROBE = True

_WORDLISTS_DIR = Path(__file__).parent.parent.parent.parent.parent / "wordlists"
_DEFAULT_PASSWORDS = _WORDLISTS_DIR / "common_passwords.txt"
_DEFAULT_USERNAMES = _WORDLISTS_DIR / "common_usernames.txt"

_LOGIN_PATH_HINTS = [
    "/login", "/signin", "/sign-in", "/auth", "/authenticate",
    "/account/login", "/user/login", "/users/sign_in",
    "/wp-login.php", "/admin/login", "/admin",
    "/panel", "/dashboard",
]

_USERNAME_FIELD_NAMES = {
    "username", "user", "login", "email", "user_login",
    "name", "identifier", "uname", "usr",
}
_PASSWORD_FIELD_NAMES = {
    "password", "pass", "passwd", "pwd", "secret",
    "user_password", "pass1", "passcode",
}

# Keywords in the response body that indicate a *failed* login
_FAILURE_KEYWORDS = {
    "invalid", "incorrect", "wrong", "failed", "error",
    "denied", "unauthorized", "bad credentials", "try again",
    "login failed", "authentication failed",
}


@dataclass(frozen=True)
class _LoginForm:
    action_url: str
    method: str
    username_field: str
    password_field: str
    hidden_fields: dict[str, str]


def _load_wordlist(path: Path) -> list[str]:
    if not path.exists():
        return []
    with open(path) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


def _detect_failure(status: int, body: str, baseline_status: int, baseline_len: int) -> bool:
    """Return True if the response looks like a failed login."""
    if status == baseline_status and abs(len(body) - baseline_len) < 100:
        return True
    body_lower = body.lower()
    if any(kw in body_lower for kw in _FAILURE_KEYWORDS):
        return True
    return False


def _extract_login_forms(html: str, page_url: str) -> list[_LoginForm]:
    """Parse HTML and return all detected login forms."""
    soup = BeautifulSoup(html, "lxml")
    forms: list[_LoginForm] = []

    for form in soup.find_all("form"):
        inputs = form.find_all("input")
        fields: dict[str, str] = {}
        for inp in inputs:
            name = (inp.get("name") or "").lower()
            val = inp.get("value") or ""
            itype = (inp.get("type") or "text").lower()
            if name:
                fields[name] = val if itype != "password" else ""

        username_field = next(
            (n for n in fields if n in _USERNAME_FIELD_NAMES), None
        )
        password_field = next(
            (n for n in fields if n in _PASSWORD_FIELD_NAMES), None
        )

        if not username_field or not password_field:
            continue

        action = form.get("action") or page_url
        action_url = urljoin(page_url, action)
        method = (form.get("method") or "post").lower()

        hidden = {
            k: v for k, v in fields.items()
            if k not in (username_field, password_field)
        }

        forms.append(_LoginForm(
            action_url=action_url,
            method=method,
            username_field=username_field,
            password_field=password_field,
            hidden_fields=hidden,
        ))

    return forms


class FormLoginBruteForce:
    """Detects HTML login forms and tests credentials from a wordlist."""

    module_name = ScanModule.BRUTEFORCE

    def __init__(
        self,
        http_client: ScopedHttpClient,
        password_wordlist: Path | None = None,
        username_wordlist: Path | None = None,
        max_attempts: int = 300,
    ) -> None:
        self._client = http_client
        self._passwords = _load_wordlist(password_wordlist or _DEFAULT_PASSWORDS)
        self._usernames = _load_wordlist(username_wordlist or _DEFAULT_USERNAMES)
        self._max_attempts = max_attempts

        if not self._usernames:
            self._usernames = ["admin", "root", "administrator", "user", "test"]

    async def scan(self, target: ScanTarget) -> ModuleResult:
        started = time.monotonic()
        findings: list[Finding] = []
        urls_checked = 0

        login_pages = await self._find_login_pages(target)

        for page_url, html in login_pages:
            urls_checked += 1
            forms = _extract_login_forms(html, page_url)
            for form in forms:
                logger.info(
                    "Found login form at %s → POST %s [user=%s, pass=%s]",
                    page_url, form.action_url, form.username_field, form.password_field,
                )
                finding = await self._brute_force_form(form, page_url)
                if finding:
                    findings.append(finding)

        return ModuleResult(
            module=ScanModule.BRUTEFORCE,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - started,
            urls_scanned=urls_checked,
        )

    async def _find_login_pages(self, target: ScanTarget) -> list[tuple[str, str]]:
        """Return (url, html) for pages that likely contain a login form."""
        candidates: list[str] = [target.base_url]
        for path in _LOGIN_PATH_HINTS:
            candidates.append(urljoin(target.base_url, path))

        results: list[tuple[str, str]] = []
        for url in candidates:
            try:
                status, _, body = await self._client.get(url)
                if status == 200 and body:
                    soup = BeautifulSoup(body, "lxml")
                    # Quick pre-check: does the page have a password input?
                    if soup.find("input", {"type": "password"}):
                        results.append((url, body))
            except Exception:
                pass

        return results

    async def _brute_force_form(self, form: _LoginForm, source_url: str) -> Finding | None:
        """Submit the form with wordlist credentials. Return Finding on success."""
        # Establish baseline: what does a bad login look like?
        try:
            baseline_status, _, baseline_body = await self._submit_form(
                form, "__invalid_user_xqz__", "__invalid_pass_xqz__"
            )
        except Exception as e:
            logger.debug("Baseline request failed for %s: %s", form.action_url, e)
            return None

        baseline_len = len(baseline_body or "")
        attempts = 0

        for username in self._usernames:
            for password in self._passwords:
                if attempts >= self._max_attempts:
                    return None
                attempts += 1

                try:
                    status, _, body = await self._submit_form(form, username, password)
                    body = body or ""
                    if not _detect_failure(status, body, baseline_status, baseline_len):
                        logger.warning(
                            "VALID FORM CREDENTIALS: %s:%s at %s",
                            username, password, form.action_url,
                        )
                        return Finding(
                            module=ScanModule.BRUTEFORCE,
                            check_name="form_login_weak_credentials",
                            severity=Severity.CRITICAL,
                            title="Weak Login Form Credentials",
                            description=(
                                "The login form accepted a common username/password combination "
                                "from a public wordlist. An attacker with access to the login page "
                                "could authenticate as this user without needing to steal credentials."
                            ),
                            url=source_url,
                            evidence=(
                                f"Successful login detected: username='{username}', password='{password}'. "
                                f"Form action: {form.action_url}. "
                                f"Response status {status} differed from failure baseline {baseline_status}."
                            ),
                            remediation=(
                                "Enforce strong password policies (min 12 chars, mixed case, numbers, symbols). "
                                "Implement account lockout after 5–10 failed attempts. "
                                "Add CAPTCHA or MFA to the login form. "
                                "Use password breach detection (e.g. HaveIBeenPwned API)."
                            ),
                            cwe_id="CWE-307",
                            cvss_score=9.1,
                        )
                except Exception as e:
                    logger.debug("Form submit error: %s", e)

        return None

    async def _submit_form(
        self, form: _LoginForm, username: str, password: str
    ) -> tuple[int, dict[str, str], str | None]:
        data = {**form.hidden_fields, form.username_field: username, form.password_field: password}

        if form.method == "get":
            from urllib.parse import urlencode
            url_with_params = f"{form.action_url}?{urlencode(data)}"
            return await self._client.get(url_with_params)
        else:
            return await self._client.post(form.action_url, data=data)
