"""Scope validation and authorization enforcement.

This is the critical safety gate — every scan request MUST pass through
scope validation before any network I/O is allowed.
"""

from __future__ import annotations

from dataclasses import dataclass
from fnmatch import fnmatch
from urllib.parse import urlparse

from webscanner.core.exceptions import ScopeValidationError, ScopeViolationError
from webscanner.core.types import ScanTarget


@dataclass(frozen=True)
class ScopeConfig:
    """User-supplied authorization configuration."""

    authorized_domains: frozenset[str]
    excluded_paths: frozenset[str]
    bug_bounty_program: str
    authorization_confirmed: bool


def validate_scope(raw_url: str, config: ScopeConfig) -> ScanTarget:
    """Validate that the target URL is within authorized scope.

    Raises ScopeValidationError for invalid configuration.
    Raises ScopeViolationError if the target is outside declared scope.
    Returns an immutable ScanTarget on success.
    """
    if not config.authorization_confirmed:
        raise ScopeValidationError(
            "authorization_confirmed must be True. "
            "Confirm you have explicit written authorization to test this target."
        )

    if not config.authorized_domains:
        raise ScopeValidationError("At least one authorized domain is required.")

    if not config.bug_bounty_program:
        raise ScopeValidationError("Bug bounty program name is required.")

    parsed = urlparse(raw_url)
    if parsed.scheme not in ("http", "https"):
        raise ScopeValidationError(f"Invalid URL scheme: {parsed.scheme!r}. Use http or https.")

    if not parsed.netloc:
        raise ScopeValidationError(f"Invalid URL: missing host in {raw_url!r}")

    domain = parsed.netloc.split(":")[0]
    if not _is_domain_authorized(domain, config.authorized_domains):
        raise ScopeViolationError(
            f"Domain {domain!r} is not in the authorized scope: "
            f"{sorted(config.authorized_domains)}"
        )

    return ScanTarget(
        base_url=raw_url,
        authorized_domains=config.authorized_domains,
        excluded_paths=config.excluded_paths,
    )


def is_url_in_scope(url: str, target: ScanTarget) -> bool:
    """Check whether a discovered URL is within the validated target scope."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False

    domain = parsed.netloc.split(":")[0]
    if not _is_domain_authorized(domain, target.authorized_domains):
        return False

    path = parsed.path or "/"
    for excluded in target.excluded_paths:
        if fnmatch(path, excluded) or path.startswith(excluded):
            return False

    return True


def _is_domain_authorized(domain: str, authorized_domains: frozenset[str]) -> bool:
    """Check if a domain matches any authorized domain (including subdomains)."""
    return any(
        domain == auth_domain or domain.endswith(f".{auth_domain}")
        for auth_domain in authorized_domains
    )
