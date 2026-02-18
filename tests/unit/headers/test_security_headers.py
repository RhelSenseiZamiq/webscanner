"""Tests for security headers scanner."""

import pytest
from unittest.mock import AsyncMock, MagicMock

from webscanner.core.types import ScanTarget, Severity
from webscanner.headers.security_headers import (
    SecurityHeadersScanner,
    _check_csp_quality,
    _check_deprecated_headers,
    _check_missing_headers,
)


class TestCheckMissingHeaders:
    def test_all_present(self) -> None:
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin",
            "Permissions-Policy": "camera=()",
        }
        findings = _check_missing_headers(headers, "https://example.com")
        assert len(findings) == 0

    def test_all_missing(self) -> None:
        findings = _check_missing_headers({}, "https://example.com")
        assert len(findings) == 6

    def test_missing_csp_is_high(self) -> None:
        findings = _check_missing_headers({}, "https://example.com")
        csp_finding = next(f for f in findings if "Content-Security-Policy" in f.title)
        assert csp_finding.severity == Severity.HIGH


class TestCheckCSPQuality:
    def test_no_csp(self) -> None:
        findings = _check_csp_quality({}, "https://example.com")
        assert len(findings) == 0

    def test_unsafe_inline(self) -> None:
        headers = {"Content-Security-Policy": "default-src 'self' 'unsafe-inline'"}
        findings = _check_csp_quality(headers, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_wildcard(self) -> None:
        headers = {"Content-Security-Policy": "default-src *"}
        findings = _check_csp_quality(headers, "https://example.com")
        assert any(f.check_name == "weak_csp" for f in findings)


class TestCheckDeprecatedHeaders:
    def test_no_deprecated(self) -> None:
        findings = _check_deprecated_headers({}, "https://example.com")
        assert len(findings) == 0

    def test_x_xss_protection(self) -> None:
        headers = {"X-XSS-Protection": "1; mode=block"}
        findings = _check_deprecated_headers(headers, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.INFO
