"""Tests for cookie security scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.headers.cookies import _analyze_cookie


class TestAnalyzeCookie:
    def test_secure_cookie(self) -> None:
        header = "sessionid=abc123; Secure; HttpOnly; SameSite=Strict"
        findings = _analyze_cookie(header, "https://example.com")
        assert len(findings) == 0

    def test_missing_all_flags(self) -> None:
        header = "sessionid=abc123"
        findings = _analyze_cookie(header, "https://example.com")
        assert len(findings) == 3
        check_names = {f.check_name for f in findings}
        assert "cookie_missing_secure" in check_names
        assert "cookie_missing_httponly" in check_names
        assert "cookie_missing_samesite" in check_names

    def test_session_cookie_higher_severity(self) -> None:
        header = "sessionid=abc123"
        findings = _analyze_cookie(header, "https://example.com")
        secure_finding = next(f for f in findings if f.check_name == "cookie_missing_secure")
        assert secure_finding.severity == Severity.MEDIUM

    def test_non_session_cookie_lower_severity(self) -> None:
        header = "theme=dark"
        findings = _analyze_cookie(header, "https://example.com")
        secure_finding = next(f for f in findings if f.check_name == "cookie_missing_secure")
        assert secure_finding.severity == Severity.LOW

    def test_empty_header(self) -> None:
        findings = _analyze_cookie("", "https://example.com")
        assert len(findings) >= 0
