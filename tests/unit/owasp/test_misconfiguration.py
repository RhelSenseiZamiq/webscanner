"""Tests for misconfiguration scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.owasp.misconfiguration import (
    _check_cors,
    _check_debug_mode,
    _check_directory_listing,
)


class TestCheckDebugMode:
    def test_no_debug(self) -> None:
        findings = _check_debug_mode("<html>Normal page</html>", "https://example.com")
        assert len(findings) == 0

    def test_django_debug(self) -> None:
        body = "Traceback (most recent call last): File django..."
        findings = _check_debug_mode(body, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH

    def test_laravel_debug(self) -> None:
        body = "Whoops! Something went wrong"
        findings = _check_debug_mode(body, "https://example.com")
        assert len(findings) == 1


class TestCheckCORS:
    def test_no_cors(self) -> None:
        findings = _check_cors({}, "https://example.com")
        assert len(findings) == 0

    def test_wildcard_cors(self) -> None:
        headers = {"Access-Control-Allow-Origin": "*"}
        findings = _check_cors(headers, "https://example.com")
        assert len(findings) == 1
        assert findings[0].severity == Severity.MEDIUM

    def test_wildcard_with_credentials(self) -> None:
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        findings = _check_cors(headers, "https://example.com")
        assert len(findings) == 2
        severities = {f.severity for f in findings}
        assert Severity.HIGH in severities


class TestCheckDirectoryListing:
    def test_no_listing(self) -> None:
        findings = _check_directory_listing("<html>Normal</html>", "https://example.com")
        assert len(findings) == 0

    def test_index_of(self) -> None:
        body = "<h1>Index of /uploads</h1>"
        findings = _check_directory_listing(body, "https://example.com")
        assert len(findings) == 1
