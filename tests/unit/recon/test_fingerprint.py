"""Tests for fingerprint scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.recon.fingerprint import _check_server_info_leak


class TestCheckServerInfoLeak:
    def test_version_disclosure(self) -> None:
        findings: list = []
        headers = {"Server": "Apache/2.4.52"}
        _check_server_info_leak(headers, "https://example.com", findings)
        assert len(findings) == 1
        assert findings[0].severity == Severity.LOW

    def test_no_version(self) -> None:
        findings: list = []
        headers = {"Server": "nginx"}
        _check_server_info_leak(headers, "https://example.com", findings)
        assert len(findings) == 0

    def test_x_powered_by(self) -> None:
        findings: list = []
        headers = {"X-Powered-By": "PHP/8.1"}
        _check_server_info_leak(headers, "https://example.com", findings)
        assert len(findings) >= 1

    def test_no_headers(self) -> None:
        findings: list = []
        _check_server_info_leak({}, "https://example.com", findings)
        assert len(findings) == 0
