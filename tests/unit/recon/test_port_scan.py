"""Tests for port scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.recon.port_scan import _create_port_finding


class TestCreatePortFinding:
    def test_dangerous_service(self) -> None:
        finding = _create_port_finding("example.com", 6379, "https://example.com")
        assert finding.severity == Severity.HIGH
        assert "Redis" in finding.title

    def test_safe_port(self) -> None:
        finding = _create_port_finding("example.com", 8080, "https://example.com")
        assert finding.severity == Severity.INFO

    def test_telnet_is_high(self) -> None:
        finding = _create_port_finding("example.com", 23, "https://example.com")
        assert finding.severity == Severity.HIGH
        assert "Telnet" in finding.title
