"""Tests for sensitive data scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.owasp.sensitive_data import _scan_body_for_secrets


class TestScanBodyForSecrets:
    def test_no_secrets(self) -> None:
        findings = _scan_body_for_secrets("Hello world", "https://example.com")
        assert len(findings) == 0

    def test_aws_key(self) -> None:
        body = "config: AKIAIOSFODNN7EXAMPLE"
        findings = _scan_body_for_secrets(body, "https://example.com")
        assert any(f.check_name == "aws_key_exposure" for f in findings)
        aws = next(f for f in findings if f.check_name == "aws_key_exposure")
        assert aws.severity == Severity.CRITICAL

    def test_private_key(self) -> None:
        body = "-----BEGIN RSA PRIVATE KEY-----\nMIIE..."
        findings = _scan_body_for_secrets(body, "https://example.com")
        assert any(f.check_name == "private_key_exposure" for f in findings)

    def test_connection_string(self) -> None:
        body = "DATABASE_URL=postgres://user:pass@host:5432/db"
        findings = _scan_body_for_secrets(body, "https://example.com")
        assert any(f.check_name == "sql_connection_string" for f in findings)

    def test_internal_ip(self) -> None:
        body = "Server: 192.168.1.100"
        findings = _scan_body_for_secrets(body, "https://example.com")
        assert any(f.check_name == "internal_ip_exposure" for f in findings)
