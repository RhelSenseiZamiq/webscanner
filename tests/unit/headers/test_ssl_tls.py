"""Tests for SSL/TLS scanner."""

import pytest

from webscanner.core.types import ScanTarget, Severity
from webscanner.headers.ssl_tls import SSLTLSScanner, _check_protocol_version


class TestSSLTLSScanner:
    @pytest.mark.asyncio
    async def test_http_target_flags_no_https(self) -> None:
        target = ScanTarget(
            base_url="http://example.com",
            authorized_domains=frozenset({"example.com"}),
        )
        scanner = SSLTLSScanner()
        result = await scanner.scan(target)
        assert len(result.findings) >= 1
        assert any(f.check_name == "no_https" for f in result.findings)

    def test_module_name(self) -> None:
        scanner = SSLTLSScanner()
        assert scanner.module_name == "ssl_tls"

    def test_not_active_probe(self) -> None:
        scanner = SSLTLSScanner()
        assert scanner.is_active_probe is False
