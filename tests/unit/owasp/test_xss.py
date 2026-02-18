"""Tests for XSS scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.owasp.xss import _check_dom_xss


class TestCheckDomXSS:
    def test_no_sources_no_findings(self) -> None:
        html = "<script>console.log('safe')</script>"
        findings = _check_dom_xss(html, "https://example.com")
        assert len(findings) == 0

    def test_source_and_sink(self) -> None:
        html = """
        <script>
        var x = location.hash;
        document.write(x);
        </script>
        """
        findings = _check_dom_xss(html, "https://example.com")
        assert len(findings) >= 1
        assert findings[0].check_name == "xss_dom"

    def test_source_without_sink(self) -> None:
        html = "<script>var x = location.hash; console.log(x);</script>"
        findings = _check_dom_xss(html, "https://example.com")
        assert len(findings) == 0

    def test_innerhtml_with_source(self) -> None:
        html = """
        <script>
        var input = location.search;
        element.innerHTML = input;
        </script>
        """
        findings = _check_dom_xss(html, "https://example.com")
        assert len(findings) >= 1
