"""Tests for HTML report generation."""

from datetime import datetime, timezone

import pytest

from webscanner.core.types import (
    Finding, ModuleResult, ScanModule, ScanResult, ScanTarget, Severity,
)
from webscanner.reporting.html_reporter import generate_html_report


@pytest.fixture
def sample_scan_result() -> ScanResult:
    now = datetime.now(timezone.utc)
    return ScanResult(
        target=ScanTarget(
            base_url="https://example.com",
            authorized_domains=frozenset({"example.com"}),
        ),
        scan_id="html-test",
        started_at=now,
        finished_at=now,
        module_results=(
            ModuleResult(
                module=ScanModule.HEADERS,
                findings=(
                    Finding(
                        module=ScanModule.HEADERS,
                        check_name="csp",
                        severity=Severity.HIGH,
                        title="Missing CSP",
                        description="No CSP header",
                        url="https://example.com",
                        evidence="Header absent",
                        remediation="Add CSP header",
                    ),
                ),
                duration_seconds=0.5,
                urls_scanned=1,
            ),
        ),
        scanner_version="0.1.0",
    )


class TestGenerateHtmlReport:
    def test_contains_html(self, sample_scan_result: ScanResult) -> None:
        html = generate_html_report(sample_scan_result)
        assert "<!DOCTYPE html>" in html
        assert "WebScanner" in html

    def test_contains_finding(self, sample_scan_result: ScanResult) -> None:
        html = generate_html_report(sample_scan_result)
        assert "Missing CSP" in html

    def test_self_contained(self, sample_scan_result: ScanResult) -> None:
        html = generate_html_report(sample_scan_result)
        assert "<style>" in html
