"""Tests for JSON report generation."""

import json
from datetime import datetime, timezone

import pytest

from webscanner.core.types import (
    Finding, ModuleResult, ScanModule, ScanResult, ScanTarget, Severity,
)
from webscanner.reporting.json_reporter import generate_json_report


@pytest.fixture
def sample_scan_result() -> ScanResult:
    now = datetime.now(timezone.utc)
    finding = Finding(
        module=ScanModule.OWASP,
        check_name="sqli",
        severity=Severity.CRITICAL,
        title="SQL Injection",
        description="Found SQL injection",
        url="https://example.com/search?q=test",
        evidence="Error in SQL syntax",
        remediation="Use parameterized queries",
    )
    return ScanResult(
        target=ScanTarget(
            base_url="https://example.com",
            authorized_domains=frozenset({"example.com"}),
        ),
        scan_id="test-scan-123",
        started_at=now,
        finished_at=now,
        module_results=(
            ModuleResult(
                module=ScanModule.OWASP,
                findings=(finding,),
                duration_seconds=1.5,
                urls_scanned=10,
            ),
        ),
        scanner_version="0.1.0",
    )


class TestGenerateJsonReport:
    def test_valid_json(self, sample_scan_result: ScanResult) -> None:
        report = generate_json_report(sample_scan_result)
        parsed = json.loads(report)
        assert parsed["scan_id"] == "test-scan-123"

    def test_has_summary(self, sample_scan_result: ScanResult) -> None:
        report = generate_json_report(sample_scan_result)
        parsed = json.loads(report)
        assert "summary" in parsed
        assert parsed["summary"]["critical"] == 1

    def test_has_findings(self, sample_scan_result: ScanResult) -> None:
        report = generate_json_report(sample_scan_result)
        parsed = json.loads(report)
        assert len(parsed["findings"]) == 1
        assert parsed["findings"][0]["title"] == "SQL Injection"
