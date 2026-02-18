"""Tests for core immutable data types."""

import pytest

from webscanner.core.types import (
    Finding,
    ModuleResult,
    ScanModule,
    ScanResult,
    ScanTarget,
    Severity,
)


class TestScanTarget:
    def test_frozen(self) -> None:
        target = ScanTarget(
            base_url="https://example.com",
            authorized_domains=frozenset({"example.com"}),
        )
        with pytest.raises(AttributeError):
            target.base_url = "https://other.com"  # type: ignore[misc]

    def test_defaults(self) -> None:
        target = ScanTarget(
            base_url="https://example.com",
            authorized_domains=frozenset({"example.com"}),
        )
        assert target.excluded_paths == frozenset()
        assert target.max_depth == 3


class TestFinding:
    def test_frozen(self) -> None:
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
        with pytest.raises(AttributeError):
            finding.title = "changed"  # type: ignore[misc]

    def test_auto_id(self) -> None:
        f1 = Finding(
            module=ScanModule.OWASP,
            check_name="sqli",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="desc",
            url="https://example.com",
            evidence="ev",
            remediation="fix",
        )
        f2 = Finding(
            module=ScanModule.OWASP,
            check_name="sqli",
            severity=Severity.CRITICAL,
            title="SQL Injection",
            description="desc",
            url="https://example.com",
            evidence="ev",
            remediation="fix",
        )
        assert f1.id != f2.id

    def test_auto_timestamp(self) -> None:
        finding = Finding(
            module=ScanModule.HEADERS,
            check_name="csp",
            severity=Severity.MEDIUM,
            title="Missing CSP",
            description="desc",
            url="https://example.com",
            evidence="ev",
            remediation="fix",
        )
        assert finding.timestamp is not None


class TestModuleResult:
    def test_frozen(self) -> None:
        result = ModuleResult(
            module=ScanModule.RECON,
            findings=(),
            duration_seconds=1.5,
            urls_scanned=10,
        )
        with pytest.raises(AttributeError):
            result.module = ScanModule.OWASP  # type: ignore[misc]


class TestScanResult:
    def test_all_findings(self) -> None:
        f1 = Finding(
            module=ScanModule.OWASP,
            check_name="sqli",
            severity=Severity.CRITICAL,
            title="SQLi",
            description="d",
            url="https://example.com",
            evidence="e",
            remediation="r",
        )
        f2 = Finding(
            module=ScanModule.HEADERS,
            check_name="csp",
            severity=Severity.MEDIUM,
            title="CSP",
            description="d",
            url="https://example.com",
            evidence="e",
            remediation="r",
        )
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        result = ScanResult(
            target=ScanTarget(
                base_url="https://example.com",
                authorized_domains=frozenset({"example.com"}),
            ),
            scan_id="test-scan",
            started_at=now,
            finished_at=now,
            module_results=(
                ModuleResult(module=ScanModule.OWASP, findings=(f1,), duration_seconds=1.0, urls_scanned=5),
                ModuleResult(module=ScanModule.HEADERS, findings=(f2,), duration_seconds=0.5, urls_scanned=3),
            ),
            scanner_version="0.1.0",
        )
        assert len(result.all_findings) == 2

    def test_findings_by_severity(self) -> None:
        f1 = Finding(
            module=ScanModule.OWASP, check_name="sqli", severity=Severity.CRITICAL,
            title="SQLi", description="d", url="u", evidence="e", remediation="r",
        )
        f2 = Finding(
            module=ScanModule.OWASP, check_name="xss", severity=Severity.CRITICAL,
            title="XSS", description="d", url="u", evidence="e", remediation="r",
        )
        f3 = Finding(
            module=ScanModule.HEADERS, check_name="csp", severity=Severity.MEDIUM,
            title="CSP", description="d", url="u", evidence="e", remediation="r",
        )
        from datetime import datetime, timezone

        now = datetime.now(timezone.utc)
        result = ScanResult(
            target=ScanTarget(base_url="https://example.com", authorized_domains=frozenset({"example.com"})),
            scan_id="test",
            started_at=now,
            finished_at=now,
            module_results=(
                ModuleResult(module=ScanModule.OWASP, findings=(f1, f2), duration_seconds=1.0, urls_scanned=5),
                ModuleResult(module=ScanModule.HEADERS, findings=(f3,), duration_seconds=0.5, urls_scanned=3),
            ),
            scanner_version="0.1.0",
        )
        by_sev = result.findings_by_severity
        assert len(by_sev[Severity.CRITICAL]) == 2
        assert len(by_sev[Severity.MEDIUM]) == 1
        assert len(by_sev[Severity.LOW]) == 0
