"""Tests for the Scanner protocol."""

from webscanner.core.scanner import Scanner
from webscanner.core.types import ModuleResult, ScanModule, ScanTarget


class FakeScanner:
    async def scan(self, target: ScanTarget) -> ModuleResult:
        return ModuleResult(module=ScanModule.RECON, findings=(), duration_seconds=0, urls_scanned=0)

    @property
    def module_name(self) -> str:
        return "fake"

    @property
    def is_active_probe(self) -> bool:
        return False


class TestScannerProtocol:
    def test_implements_protocol(self) -> None:
        scanner = FakeScanner()
        assert isinstance(scanner, Scanner)

    def test_module_name(self) -> None:
        scanner = FakeScanner()
        assert scanner.module_name == "fake"

    def test_is_active_probe(self) -> None:
        scanner = FakeScanner()
        assert scanner.is_active_probe is False
