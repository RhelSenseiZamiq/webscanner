"""Tests for directory scanner."""

import pytest

from webscanner.core.types import Severity
from webscanner.recon.directory import _create_path_finding


class TestCreatePathFinding:
    def test_sensitive_exposed(self) -> None:
        finding = _create_path_finding("https://example.com/.env", "/.env", 200)
        assert finding.severity == Severity.HIGH

    def test_protected_path(self) -> None:
        finding = _create_path_finding("https://example.com/admin", "/admin", 403)
        assert finding.severity == Severity.INFO

    def test_normal_path(self) -> None:
        finding = _create_path_finding("https://example.com/api", "/api", 200)
        assert finding.severity == Severity.INFO

    def test_redirect(self) -> None:
        finding = _create_path_finding("https://example.com/login", "/login", 301)
        assert finding is not None
