"""Tests for open redirect scanner."""

import pytest

from webscanner.owasp.open_redirect import _is_external_redirect


class TestIsExternalRedirect:
    def test_external(self) -> None:
        assert _is_external_redirect("https://evil.example.com/page", "https://evil.example.com") is True

    def test_internal(self) -> None:
        assert _is_external_redirect("/dashboard", "https://evil.example.com") is False

    def test_empty(self) -> None:
        assert _is_external_redirect("", "https://evil.example.com") is False
