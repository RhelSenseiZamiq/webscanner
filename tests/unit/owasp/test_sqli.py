"""Tests for SQL injection scanner."""

import pytest

from webscanner.owasp.sqli import _extract_params_from_html, _inject_param


class TestExtractParams:
    def test_extracts_form_inputs(self) -> None:
        html = '<form action="/search"><input name="q" type="text"></form>'
        params = _extract_params_from_html(html, "https://example.com")
        assert len(params) >= 1
        assert any(name == "q" for _, name in params)

    def test_extracts_link_params(self) -> None:
        html = '<a href="/page?id=1&name=test">Link</a>'
        params = _extract_params_from_html(html, "https://example.com")
        param_names = {name for _, name in params}
        assert "id" in param_names

    def test_empty_html(self) -> None:
        params = _extract_params_from_html("", "https://example.com")
        assert params == []


class TestInjectParam:
    def test_adds_param(self) -> None:
        result = _inject_param("https://example.com/search", "q", "test")
        assert "q=test" in result

    def test_replaces_existing_param(self) -> None:
        result = _inject_param("https://example.com/search?q=original", "q", "injected")
        assert "q=injected" in result
        assert "original" not in result

    def test_preserves_other_params(self) -> None:
        result = _inject_param("https://example.com/search?q=test&page=1", "q", "payload")
        assert "page=1" in result
        assert "q=payload" in result
