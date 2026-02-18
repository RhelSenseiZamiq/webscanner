"""Tests for CSRF scanner."""

import pytest

from bs4 import BeautifulSoup

from webscanner.owasp.csrf import _form_has_csrf_token


class TestFormHasCSRFToken:
    def test_with_token(self) -> None:
        html = '<form><input type="hidden" name="csrf_token" value="abc123"></form>'
        form = BeautifulSoup(html, "lxml").find("form")
        assert _form_has_csrf_token(form) is True

    def test_without_token(self) -> None:
        html = '<form><input type="text" name="username"></form>'
        form = BeautifulSoup(html, "lxml").find("form")
        assert _form_has_csrf_token(form) is False

    def test_django_token(self) -> None:
        html = '<form><input type="hidden" name="csrfmiddlewaretoken" value="xyz"></form>'
        form = BeautifulSoup(html, "lxml").find("form")
        assert _form_has_csrf_token(form) is True

    def test_rails_token(self) -> None:
        html = '<form><input type="hidden" name="authenticity_token" value="xyz"></form>'
        form = BeautifulSoup(html, "lxml").find("form")
        assert _form_has_csrf_token(form) is True
