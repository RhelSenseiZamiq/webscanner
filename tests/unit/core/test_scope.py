"""Tests for scope validation — 100% branch coverage target."""

import pytest

from webscanner.core.exceptions import ScopeValidationError, ScopeViolationError
from webscanner.core.scope import ScopeConfig, is_url_in_scope, validate_scope
from webscanner.core.types import ScanTarget


class TestValidateScope:
    def test_valid_scope(self, sample_scope_config: ScopeConfig) -> None:
        target = validate_scope("https://example.com", sample_scope_config)
        assert target.base_url == "https://example.com"
        assert "example.com" in target.authorized_domains

    def test_subdomain_in_scope(self, sample_scope_config: ScopeConfig) -> None:
        target = validate_scope("https://sub.example.com", sample_scope_config)
        assert target.base_url == "https://sub.example.com"

    def test_rejects_unconfirmed_authorization(self) -> None:
        config = ScopeConfig(
            authorized_domains=frozenset({"example.com"}),
            excluded_paths=frozenset(),
            bug_bounty_program="test",
            authorization_confirmed=False,
        )
        with pytest.raises(ScopeValidationError, match="authorization_confirmed"):
            validate_scope("https://example.com", config)

    def test_rejects_empty_domains(self) -> None:
        config = ScopeConfig(
            authorized_domains=frozenset(),
            excluded_paths=frozenset(),
            bug_bounty_program="test",
            authorization_confirmed=True,
        )
        with pytest.raises(ScopeValidationError, match="authorized domain"):
            validate_scope("https://example.com", config)

    def test_rejects_empty_program_name(self) -> None:
        config = ScopeConfig(
            authorized_domains=frozenset({"example.com"}),
            excluded_paths=frozenset(),
            bug_bounty_program="",
            authorization_confirmed=True,
        )
        with pytest.raises(ScopeValidationError, match="program name"):
            validate_scope("https://example.com", config)

    def test_rejects_invalid_scheme(self, sample_scope_config: ScopeConfig) -> None:
        with pytest.raises(ScopeValidationError, match="Invalid URL scheme"):
            validate_scope("ftp://example.com", sample_scope_config)

    def test_rejects_missing_host(self, sample_scope_config: ScopeConfig) -> None:
        with pytest.raises(ScopeValidationError, match="missing host"):
            validate_scope("https://", sample_scope_config)

    def test_rejects_out_of_scope_domain(self, sample_scope_config: ScopeConfig) -> None:
        with pytest.raises(ScopeViolationError, match="not in the authorized scope"):
            validate_scope("https://evil.com", sample_scope_config)

    def test_http_scheme_allowed(self, sample_scope_config: ScopeConfig) -> None:
        target = validate_scope("http://example.com", sample_scope_config)
        assert target.base_url == "http://example.com"

    def test_url_with_port(self, sample_scope_config: ScopeConfig) -> None:
        target = validate_scope("https://example.com:8443", sample_scope_config)
        assert target.base_url == "https://example.com:8443"

    def test_excluded_paths_propagated(self, sample_scope_config: ScopeConfig) -> None:
        target = validate_scope("https://example.com", sample_scope_config)
        assert "/logout" in target.excluded_paths


class TestIsUrlInScope:
    def test_in_scope(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("https://example.com/page", sample_target) is True

    def test_subdomain_in_scope(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("https://sub.example.com/page", sample_target) is True

    def test_out_of_scope_domain(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("https://evil.com/page", sample_target) is False

    def test_excluded_path(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("https://example.com/logout", sample_target) is False

    def test_invalid_scheme(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("ftp://example.com/file", sample_target) is False

    def test_partial_domain_not_matched(self) -> None:
        target = ScanTarget(
            base_url="https://example.com",
            authorized_domains=frozenset({"example.com"}),
        )
        assert is_url_in_scope("https://notexample.com", target) is False

    def test_empty_path(self, sample_target: ScanTarget) -> None:
        assert is_url_in_scope("https://example.com", sample_target) is True
