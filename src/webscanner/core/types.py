"""Immutable data types for the web scanner."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanModule(str, Enum):
    RECON = "recon"
    HEADERS = "headers"
    OWASP = "owasp"
    API_SECURITY = "api_security"
    BRUTEFORCE = "bruteforce"
    WIFI = "wifi"


@dataclass(frozen=True)
class ScanTarget:
    """Immutable description of a validated, authorized target."""

    base_url: str
    authorized_domains: frozenset[str]
    excluded_paths: frozenset[str] = field(default_factory=frozenset)
    max_depth: int = 3


@dataclass(frozen=True)
class Finding:
    """An immutable vulnerability finding."""

    module: ScanModule
    check_name: str
    severity: Severity
    title: str
    description: str
    url: str
    evidence: str
    remediation: str
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    cvss_score: float | None = None
    cwe_id: str | None = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    request_sample: str | None = None
    response_sample: str | None = None


@dataclass(frozen=True)
class ModuleResult:
    """Immutable result from a single scan module."""

    module: ScanModule
    findings: tuple[Finding, ...]
    duration_seconds: float
    urls_scanned: int
    error: str | None = None


@dataclass(frozen=True)
class ScanResult:
    """Immutable aggregate result of a full scan."""

    target: ScanTarget
    scan_id: str
    started_at: datetime
    finished_at: datetime
    module_results: tuple[ModuleResult, ...]
    scanner_version: str

    @property
    def all_findings(self) -> tuple[Finding, ...]:
        return tuple(f for mr in self.module_results for f in mr.findings)

    @property
    def findings_by_severity(self) -> dict[Severity, tuple[Finding, ...]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.all_findings:
            result[f.severity].append(f)
        return {k: tuple(v) for k, v in result.items()}
