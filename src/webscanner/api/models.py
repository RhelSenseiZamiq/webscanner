"""Pydantic models for the REST API."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, field_validator


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class StartScanRequest(BaseModel):
    target_url: str
    authorized_domains: list[str]
    excluded_paths: list[str] = []
    program: str
    modules: list[str] = ["recon", "headers", "owasp", "api"]
    rate_limit: float = 5.0
    passive_only: bool = False
    timeout_seconds: int = 10
    contact_email: str = ""
    # Brute force options (only used when "bruteforce" is in modules)
    bruteforce_wordlist: str = ""      # path to password wordlist on the server
    bruteforce_usernames: str = ""     # path to username wordlist on the server
    bruteforce_max_attempts: int = 300

    @field_validator("target_url")
    @classmethod
    def validate_url(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @field_validator("authorized_domains")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("At least one authorized domain is required")
        return v

    @field_validator("program")
    @classmethod
    def validate_program(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("Bug bounty program name is required")
        return v

    @field_validator("rate_limit")
    @classmethod
    def validate_rate_limit(cls, v: float) -> float:
        if v <= 0:
            raise ValueError("rate_limit must be positive")
        return v


class FindingResponse(BaseModel):
    id: str
    module: str
    check_name: str
    severity: str
    title: str
    description: str
    url: str
    evidence: str
    remediation: str
    cvss_score: float | None
    cwe_id: str | None
    timestamp: datetime


class ScanSummary(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResponse(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    program: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    summary: ScanSummary = ScanSummary()
    findings: list[FindingResponse] = []
    error: str | None = None


class ScanListItem(BaseModel):
    scan_id: str
    status: ScanStatus
    target_url: str
    program: str
    created_at: datetime
    finished_at: datetime | None = None
    summary: ScanSummary = ScanSummary()


class SSEEvent(BaseModel):
    event: str
    data: dict[str, Any]


# ---------------------------------------------------------------------------
# WiFi models
# ---------------------------------------------------------------------------

class WiFiNetworkResponse(BaseModel):
    ssid: str
    bssid: str
    signal_dbm: int
    channel: int
    security: str
    wps_enabled: bool
    band: str


class WiFiFindingResponse(BaseModel):
    network_ssid: str
    bssid: str
    severity: str
    title: str
    description: str
    evidence: str
    remediation: str


class WiFiScanSummary(BaseModel):
    total_networks: int = 0
    open: int = 0
    wep: int = 0
    wps_enabled: int = 0
    wpa2: int = 0
    wpa3: int = 0
    total_findings: int = 0


class WiFiScanResponse(BaseModel):
    status: str
    platform: str
    scan_duration_seconds: float
    networks: list[WiFiNetworkResponse] = []
    findings: list[WiFiFindingResponse] = []
    summary: WiFiScanSummary = WiFiScanSummary()
    error: str | None = None


# ---------------------------------------------------------------------------
# WiFi attack models
# ---------------------------------------------------------------------------

class WiFiAttackRequest(BaseModel):
    ssid: str
    wordlist: str = "wordlists/wifi-passwords.txt"
    max_attempts: int = 30
    interface: str = "en0"


class WiFiAttackResponse(BaseModel):
    ssid: str
    password_found: bool
    password: str | None = None
    attempts: int
    duration_seconds: float
    wordlist_used: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Docker scan models
# ---------------------------------------------------------------------------

class DockerScanRequest(BaseModel):
    path: str = "."
    include_live: bool = False


class DockerFindingResponse(BaseModel):
    severity: str
    title: str
    source: str
    evidence: str
    remediation: str


class DockerScanResponse(BaseModel):
    dockerfiles_scanned: int
    compose_files_scanned: int
    containers_inspected: int
    findings: list[DockerFindingResponse]
    error: str | None = None


# ---------------------------------------------------------------------------
# Kubernetes scan models
# ---------------------------------------------------------------------------

class K8sScanRequest(BaseModel):
    path: str = "."
    include_live: bool = False


class K8sFindingResponse(BaseModel):
    severity: str
    title: str
    source: str
    namespace: str
    evidence: str
    remediation: str


class K8sScanResponse(BaseModel):
    manifests_scanned: int
    live_resources_checked: int
    findings: list[K8sFindingResponse]
    error: str | None = None
