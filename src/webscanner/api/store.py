"""Scan store — in-memory with on-disk persistence.

Completed and failed scans are written to data/scans/<scan_id>.json so they
survive server restarts. Only the latest MAX_SCANS files are kept on disk.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections import OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from webscanner.api.models import FindingResponse, ScanResponse, ScanStatus, ScanSummary, SiteInfoResponse
from webscanner.core.types import Finding, ScanModule, ScanResult, Severity
from webscanner.recon.site_info import SiteInfo

logger = logging.getLogger("webscanner.api.store")

# data/scans/ lives at the project root (four directories above this file)
# store.py → api/ → webscanner/ → src/ → project root
_DATA_DIR = Path(__file__).parents[3] / "data" / "scans"


@dataclass
class ScanRecord:
    """Mutable scan record (internal state, not exposed directly)."""

    scan_id: str
    status: ScanStatus
    target_url: str
    program: str
    created_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    _subscribers: list[asyncio.Queue[dict[str, Any]]] = field(
        default_factory=list, repr=False
    )
    # Buffered events for late-connecting SSE clients
    _buffer: list[dict[str, Any]] = field(default_factory=list, repr=False)
    # Background asyncio task — used for cancel support; excluded from serialisation
    _task: asyncio.Task | None = field(default=None, repr=False)
    # Site overview collected during recon; excluded from in-memory repr
    site_info: SiteInfo | None = field(default=None, repr=False)

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)
        self._broadcast({"type": "finding", "finding": _finding_to_dict(finding)})

    def add_progress(self, pct: int, message: str) -> None:
        """Broadcast a progress event (percentage + message) to all SSE subscribers."""
        self._broadcast({"type": "progress", "pct": pct, "message": message})

    def set_status(self, status: ScanStatus) -> None:
        self.status = status
        self._broadcast({"type": "status", "status": status.value})

    def set_error(self, error: str) -> None:
        self.error = error
        self.status = ScanStatus.FAILED
        self._broadcast({"type": "error", "error": error})

    def set_result(self, result: ScanResult) -> None:
        self.finished_at = result.finished_at
        self.findings = list(result.all_findings)
        self.status = ScanStatus.COMPLETED
        self._broadcast({"type": "completed", "summary": _build_summary(self.findings)})

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Subscribe to events. Pre-fills queue with buffered history for late clients."""
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        for event in self._buffer:
            queue.put_nowait(event)
        self._subscribers.append(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        if queue in self._subscribers:
            self._subscribers.remove(queue)

    def _broadcast(self, event: dict[str, Any]) -> None:
        self._buffer.append(event)
        for queue in self._subscribers:
            queue.put_nowait(event)

    def to_response(self) -> ScanResponse:
        summary_dict = _build_summary(self.findings)
        return ScanResponse(
            scan_id=self.scan_id,
            status=self.status,
            target_url=self.target_url,
            program=self.program,
            created_at=self.created_at,
            started_at=self.started_at,
            finished_at=self.finished_at,
            summary=ScanSummary(**summary_dict),
            findings=[
                FindingResponse(
                    id=f.id,
                    module=f.module.value,
                    check_name=f.check_name,
                    severity=f.severity.value,
                    title=f.title,
                    description=f.description,
                    url=f.url,
                    evidence=f.evidence,
                    remediation=f.remediation,
                    cvss_score=f.cvss_score,
                    cwe_id=f.cwe_id,
                    timestamp=f.timestamp,
                )
                for f in self.findings
            ],
            site_info=_site_info_to_response(self.site_info),
            error=self.error,
        )


class ScanStore:
    """Scan store backed by on-disk JSON files. Keeps the latest MAX_SCANS scans."""

    MAX_SCANS = 30

    def __init__(self) -> None:
        self._scans: OrderedDict[str, ScanRecord] = OrderedDict()
        _DATA_DIR.mkdir(parents=True, exist_ok=True)
        self._load_from_disk()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create(self, scan_id: str, target_url: str, program: str) -> ScanRecord:
        record = ScanRecord(
            scan_id=scan_id,
            status=ScanStatus.PENDING,
            target_url=target_url,
            program=program,
            created_at=datetime.now(timezone.utc),
        )
        self._scans[scan_id] = record
        self._evict_oldest()
        return record

    def get(self, scan_id: str) -> ScanRecord | None:
        return self._scans.get(scan_id)

    def list_all(self) -> list[ScanRecord]:
        return list(reversed(list(self._scans.values())))

    def delete(self, scan_id: str) -> None:
        """Remove a scan record from memory and delete its disk file."""
        self._scans.pop(scan_id, None)
        (_DATA_DIR / f"{scan_id}.json").unlink(missing_ok=True)

    def persist(self, record: ScanRecord) -> None:
        """Write a completed or failed scan record to disk."""
        if record.status not in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            return
        try:
            path = _DATA_DIR / f"{record.scan_id}.json"
            path.write_text(json.dumps(_record_to_dict(record), indent=2), encoding="utf-8")
        except Exception:
            logger.exception("Failed to persist scan %s", record.scan_id)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _evict_oldest(self) -> None:
        """Remove the oldest in-memory record and its disk file if over limit."""
        while len(self._scans) > self.MAX_SCANS:
            oldest_id, _ = self._scans.popitem(last=False)
            (_DATA_DIR / f"{oldest_id}.json").unlink(missing_ok=True)

    def _load_from_disk(self) -> None:
        """Load persisted scans from disk on startup (newest first, up to MAX_SCANS)."""
        # Sort newest-first to identify the MAX_SCANS most recent files.
        # Then insert them oldest-first so list_all()'s reversal yields newest-first.
        newest_first = sorted(_DATA_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
        to_load = newest_first[: self.MAX_SCANS]
        paths = list(reversed(to_load))  # oldest-first for ordered insertion
        for path in paths:
            try:
                record = _record_from_dict(json.loads(path.read_text(encoding="utf-8")))
                self._scans[record.scan_id] = record
            except Exception:
                logger.debug("Skipping corrupt scan file %s", path)
        # Delete any extra files beyond the limit (oldest files are at the end of newest_first)
        for path in newest_first[self.MAX_SCANS :]:
            try:
                path.unlink()
            except Exception:
                pass


# ---------------------------------------------------------------------------
# Serialisation helpers
# ---------------------------------------------------------------------------

def _record_to_dict(record: ScanRecord) -> dict[str, Any]:
    return {
        "scan_id": record.scan_id,
        "status": record.status.value,
        "target_url": record.target_url,
        "program": record.program,
        "created_at": record.created_at.isoformat(),
        "started_at": record.started_at.isoformat() if record.started_at else None,
        "finished_at": record.finished_at.isoformat() if record.finished_at else None,
        "error": record.error,
        "findings": [_finding_to_dict(f) for f in record.findings],
        "site_info": _site_info_to_dict(record.site_info),
    }


def _record_from_dict(data: dict[str, Any]) -> ScanRecord:
    findings = [_finding_from_dict(f) for f in data.get("findings", [])]
    raw_si = data.get("site_info")
    site_info = _site_info_from_dict(raw_si) if raw_si else None
    return ScanRecord(
        scan_id=data["scan_id"],
        status=ScanStatus(data["status"]),
        target_url=data["target_url"],
        program=data.get("program", ""),
        created_at=datetime.fromisoformat(data["created_at"]),
        started_at=datetime.fromisoformat(data["started_at"]) if data.get("started_at") else None,
        finished_at=datetime.fromisoformat(data["finished_at"]) if data.get("finished_at") else None,
        error=data.get("error"),
        findings=findings,
        site_info=site_info,
    )


def _finding_to_dict(f: Finding) -> dict[str, Any]:
    return {
        "id": f.id,
        "module": f.module.value,
        "check_name": f.check_name,
        "severity": f.severity.value,
        "title": f.title,
        "description": f.description,
        "url": f.url,
        "evidence": f.evidence,
        "remediation": f.remediation,
        "cvss_score": f.cvss_score,
        "cwe_id": f.cwe_id,
        "timestamp": f.timestamp.isoformat(),
    }


def _finding_from_dict(data: dict[str, Any]) -> Finding:
    return Finding(
        id=data["id"],
        module=ScanModule(data["module"]),
        check_name=data["check_name"],
        severity=Severity(data["severity"]),
        title=data["title"],
        description=data["description"],
        url=data["url"],
        evidence=data["evidence"],
        remediation=data["remediation"],
        cvss_score=data.get("cvss_score"),
        cwe_id=data.get("cwe_id"),
        timestamp=datetime.fromisoformat(data["timestamp"]),
    )


def _site_info_to_dict(info: SiteInfo | None) -> dict[str, Any] | None:
    if info is None:
        return None
    return {
        "final_url": info.final_url,
        "status_code": info.status_code,
        "response_time_ms": info.response_time_ms,
        "redirect_chain": list(info.redirect_chain),
        "server": info.server,
        "powered_by": info.powered_by,
        "ip_address": info.ip_address,
        "cdn": info.cdn,
        "title": info.title,
        "description": info.description,
        "favicon_url": info.favicon_url,
        "language": info.language,
        "og_title": info.og_title,
        "og_description": info.og_description,
        "technologies": list(info.technologies),
        "ssl_issuer": info.ssl_issuer,
        "ssl_subject": info.ssl_subject,
        "ssl_expiry": info.ssl_expiry,
        "ssl_days_remaining": info.ssl_days_remaining,
        "ssl_sans": list(info.ssl_sans),
        "dns_a": list(info.dns_a),
        "dns_mx": list(info.dns_mx),
        "dns_ns": list(info.dns_ns),
        "dns_txt": list(info.dns_txt),
        "has_robots_txt": info.has_robots_txt,
        "robots_txt_preview": info.robots_txt_preview,
        "has_sitemap": info.has_sitemap,
        "response_headers": dict(info.response_headers),
    }


def _site_info_from_dict(data: dict[str, Any]) -> SiteInfo:
    return SiteInfo(
        final_url=data["final_url"],
        status_code=data["status_code"],
        response_time_ms=data["response_time_ms"],
        redirect_chain=tuple(data.get("redirect_chain", [])),
        server=data.get("server"),
        powered_by=data.get("powered_by"),
        ip_address=data.get("ip_address"),
        cdn=data.get("cdn"),
        title=data.get("title"),
        description=data.get("description"),
        favicon_url=data.get("favicon_url"),
        language=data.get("language"),
        og_title=data.get("og_title"),
        og_description=data.get("og_description"),
        technologies=tuple(data.get("technologies", [])),
        ssl_issuer=data.get("ssl_issuer"),
        ssl_subject=data.get("ssl_subject"),
        ssl_expiry=data.get("ssl_expiry"),
        ssl_days_remaining=data.get("ssl_days_remaining"),
        ssl_sans=tuple(data.get("ssl_sans", [])),
        dns_a=tuple(data.get("dns_a", [])),
        dns_mx=tuple(data.get("dns_mx", [])),
        dns_ns=tuple(data.get("dns_ns", [])),
        dns_txt=tuple(data.get("dns_txt", [])),
        has_robots_txt=data.get("has_robots_txt", False),
        robots_txt_preview=data.get("robots_txt_preview"),
        has_sitemap=data.get("has_sitemap", False),
        response_headers=data.get("response_headers", {}),
    )


def _site_info_to_response(info: SiteInfo | None) -> SiteInfoResponse | None:
    if info is None:
        return None
    return SiteInfoResponse(
        final_url=info.final_url,
        status_code=info.status_code,
        response_time_ms=info.response_time_ms,
        redirect_chain=list(info.redirect_chain),
        server=info.server,
        powered_by=info.powered_by,
        ip_address=info.ip_address,
        cdn=info.cdn,
        title=info.title,
        description=info.description,
        favicon_url=info.favicon_url,
        language=info.language,
        og_title=info.og_title,
        og_description=info.og_description,
        technologies=list(info.technologies),
        ssl_issuer=info.ssl_issuer,
        ssl_subject=info.ssl_subject,
        ssl_expiry=info.ssl_expiry,
        ssl_days_remaining=info.ssl_days_remaining,
        ssl_sans=list(info.ssl_sans),
        dns_a=list(info.dns_a),
        dns_mx=list(info.dns_mx),
        dns_ns=list(info.dns_ns),
        dns_txt=list(info.dns_txt),
        has_robots_txt=info.has_robots_txt,
        robots_txt_preview=info.robots_txt_preview,
        has_sitemap=info.has_sitemap,
        response_headers=dict(info.response_headers),
    )


def _build_summary(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
