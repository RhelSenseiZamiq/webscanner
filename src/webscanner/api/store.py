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

from webscanner.api.models import FindingResponse, ScanResponse, ScanStatus, ScanSummary
from webscanner.core.types import Finding, ScanModule, ScanResult, Severity

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
        paths = sorted(_DATA_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime)
        # Keep only the latest MAX_SCANS
        for path in paths[: self.MAX_SCANS]:
            try:
                record = _record_from_dict(json.loads(path.read_text(encoding="utf-8")))
                self._scans[record.scan_id] = record
            except Exception:
                logger.debug("Skipping corrupt scan file %s", path)
        # Delete any extra files beyond the limit
        for path in paths[self.MAX_SCANS :]:
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
    }


def _record_from_dict(data: dict[str, Any]) -> ScanRecord:
    findings = [_finding_from_dict(f) for f in data.get("findings", [])]
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


def _build_summary(findings: list[Finding]) -> dict[str, int]:
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
