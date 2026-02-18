"""JSON report generation."""

from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path

from webscanner.core.types import ScanResult, Severity


def generate_json_report(result: ScanResult) -> str:
    """Generate a JSON string report from scan results."""
    report = {
        "scan_id": result.scan_id,
        "target": result.target.base_url,
        "scanner_version": result.scanner_version,
        "started_at": result.started_at.isoformat(),
        "finished_at": result.finished_at.isoformat(),
        "summary": _build_summary(result),
        "findings": [_serialize_finding(f) for f in result.all_findings],
        "module_results": [
            {
                "module": mr.module.value,
                "findings_count": len(mr.findings),
                "duration_seconds": round(mr.duration_seconds, 2),
                "urls_scanned": mr.urls_scanned,
                "error": mr.error,
            }
            for mr in result.module_results
        ],
    }
    return json.dumps(report, indent=2, default=str)


def write_json_report(result: ScanResult, output_path: Path) -> None:
    """Write JSON report to file."""
    content = generate_json_report(result)
    output_path.write_text(content, encoding="utf-8")


def _build_summary(result: ScanResult) -> dict[str, int]:
    by_severity = result.findings_by_severity
    return {
        severity.value: len(findings)
        for severity, findings in by_severity.items()
    }


def _serialize_finding(finding: object) -> dict[str, object]:
    """Serialize a Finding to a JSON-safe dictionary."""
    data = asdict(finding)  # type: ignore[arg-type]
    if "module" in data:
        data["module"] = data["module"].value if hasattr(data["module"], "value") else str(data["module"])
    if "severity" in data:
        data["severity"] = data["severity"].value if hasattr(data["severity"], "value") else str(data["severity"])
    if "timestamp" in data:
        ts = data["timestamp"]
        data["timestamp"] = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
    return data
