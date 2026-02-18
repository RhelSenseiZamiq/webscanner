"""Self-contained HTML report generation."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Template

from webscanner.core.types import ScanResult, Severity

HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebScanner Report - {{ target }}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
         background: #1a1a2e; color: #e0e0e0; padding: 2rem; }
  .container { max-width: 1200px; margin: 0 auto; }
  h1 { color: #00d4ff; margin-bottom: 1rem; }
  .meta { color: #888; margin-bottom: 2rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .summary-card { padding: 1rem 1.5rem; border-radius: 8px; background: #16213e; min-width: 120px; text-align: center; }
  .summary-card .count { font-size: 2rem; font-weight: bold; }
  .critical { border-left: 4px solid #ff4444; }
  .critical .count { color: #ff4444; }
  .high { border-left: 4px solid #ff8800; }
  .high .count { color: #ff8800; }
  .medium { border-left: 4px solid #ffcc00; }
  .medium .count { color: #ffcc00; }
  .low { border-left: 4px solid #4488ff; }
  .low .count { color: #4488ff; }
  .info { border-left: 4px solid #888; }
  .info .count { color: #888; }
  table { width: 100%; border-collapse: collapse; margin-top: 1rem; }
  th { background: #16213e; padding: 0.75rem; text-align: left; border-bottom: 2px solid #333; }
  td { padding: 0.75rem; border-bottom: 1px solid #2a2a4a; }
  tr:hover { background: #16213e; }
  .severity-badge { padding: 0.25rem 0.5rem; border-radius: 4px; font-size: 0.8rem; font-weight: bold; }
  .badge-critical { background: #ff4444; color: white; }
  .badge-high { background: #ff8800; color: white; }
  .badge-medium { background: #ffcc00; color: black; }
  .badge-low { background: #4488ff; color: white; }
  .badge-info { background: #555; color: white; }
  details { margin-top: 0.5rem; }
  details summary { cursor: pointer; color: #00d4ff; }
  details pre { background: #0f0f23; padding: 1rem; margin-top: 0.5rem; border-radius: 4px; overflow-x: auto; font-size: 0.85rem; }
</style>
</head>
<body>
<div class="container">
  <h1>WebScanner Vulnerability Report</h1>
  <div class="meta">
    Target: {{ target }} | Scan ID: {{ scan_id }} | Duration: {{ duration }}s | {{ timestamp }}
  </div>
  <div class="summary">
    {% for sev, count in summary.items() %}
    <div class="summary-card {{ sev }}">
      <div class="count">{{ count }}</div>
      <div>{{ sev | upper }}</div>
    </div>
    {% endfor %}
  </div>
  <table>
    <thead>
      <tr><th>Severity</th><th>Module</th><th>Title</th><th>URL</th><th>Details</th></tr>
    </thead>
    <tbody>
    {% for f in findings %}
      <tr>
        <td><span class="severity-badge badge-{{ f.severity }}">{{ f.severity | upper }}</span></td>
        <td>{{ f.module }}</td>
        <td>{{ f.title }}</td>
        <td style="max-width:300px;overflow:hidden;text-overflow:ellipsis">{{ f.url }}</td>
        <td>
          <details>
            <summary>View</summary>
            <pre>{{ f.description }}

Evidence: {{ f.evidence }}
Remediation: {{ f.remediation }}
{% if f.cwe_id %}CWE: {{ f.cwe_id }}{% endif %}
{% if f.cvss_score %}CVSS: {{ f.cvss_score }}{% endif %}</pre>
          </details>
        </td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
</div>
</body>
</html>"""


def generate_html_report(result: ScanResult) -> str:
    """Generate a self-contained HTML report string."""
    template = Template(HTML_TEMPLATE)
    duration = (result.finished_at - result.started_at).total_seconds()
    by_severity = result.findings_by_severity

    sorted_findings = sorted(
        result.all_findings,
        key=lambda f: list(Severity).index(f.severity),
    )

    return template.render(
        target=result.target.base_url,
        scan_id=result.scan_id,
        duration=f"{duration:.1f}",
        timestamp=result.started_at.isoformat(),
        summary={
            s.value: len(by_severity.get(s, ()))
            for s in Severity
        },
        findings=[
            {
                "severity": f.severity.value,
                "module": f.module.value,
                "title": f.title,
                "url": f.url,
                "description": f.description,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "cwe_id": f.cwe_id,
                "cvss_score": f.cvss_score,
            }
            for f in sorted_findings
        ],
    )


def write_html_report(result: ScanResult, output_path: Path) -> None:
    """Write HTML report to file."""
    content = generate_html_report(result)
    output_path.write_text(content, encoding="utf-8")
