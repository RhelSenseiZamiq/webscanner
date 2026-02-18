"""Rich terminal report output."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from webscanner.core.types import ScanResult, Severity

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}


def print_terminal_report(result: ScanResult, console: Console | None = None) -> None:
    """Print a formatted report to the terminal."""
    if console is None:
        console = Console()

    _print_header(result, console)
    _print_summary(result, console)
    _print_findings_table(result, console)
    _print_footer(result, console)


def _print_header(result: ScanResult, console: Console) -> None:
    duration = (result.finished_at - result.started_at).total_seconds()
    console.print(Panel(
        f"[bold]Target:[/bold] {result.target.base_url}\n"
        f"[bold]Scan ID:[/bold] {result.scan_id}\n"
        f"[bold]Duration:[/bold] {duration:.1f}s\n"
        f"[bold]Version:[/bold] {result.scanner_version}",
        title="[bold cyan]WebScanner Report[/bold cyan]",
        border_style="cyan",
    ))


def _print_summary(result: ScanResult, console: Console) -> None:
    by_severity = result.findings_by_severity
    summary_parts: list[str] = []
    for severity in Severity:
        count = len(by_severity.get(severity, ()))
        color = SEVERITY_COLORS[severity]
        summary_parts.append(f"[{color}]{severity.value.upper()}: {count}[/{color}]")

    console.print(f"\n  {' | '.join(summary_parts)}\n")


def _print_findings_table(result: ScanResult, console: Console) -> None:
    if not result.all_findings:
        console.print("[green]No vulnerabilities found.[/green]")
        return

    table = Table(show_header=True, header_style="bold")
    table.add_column("Severity", width=10)
    table.add_column("Module", width=12)
    table.add_column("Title", min_width=30)
    table.add_column("URL", max_width=50)

    sorted_findings = sorted(
        result.all_findings,
        key=lambda f: list(Severity).index(f.severity),
    )

    for finding in sorted_findings:
        color = SEVERITY_COLORS[finding.severity]
        table.add_row(
            f"[{color}]{finding.severity.value.upper()}[/{color}]",
            finding.module.value,
            finding.title,
            finding.url[:50],
        )

    console.print(table)


def _print_footer(result: ScanResult, console: Console) -> None:
    total = len(result.all_findings)
    by_sev = result.findings_by_severity
    critical = len(by_sev.get(Severity.CRITICAL, ()))
    high = len(by_sev.get(Severity.HIGH, ()))

    console.print()
    if critical > 0 or high > 0:
        console.print(
            f"[bold red]ATTENTION: {critical} CRITICAL and {high} HIGH findings require immediate action.[/bold red]"
        )
    console.print(f"Total findings: {total}")
