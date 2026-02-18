"""CLI entry point for the web vulnerability scanner."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Annotated, Optional

import typer
import yaml
from rich.console import Console
from rich.table import Table

from webscanner.core.exceptions import ScannerError, ScopeValidationError, ScopeViolationError
from webscanner.core.logging import setup_logging
from webscanner.core.scope import ScopeConfig
from webscanner.orchestrator.engine import ScanConfig, run_scan
from webscanner.reporting.html_reporter import write_html_report
from webscanner.reporting.json_reporter import write_json_report
from webscanner.reporting.terminal_reporter import print_terminal_report

app = typer.Typer(
    name="webscanner",
    help="Authorized web vulnerability scanner for bug bounty use.",
    no_args_is_help=True,
)

console = Console()

_VALID_SCAN_MODULES = {"recon", "headers", "owasp", "api", "bruteforce"}


# ---------------------------------------------------------------------------
# webscanner scan  — web vulnerability scan
# ---------------------------------------------------------------------------

@app.command()
def scan(
    target_url: Annotated[str, typer.Argument(help="Target URL to scan")],
    scope_file: Annotated[Path, typer.Option("--scope-file", help="YAML scope file with authorized domains")] = ...,  # type: ignore[assignment]
    program: Annotated[str, typer.Option("--program", help="Bug bounty program name")] = ...,  # type: ignore[assignment]
    modules: Annotated[str, typer.Option("--modules", help="Comma-separated modules: recon,headers,owasp,api,bruteforce")] = "recon,headers,owasp,api",
    rate_limit: Annotated[float, typer.Option("--rate-limit", help="Requests per second")] = 5.0,
    output_format: Annotated[str, typer.Option("--output-format", help="Output format: terminal, json, html")] = "terminal",
    output_file: Annotated[Optional[Path], typer.Option("--output-file", help="Output file path")] = None,
    passive_only: Annotated[bool, typer.Option("--passive-only", help="Only run passive checks")] = False,
    timeout: Annotated[int, typer.Option("--timeout", help="Per-request timeout in seconds")] = 10,
    contact_email: Annotated[str, typer.Option("--contact", help="Contact email for scanner identification")] = "",
    wordlist: Annotated[Optional[Path], typer.Option("--wordlist", help="Password wordlist for brute force module")] = None,
    usernames: Annotated[Optional[Path], typer.Option("--usernames", help="Username wordlist for brute force module")] = None,
    max_attempts: Annotated[int, typer.Option("--max-attempts", help="Max brute force attempts per endpoint")] = 300,
    verbose: Annotated[bool, typer.Option("--verbose", help="Enable verbose logging")] = False,
) -> None:
    """Scan a target URL for web vulnerabilities within authorized scope.

    Add 'bruteforce' to --modules to also test login forms and HTTP auth endpoints.

    Examples:

      # Full scan (all modules)
      webscanner scan https://example.com --scope-file scope.yaml --program my-bounty

      # Headers + brute force only, with custom wordlist
      webscanner scan https://example.com --scope-file scope.yaml --program my-bounty \\
        --modules headers,bruteforce --wordlist wordlists/rockyou.txt

      # Passive only (no active probes, no brute force)
      webscanner scan https://example.com --scope-file scope.yaml --program my-bounty \\
        --passive-only
    """
    setup_logging(verbose=verbose)

    if rate_limit <= 0:
        console.print("[red]Error: --rate-limit must be positive[/red]")
        raise typer.Exit(code=1)

    if output_format in ("json", "html") and output_file is None:
        console.print(f"[red]Error: --output-file required for {output_format} format[/red]")
        raise typer.Exit(code=1)

    try:
        scope_config = _load_scope_file(scope_file, program)
    except (FileNotFoundError, ValueError, yaml.YAMLError) as e:
        console.print(f"[red]Scope file error: {e}[/red]")
        raise typer.Exit(code=1)

    module_set = frozenset(m.strip() for m in modules.split(","))
    invalid = module_set - _VALID_SCAN_MODULES
    if invalid:
        console.print(f"[red]Unknown modules: {invalid}. Valid: {_VALID_SCAN_MODULES}[/red]")
        raise typer.Exit(code=1)

    scan_config = ScanConfig(
        target_url=target_url,
        scope_config=scope_config,
        rate_limit=rate_limit,
        modules=module_set,
        passive_only=passive_only,
        timeout_seconds=timeout,
        program_name=program,
        contact_email=contact_email,
        bruteforce_wordlist=str(wordlist) if wordlist else "",
        bruteforce_usernames=str(usernames) if usernames else "",
        bruteforce_max_attempts=max_attempts,
    )

    try:
        console.print(f"[cyan]Starting scan against {target_url}...[/cyan]")
        result = asyncio.run(run_scan(scan_config))

        if output_format == "json":
            write_json_report(result, output_file)  # type: ignore[arg-type]
            console.print(f"[green]JSON report written to {output_file}[/green]")
        elif output_format == "html":
            write_html_report(result, output_file)  # type: ignore[arg-type]
            console.print(f"[green]HTML report written to {output_file}[/green]")
        else:
            print_terminal_report(result, console)

    except (ScopeValidationError, ScopeViolationError) as e:
        console.print(f"[red]Scope error: {e}[/red]")
        raise typer.Exit(code=1)
    except ScannerError as e:
        console.print(f"[red]Scanner error: {e}[/red]")
        raise typer.Exit(code=1)


# ---------------------------------------------------------------------------
# webscanner wifi  — passive WiFi security scan
# ---------------------------------------------------------------------------

@app.command()
def wifi(
    output_format: Annotated[str, typer.Option("--output-format", help="terminal or json")] = "terminal",
    output_file: Annotated[Optional[Path], typer.Option("--output-file", help="Save output to file")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Passively scan nearby WiFi networks and report security weaknesses.

    Identifies open networks, WEP encryption, WPS-enabled APs, and
    other wireless security misconfigurations. No packets are injected.

    Examples:

      webscanner wifi
      webscanner wifi --output-format json --output-file wifi-report.json
    """
    setup_logging(verbose=verbose)

    from webscanner.wifi.scanner import scan_networks
    from webscanner.wifi.analyzer import analyze

    console.print("[cyan]Scanning nearby WiFi networks...[/cyan]")
    scan_result = scan_networks()

    if scan_result.error:
        console.print(f"[red]WiFi scan error: {scan_result.error}[/red]")
        raise typer.Exit(code=1)

    if not scan_result.networks:
        console.print("[yellow]No networks found. Are you near any WiFi networks?[/yellow]")
        raise typer.Exit(code=0)

    analysis = analyze(scan_result)

    if output_format == "json":
        data = {
            "networks": [
                {
                    "ssid": n.ssid, "bssid": n.bssid, "signal_dbm": n.signal_dbm,
                    "channel": n.channel, "security": n.security,
                    "wps_enabled": n.wps_enabled, "band": n.band,
                }
                for n in scan_result.networks
            ],
            "findings": [
                {
                    "ssid": f.network_ssid, "bssid": f.bssid,
                    "severity": f.severity, "title": f.title,
                    "description": f.description, "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in analysis.findings
            ],
            "summary": {
                "total_networks": analysis.networks_analyzed,
                "open": analysis.open_count,
                "wep": analysis.wep_count,
                "wps_enabled": analysis.wps_count,
                "wpa2": analysis.wpa2_count,
                "wpa3": analysis.wpa3_count,
                "total_findings": len(analysis.findings),
            },
        }
        out = json.dumps(data, indent=2)
        if output_file:
            output_file.write_text(out)
            console.print(f"[green]Report saved to {output_file}[/green]")
        else:
            console.print(out)
        return

    # Terminal output
    console.print(f"\n[bold]Networks discovered:[/bold] {analysis.networks_analyzed}  "
                  f"  Open: [red]{analysis.open_count}[/red]  "
                  f"WEP: [red]{analysis.wep_count}[/red]  "
                  f"WPS: [yellow]{analysis.wps_count}[/yellow]  "
                  f"WPA3: [green]{analysis.wpa3_count}[/green]\n")

    table = Table(title="Nearby WiFi Networks", show_lines=True)
    table.add_column("SSID", style="cyan", no_wrap=True)
    table.add_column("BSSID", style="dim")
    table.add_column("Signal", justify="right")
    table.add_column("Ch", justify="center")
    table.add_column("Band", justify="center")
    table.add_column("Security", style="yellow")
    table.add_column("WPS", justify="center")

    for n in sorted(scan_result.networks, key=lambda x: -x.signal_dbm):
        sec_color = (
            "red" if "WEP" in n.security.upper() or not n.security or n.security == "Open"
            else "green" if "WPA3" in n.security.upper()
            else "yellow"
        )
        table.add_row(
            n.ssid,
            n.bssid,
            f"{n.signal_dbm} dBm",
            str(n.channel),
            n.band,
            f"[{sec_color}]{n.security}[/{sec_color}]",
            "[red]YES[/red]" if n.wps_enabled else "[dim]no[/dim]",
        )

    console.print(table)

    if analysis.findings:
        console.print(f"\n[bold red]Security Findings ({len(analysis.findings)}):[/bold red]\n")
        for f in analysis.findings:
            sev_color = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}.get(f.severity, "white")
            console.print(f"  [{sev_color}][{f.severity.upper()}][/{sev_color}] {f.title}")
            console.print(f"         SSID: {f.network_ssid}  BSSID: {f.bssid}")
            console.print(f"         {f.evidence}")
            console.print(f"         [dim]Fix: {f.remediation[:120]}...[/dim]\n")
    else:
        console.print("\n[green]No security issues found.[/green]")


# ---------------------------------------------------------------------------
# webscanner wifi-audit  — dictionary attack on captured WPA handshake
# ---------------------------------------------------------------------------

@app.command(name="wifi-audit")
def wifi_audit(
    capture: Annotated[Path, typer.Argument(help="WPA handshake capture file (.cap or .hc22000)")],
    wordlist: Annotated[Optional[Path], typer.Option("--wordlist", "-w", help="Password wordlist")] = None,
    bssid: Annotated[Optional[str], typer.Option("--bssid", "-b", help="Target AP BSSID (for multi-AP captures)")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Test WPA/WPA2 password strength against a captured handshake.

    Runs a dictionary attack on a .cap or .hc22000 file using aircrack-ng
    or hashcat. Use this to verify that your own network's password cannot
    be cracked from a publicly available wordlist.

    Capture a handshake first (Linux with monitor-mode capable card):

      sudo airmon-ng start wlan0
      sudo airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w capture wlan0mon
      # reconnect a client device to trigger the handshake
      sudo airmon-ng stop wlan0mon

    Then audit:

      webscanner wifi-audit capture-01.cap --wordlist wordlists/rockyou.txt
      webscanner wifi-audit capture-01.cap  # uses built-in wifi-passwords.txt
    """
    setup_logging(verbose=verbose)

    from webscanner.wifi.wpa_audit import audit_capture

    console.print(f"[cyan]Auditing {capture.name} ...[/cyan]")
    if wordlist:
        console.print(f"[dim]Wordlist: {wordlist}[/dim]")
    else:
        console.print("[dim]Wordlist: built-in wifi-passwords.txt (run download_wordlists.py for rockyou)[/dim]")

    result = audit_capture(capture, wordlist, bssid)

    if result.error:
        console.print(f"\n[red]Audit error: {result.error}[/red]")
        raise typer.Exit(code=1)

    console.print(f"\n[dim]Tool: {result.tool_used} | Keys tested: {result.keys_tested:,} | "
                  f"Duration: {result.duration_seconds:.1f}s[/dim]")

    if result.password_found:
        console.print(f"\n[bold red]PASSWORD FOUND: {result.password}[/bold red]")
        console.print(
            "\n[yellow]Your WiFi password was cracked from a public wordlist. "
            "Change it immediately to a random 16+ character passphrase.[/yellow]"
        )
    else:
        console.print("\n[green]Password not found in wordlist.[/green]")
        console.print("[dim]Consider testing with a larger wordlist (rockyou.txt) or "
                      "rule-based attacks with hashcat.[/dim]")


# ---------------------------------------------------------------------------
# webscanner wifi-attack  — online WPA brute-force against a live SSID
# ---------------------------------------------------------------------------

@app.command(name="wifi-attack")
def wifi_attack(
    ssid: Annotated[str, typer.Argument(help="Target WiFi SSID to attack")],
    wordlist: Annotated[Optional[Path], typer.Option("--wordlist", "-w", help="Password wordlist")] = None,
    max_attempts: Annotated[int, typer.Option("--max-attempts", help="Max passwords to try")] = 50,
    interface: Annotated[str, typer.Option("--interface", help="WiFi interface (default: en0)")] = "en0",
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Online WPA brute-force — tries connecting to a WiFi SSID with each password.

    USE ONLY AGAINST NETWORKS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST.

    Note: ~8–15 seconds per attempt. Temporarily disconnects your current WiFi
    during each try, then reconnects afterward.

    Examples:

      webscanner wifi-attack "MyHomeNetwork" --wordlist wordlists/wifi-passwords.txt
      webscanner wifi-attack "TargetNet" --max-attempts 20
    """
    setup_logging(verbose=verbose)

    from webscanner.wifi.online_attack import online_attack

    console.print(f"\n[bold yellow]⚠  Authorized testing only — USE ONLY ON NETWORKS YOU OWN[/bold yellow]")
    console.print(f"[cyan]Target SSID:[/cyan] {ssid}")
    console.print(f"[cyan]Max attempts:[/cyan] {max_attempts}  (~{max_attempts * 12 // 60}–{max_attempts * 15 // 60} min)")
    console.print(f"[dim]Your WiFi will reconnect automatically after each attempt.[/dim]\n")

    result = online_attack(ssid, wordlist, max_attempts, interface)

    if result.error:
        console.print(f"[red]Error: {result.error}[/red]")
        raise typer.Exit(code=1)

    console.print(
        f"\n[dim]Attempts: {result.attempts} | Duration: {result.duration_seconds:.0f}s "
        f"| Wordlist: {result.wordlist_used}[/dim]"
    )

    if result.password_found:
        console.print(f"\n[bold red]PASSWORD FOUND: {result.password}[/bold red]")
        console.print("[yellow]Change this password immediately to a strong random passphrase.[/yellow]")
    else:
        console.print(f"\n[green]Password not found in {result.attempts} attempts.[/green]")
        console.print("[dim]Try a larger wordlist (rockyou.txt) for more coverage.[/dim]")


# ---------------------------------------------------------------------------
# webscanner docker  — Docker security scan
# ---------------------------------------------------------------------------

@app.command(name="docker")
def docker_scan(
    path: Annotated[Path, typer.Option("--path", help="Directory to scan (default: current dir)")] = Path("."),
    live: Annotated[bool, typer.Option("--live", help="Also inspect running containers via docker inspect")] = False,
    output_format: Annotated[str, typer.Option("--output-format")] = "terminal",
    output_file: Annotated[Optional[Path], typer.Option("--output-file")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Scan Dockerfiles and docker-compose files for security misconfigurations.

    Checks for: root user, privileged mode, secrets in ENV, pipe-to-shell,
    Docker socket mounts, dangerous capabilities, unpinned images.

    Examples:

      webscanner docker                          # scan current directory
      webscanner docker --path /my/project       # scan specific directory
      webscanner docker --live                   # also inspect running containers
      webscanner docker --output-format json --output-file docker-report.json
    """
    setup_logging(verbose=verbose)

    from webscanner.docker_security.scanner import scan as docker_scan_fn

    console.print(f"[cyan]Scanning {path.resolve()} for Docker security issues...[/cyan]")
    if live:
        console.print("[dim]Live container inspection enabled.[/dim]")

    result = docker_scan_fn(path=path.resolve(), include_live=live)

    if output_format == "json" and output_file:
        import json as _json
        data = {
            "dockerfiles_scanned": result.dockerfiles_scanned,
            "compose_files_scanned": result.compose_files_scanned,
            "containers_inspected": result.containers_inspected,
            "findings": [
                {"severity": f.severity, "title": f.title, "source": f.source,
                 "evidence": f.evidence, "remediation": f.remediation}
                for f in result.findings
            ],
        }
        output_file.write_text(_json.dumps(data, indent=2))
        console.print(f"[green]Report written to {output_file}[/green]")
        return

    # Terminal output
    console.print(
        f"\n[bold]Scanned:[/bold] {result.dockerfiles_scanned} Dockerfile(s), "
        f"{result.compose_files_scanned} compose file(s), "
        f"{result.containers_inspected} live container(s)"
    )
    if result.error:
        console.print(f"[yellow]Warnings: {result.error}[/yellow]")

    if not result.findings:
        console.print("\n[green]No security issues found.[/green]")
        return

    console.print(f"\n[bold red]Findings ({len(result.findings)}):[/bold red]\n")
    _print_findings_table(
        [(f.severity, f.title, f.source, f.evidence, f.remediation) for f in result.findings]
    )


# ---------------------------------------------------------------------------
# webscanner k8s  — Kubernetes security scan
# ---------------------------------------------------------------------------

@app.command(name="k8s")
def k8s_scan(
    path: Annotated[Path, typer.Option("--path", help="Directory to scan for YAML manifests")] = Path("."),
    live: Annotated[bool, typer.Option("--live", help="Also query running cluster via kubectl")] = False,
    output_format: Annotated[str, typer.Option("--output-format")] = "terminal",
    output_file: Annotated[Optional[Path], typer.Option("--output-file")] = None,
    verbose: Annotated[bool, typer.Option("--verbose")] = False,
) -> None:
    """Scan Kubernetes YAML manifests for security misconfigurations.

    Checks for: privileged containers, root UID, hostPID/hostNetwork/hostIPC,
    hostPath volumes, missing resource limits, wildcard RBAC, default service accounts.

    Examples:

      webscanner k8s                             # scan current directory
      webscanner k8s --path /my/k8s/manifests   # scan specific directory
      webscanner k8s --live                      # also query running cluster
      webscanner k8s --output-format json --output-file k8s-report.json
    """
    setup_logging(verbose=verbose)

    from webscanner.kubernetes.scanner import scan as k8s_scan_fn

    console.print(f"[cyan]Scanning {path.resolve()} for Kubernetes security issues...[/cyan]")
    if live:
        console.print("[dim]Live cluster inspection enabled.[/dim]")

    result = k8s_scan_fn(path=path.resolve(), include_live=live)

    if output_format == "json" and output_file:
        import json as _json
        data = {
            "manifests_scanned": result.manifests_scanned,
            "live_resources_checked": result.live_resources_checked,
            "findings": [
                {"severity": f.severity, "title": f.title, "source": f.source,
                 "namespace": f.namespace, "evidence": f.evidence, "remediation": f.remediation}
                for f in result.findings
            ],
        }
        output_file.write_text(_json.dumps(data, indent=2))
        console.print(f"[green]Report written to {output_file}[/green]")
        return

    # Terminal output
    console.print(
        f"\n[bold]Scanned:[/bold] {result.manifests_scanned} manifest(s), "
        f"{result.live_resources_checked} live resources"
    )
    if result.error:
        console.print(f"[yellow]Warnings: {result.error}[/yellow]")

    if not result.findings:
        console.print("\n[green]No security issues found.[/green]")
        return

    console.print(f"\n[bold red]Findings ({len(result.findings)}):[/bold red]\n")
    _print_findings_table(
        [(f.severity, f.title, f"{f.source} [{f.namespace}]", f.evidence, f.remediation)
         for f in result.findings]
    )


# ---------------------------------------------------------------------------
# webscanner wordlists  — download external wordlists
# ---------------------------------------------------------------------------

@app.command()
def wordlists(
    skip_rockyou: Annotated[bool, typer.Option("--skip-rockyou")] = False,
) -> None:
    """Download external wordlists (SecLists, rockyou) for deep scanning."""
    import subprocess
    script = Path(__file__).parent.parent.parent.parent / "wordlists" / "download_wordlists.py"
    if not script.exists():
        console.print(f"[red]Download script not found: {script}[/red]")
        raise typer.Exit(code=1)
    cmd = [sys.executable, str(script)]
    if skip_rockyou:
        cmd.append("--skip-rockyou")
    subprocess.run(cmd, check=False)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _print_findings_table(rows: list[tuple[str, str, str, str, str]]) -> None:
    """Print severity-coloured findings: (severity, title, source, evidence, remediation)."""
    _sev_color = {
        "CRITICAL": "bold red",
        "HIGH": "red",
        "MEDIUM": "yellow",
        "LOW": "blue",
        "INFO": "dim",
    }
    for severity, title, source, evidence, remediation in rows:
        color = _sev_color.get(severity.upper(), "white")
        console.print(f"  [{color}][{severity}][/{color}]  {title}")
        console.print(f"         [dim]Source:     {source}[/dim]")
        console.print(f"         [dim]Evidence:   {evidence}[/dim]")
        console.print(f"         [dim]Fix:        {remediation[:140]}[/dim]\n")


def _load_scope_file(path: Path, program: str) -> ScopeConfig:
    """Load and validate a scope YAML file."""
    if not path.exists():
        raise FileNotFoundError(f"Scope file not found: {path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    if not isinstance(data, dict):
        raise ValueError("Scope file must be a YAML mapping")

    authorized_domains = data.get("authorized_domains", [])
    if not authorized_domains:
        raise ValueError("scope file must contain 'authorized_domains'")

    authorization_confirmed = data.get("authorization_confirmed", False)
    if not authorization_confirmed:
        raise ValueError(
            "scope file must contain 'authorization_confirmed: true'. "
            "This confirms you have explicit authorization to scan the target."
        )

    return ScopeConfig(
        authorized_domains=frozenset(authorized_domains),
        excluded_paths=frozenset(data.get("excluded_paths", [])),
        bug_bounty_program=program,
        authorization_confirmed=True,
    )


def run() -> None:
    """Entry point for the CLI."""
    app()


if __name__ == "__main__":
    run()
