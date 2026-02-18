"""FastAPI application for the web vulnerability scanner."""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from sse_starlette.sse import EventSourceResponse

from webscanner.api.models import (
    DockerFindingResponse,
    DockerScanRequest,
    DockerScanResponse,
    K8sFindingResponse,
    K8sScanRequest,
    K8sScanResponse,
    ScanListItem,
    ScanResponse,
    ScanStatus,
    ScanSummary,
    StartScanRequest,
    WiFiAttackRequest,
    WiFiAttackResponse,
    WiFiFindingResponse,
    WiFiNetworkResponse,
    WiFiScanResponse,
    WiFiScanSummary,
)
from webscanner.api.job_store import JobStore
from webscanner.api.store import ScanStore
from webscanner.core.scope import ScopeConfig
from webscanner.orchestrator.engine import ScanConfig, run_scan

logger = logging.getLogger("webscanner.api")

app = FastAPI(
    title="WebScanner API",
    description="Authorized web vulnerability scanner for bug bounty use",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

store = ScanStore()
job_store = JobStore()


@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "version": "0.1.0"}


@app.post("/api/scans", response_model=ScanResponse, status_code=201)
async def start_scan(request: StartScanRequest) -> ScanResponse:
    """Start a new vulnerability scan."""
    scan_id = str(uuid.uuid4())
    record = store.create(scan_id, request.target_url, request.program)

    scope_config = ScopeConfig(
        authorized_domains=frozenset(request.authorized_domains),
        excluded_paths=frozenset(request.excluded_paths),
        bug_bounty_program=request.program,
        authorization_confirmed=True,
    )

    scan_config = ScanConfig(
        target_url=request.target_url,
        scope_config=scope_config,
        rate_limit=request.rate_limit,
        modules=frozenset(request.modules),
        passive_only=request.passive_only,
        timeout_seconds=request.timeout_seconds,
        program_name=request.program,
        contact_email=request.contact_email,
        bruteforce_wordlist=request.bruteforce_wordlist,
        bruteforce_usernames=request.bruteforce_usernames,
        bruteforce_max_attempts=request.bruteforce_max_attempts,
    )

    asyncio.create_task(_run_scan_task(scan_id, scan_config))

    return record.to_response()


@app.get("/api/scans", response_model=list[ScanListItem])
async def list_scans() -> list[ScanListItem]:
    """List all scans."""
    records = store.list_all()
    return [
        ScanListItem(
            scan_id=r.scan_id,
            status=r.status,
            target_url=r.target_url,
            program=r.program,
            created_at=r.created_at,
            finished_at=r.finished_at,
            summary=ScanSummary(**_get_summary(r.findings)),
        )
        for r in records
    ]


@app.get("/api/scans/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str) -> ScanResponse:
    """Get a scan by ID including all findings."""
    record = store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    return record.to_response()


@app.get("/api/scans/{scan_id}/stream")
async def stream_scan(scan_id: str) -> EventSourceResponse:
    """Server-Sent Events stream for live scan updates."""
    record = store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        queue = record.subscribe()
        try:
            yield {"event": "connected", "data": f'{{"scan_id": "{scan_id}"}}'}

            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    import json
                    yield {"event": event["type"], "data": json.dumps(event)}

                    if event["type"] in ("completed", "error"):
                        break
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            record.unsubscribe(queue)

    return EventSourceResponse(event_generator())


@app.delete("/api/scans/{scan_id}", status_code=204)
async def delete_scan(scan_id: str) -> None:
    """Delete a scan record."""
    record = store.get(scan_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id!r} not found")
    if record.status == ScanStatus.RUNNING:
        raise HTTPException(status_code=409, detail="Cannot delete a running scan")


async def _run_scan_task(scan_id: str, config: ScanConfig) -> None:
    """Background task that runs the scan and updates the store."""
    record = store.get(scan_id)
    if not record:
        return

    record.set_status(ScanStatus.RUNNING)
    record.started_at = datetime.now(timezone.utc)

    try:
        result = await run_scan(config, on_progress=record.add_progress)
        record.set_result(result)
        logger.info("Scan %s completed with %d findings", scan_id, len(result.all_findings))
    except Exception as e:
        error_msg = str(e)
        logger.error("Scan %s failed: %s", scan_id, error_msg)
        record.set_error(error_msg)
    finally:
        store.persist(record)


def _get_summary(findings: list) -> dict[str, int]:
    from webscanner.core.types import Severity
    counts = {s.value: 0 for s in Severity}
    for f in findings:
        counts[f.severity.value] += 1
    return counts


@app.get("/api/wifi/scan", response_model=WiFiScanResponse)
async def wifi_scan() -> WiFiScanResponse:
    """Passively scan nearby WiFi networks and return security findings.

    Runs in the background thread pool so it doesn't block the event loop.
    Note: requires the API to run directly on the host (not in Docker) to
    access the host's wireless interface.
    """
    import asyncio
    from webscanner.wifi.scanner import scan_networks
    from webscanner.wifi.analyzer import analyze

    loop = asyncio.get_event_loop()
    scan_result = await loop.run_in_executor(None, scan_networks)
    analysis = await loop.run_in_executor(None, analyze, scan_result)

    if scan_result.error:
        return WiFiScanResponse(
            status="error",
            platform=scan_result.platform,
            scan_duration_seconds=scan_result.scan_duration_seconds,
            error=scan_result.error,
        )

    networks = [
        WiFiNetworkResponse(
            ssid=n.ssid, bssid=n.bssid, signal_dbm=n.signal_dbm,
            channel=n.channel, security=n.security,
            wps_enabled=n.wps_enabled, band=n.band,
        )
        for n in sorted(scan_result.networks, key=lambda x: -x.signal_dbm)
    ]

    findings = [
        WiFiFindingResponse(
            network_ssid=f.network_ssid, bssid=f.bssid,
            severity=f.severity, title=f.title,
            description=f.description, evidence=f.evidence,
            remediation=f.remediation,
        )
        for f in analysis.findings
    ]

    summary = WiFiScanSummary(
        total_networks=analysis.networks_analyzed,
        open=analysis.open_count,
        wep=analysis.wep_count,
        wps_enabled=analysis.wps_count,
        wpa2=analysis.wpa2_count,
        wpa3=analysis.wpa3_count,
        total_findings=len(analysis.findings),
    )

    return WiFiScanResponse(
        status="ok",
        platform=scan_result.platform,
        scan_duration_seconds=scan_result.scan_duration_seconds,
        networks=networks,
        findings=findings,
        summary=summary,
    )


@app.get("/api/infra/status")
async def infra_status() -> dict:
    """Return installation and runtime status of Docker and kubectl."""
    import subprocess

    result: dict = {
        "docker": {"installed": False, "running": False, "version": None, "error": None},
        "kubectl": {"installed": False, "cluster_reachable": False, "version": None, "error": None},
    }

    # --- Docker ---
    try:
        ver = subprocess.run(
            ["docker", "--version"], capture_output=True, text=True, timeout=5
        )
        if ver.returncode == 0:
            result["docker"]["installed"] = True
            result["docker"]["version"] = ver.stdout.strip()
            daemon = subprocess.run(
                ["docker", "info", "--format", "{{.ServerVersion}}"],
                capture_output=True, text=True, timeout=10,
            )
            if daemon.returncode == 0:
                result["docker"]["running"] = True
            else:
                result["docker"]["error"] = "Docker daemon is not running — start Docker Desktop"
        else:
            result["docker"]["error"] = ver.stderr.strip() or "docker command failed"
    except FileNotFoundError:
        result["docker"]["error"] = "Docker not installed — visit https://docs.docker.com/get-docker/"
    except Exception as exc:
        result["docker"]["error"] = str(exc)

    # --- kubectl ---
    try:
        ver = subprocess.run(
            ["kubectl", "version", "--client=true", "--output=json"],
            capture_output=True, text=True, timeout=5,
        )
        if ver.returncode == 0:
            result["kubectl"]["installed"] = True
            import json as _json
            try:
                vdata = _json.loads(ver.stdout)
                result["kubectl"]["version"] = (
                    vdata.get("clientVersion", {}).get("gitVersion", "unknown")
                )
            except Exception:
                result["kubectl"]["version"] = ver.stdout.strip()[:60]
            cluster = subprocess.run(
                ["kubectl", "cluster-info", "--request-timeout=5s"],
                capture_output=True, text=True, timeout=10,
            )
            if cluster.returncode == 0:
                result["kubectl"]["cluster_reachable"] = True
            else:
                result["kubectl"]["error"] = "No cluster reachable — start minikube or connect to a cluster"
        else:
            result["kubectl"]["error"] = ver.stderr.strip() or "kubectl command failed"
    except FileNotFoundError:
        result["kubectl"]["error"] = "kubectl not installed — visit https://kubernetes.io/docs/tasks/tools/"
    except Exception as exc:
        result["kubectl"]["error"] = str(exc)

    return result


@app.post("/api/wifi/attack/start")
async def wifi_attack_start(request: WiFiAttackRequest) -> dict[str, str]:
    """Start a streaming WiFi brute-force attack. Returns {job_id}.

    Connect to /api/jobs/{job_id}/stream to receive SSE progress events.
    The completed event payload contains the full WiFiAttackResponse fields.
    """
    from webscanner.wifi.online_attack import online_attack

    loop = asyncio.get_running_loop()
    job = job_store.create(loop)
    cb = job.make_progress_cb()

    async def _run() -> None:
        try:
            result = await loop.run_in_executor(
                None,
                lambda: online_attack(
                    ssid=request.ssid,
                    wordlist=Path(request.wordlist),
                    max_attempts=request.max_attempts,
                    interface=request.interface,
                    on_progress=cb,
                    on_log=job.log,
                ),
            )
            job.complete({
                "ssid": result.ssid,
                "password_found": result.password_found,
                "password": result.password,
                "attempts": result.attempts,
                "duration_seconds": result.duration_seconds,
                "wordlist_used": result.wordlist_used,
                "error": result.error,
            })
        except Exception as exc:
            logger.exception("WiFi attack job %s failed", job.job_id)
            job.error(str(exc))

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


@app.post("/api/docker/scan", response_model=DockerScanResponse)
async def docker_scan(request: DockerScanRequest) -> DockerScanResponse:
    """Scan a directory for Docker security issues.

    Performs static analysis on Dockerfiles and docker-compose files.
    Optionally inspects running containers when include_live is True.
    """
    from webscanner.docker_security import scanner as docker_scanner

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: docker_scanner.scan(
            path=Path(request.path),
            include_live=request.include_live,
        ),
    )
    return DockerScanResponse(
        dockerfiles_scanned=result.dockerfiles_scanned,
        compose_files_scanned=result.compose_files_scanned,
        containers_inspected=result.containers_inspected,
        findings=[
            DockerFindingResponse(
                severity=f.severity,
                title=f.title,
                source=f.source,
                evidence=f.evidence,
                remediation=f.remediation,
            )
            for f in result.findings
        ],
        error=result.error,
    )


@app.post("/api/k8s/scan", response_model=K8sScanResponse)
async def k8s_scan(request: K8sScanRequest) -> K8sScanResponse:
    """Scan a directory for Kubernetes security issues.

    Performs static analysis on YAML manifest files.
    Optionally queries the live cluster via kubectl when include_live is True.
    """
    from webscanner.kubernetes import scanner as k8s_scanner

    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: k8s_scanner.scan(
            path=Path(request.path),
            include_live=request.include_live,
        ),
    )
    return K8sScanResponse(
        manifests_scanned=result.manifests_scanned,
        live_resources_checked=result.live_resources_checked,
        findings=[
            K8sFindingResponse(
                severity=f.severity,
                title=f.title,
                source=f.source,
                namespace=f.namespace,
                evidence=f.evidence,
                remediation=f.remediation,
            )
            for f in result.findings
        ],
        error=result.error,
    )


# ---------------------------------------------------------------------------
# Shared SSE stream for all job types
# ---------------------------------------------------------------------------

@app.get("/api/jobs/{job_id}/stream")
async def job_stream(job_id: str) -> EventSourceResponse:
    """Stream Server-Sent Events for a running scan job.

    Events:
      progress  {pct: int, message: str}   — progress bar + log line
      log       {message: str}             — log-only line
      completed {result: dict}             — final result, stream closes
      error     {message: str}             — terminal error, stream closes
    """
    import json as _json

    record = job_store.get(job_id)
    if not record:
        raise HTTPException(status_code=404, detail=f"Job {job_id!r} not found")

    async def event_generator() -> AsyncGenerator[dict[str, str], None]:
        queue = record.subscribe()
        try:
            yield {"event": "connected", "data": _json.dumps({"job_id": job_id})}
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {"event": event["type"], "data": _json.dumps(event)}
                    if event["type"] in ("completed", "error"):
                        break
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "{}"}
        finally:
            record.unsubscribe(queue)

    return EventSourceResponse(event_generator())


# ---------------------------------------------------------------------------
# Streaming scan starters  (POST → {job_id}, then GET /api/jobs/{id}/stream)
# ---------------------------------------------------------------------------

@app.get("/api/wifi/known-networks")
async def wifi_known_networks() -> dict[str, list[str]]:
    """Return SSIDs of all saved WiFi networks (no Location Services required).

    Uses networksetup -listpreferredwirelessnetworks, which always returns real
    network names on macOS regardless of Location Services status.
    """
    from webscanner.wifi.scanner import get_preferred_networks
    return {"networks": get_preferred_networks()}


@app.post("/api/wifi/scan/start")
async def wifi_scan_start() -> dict[str, str]:
    """Start a streaming passive WiFi scan. Returns {job_id}."""
    from webscanner.wifi.scanner import scan_networks
    from webscanner.wifi.analyzer import analyze

    loop = asyncio.get_running_loop()
    job = job_store.create(loop)
    cb = job.make_progress_cb()

    async def _run() -> None:
        try:
            scan_result = await loop.run_in_executor(None, lambda: scan_networks(on_progress=cb))
            cb(90, "Analyzing security…")
            analysis = await loop.run_in_executor(None, lambda: analyze(scan_result))
            cb(100, f"Analysis complete — {len(analysis.findings)} finding(s)")

            networks = [
                {
                    "ssid": n.ssid, "bssid": n.bssid, "signal_dbm": n.signal_dbm,
                    "channel": n.channel, "security": n.security,
                    "wps_enabled": n.wps_enabled, "band": n.band,
                }
                for n in sorted(scan_result.networks, key=lambda x: -x.signal_dbm)
            ]
            findings = [
                {
                    "network_ssid": f.network_ssid, "bssid": f.bssid,
                    "severity": f.severity, "title": f.title,
                    "description": f.description, "evidence": f.evidence,
                    "remediation": f.remediation,
                }
                for f in analysis.findings
            ]
            summary = {
                "total_networks": analysis.networks_analyzed,
                "open": analysis.open_count,
                "wep": analysis.wep_count,
                "wps_enabled": analysis.wps_count,
                "wpa2": analysis.wpa2_count,
                "wpa3": analysis.wpa3_count,
                "total_findings": len(analysis.findings),
            }
            job.complete({
                "status": "ok" if not scan_result.error else "error",
                "platform": scan_result.platform,
                "scan_duration_seconds": scan_result.scan_duration_seconds,
                "networks": networks,
                "findings": findings,
                "summary": summary,
                "error": scan_result.error,
            })
        except Exception as exc:
            logger.exception("WiFi scan job %s failed", job.job_id)
            job.error(str(exc))

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


@app.post("/api/docker/scan/start")
async def docker_scan_start(request: DockerScanRequest) -> dict[str, str]:
    """Start a streaming Docker security scan. Returns {job_id}."""
    from webscanner.docker_security import scanner as docker_scanner

    loop = asyncio.get_running_loop()
    job = job_store.create(loop)
    cb = job.make_progress_cb()

    async def _run() -> None:
        try:
            result = await loop.run_in_executor(
                None,
                lambda: docker_scanner.scan(
                    path=Path(request.path),
                    include_live=request.include_live,
                    on_progress=cb,
                ),
            )
            job.complete({
                "dockerfiles_scanned": result.dockerfiles_scanned,
                "compose_files_scanned": result.compose_files_scanned,
                "containers_inspected": result.containers_inspected,
                "findings": [
                    {
                        "severity": f.severity, "title": f.title,
                        "source": f.source, "evidence": f.evidence,
                        "remediation": f.remediation,
                    }
                    for f in result.findings
                ],
                "error": result.error,
            })
        except Exception as exc:
            logger.exception("Docker scan job %s failed", job.job_id)
            job.error(str(exc))

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


@app.post("/api/k8s/scan/start")
async def k8s_scan_start(request: K8sScanRequest) -> dict[str, str]:
    """Start a streaming Kubernetes security scan. Returns {job_id}."""
    from webscanner.kubernetes import scanner as k8s_scanner

    loop = asyncio.get_running_loop()
    job = job_store.create(loop)
    cb = job.make_progress_cb()

    async def _run() -> None:
        try:
            result = await loop.run_in_executor(
                None,
                lambda: k8s_scanner.scan(
                    path=Path(request.path),
                    include_live=request.include_live,
                    on_progress=cb,
                ),
            )
            job.complete({
                "manifests_scanned": result.manifests_scanned,
                "live_resources_checked": result.live_resources_checked,
                "findings": [
                    {
                        "severity": f.severity, "title": f.title,
                        "source": f.source, "namespace": f.namespace,
                        "evidence": f.evidence, "remediation": f.remediation,
                    }
                    for f in result.findings
                ],
                "error": result.error,
            })
        except Exception as exc:
            logger.exception("K8s scan job %s failed", job.job_id)
            job.error(str(exc))

    asyncio.create_task(_run())
    return {"job_id": job.job_id}


def create_app() -> FastAPI:
    return app


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("webscanner.api.app:app", host="0.0.0.0", port=8000, reload=True)
