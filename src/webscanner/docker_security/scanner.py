"""Docker security scanner — static analysis of Dockerfiles and docker-compose files
plus live inspection of running containers.

Checks for common misconfigurations that expose containers to privilege escalation,
credential leakage, and host breakout attacks.

USE ONLY AGAINST INFRASTRUCTURE YOU OWN OR HAVE EXPLICIT PERMISSION TO TEST.
"""

from __future__ import annotations

import json
import logging
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger("webscanner.docker_security.scanner")

# Regex for secrets in ENV / environment blocks
_SECRET_KEYS = re.compile(
    r"(password|passwd|secret|token|api_key|apikey|auth|credential|private_key|access_key)",
    re.IGNORECASE,
)
_SECRET_VALUE = re.compile(r"=\S+")  # has a non-empty value


@dataclass(frozen=True)
class DockerFinding:
    """Immutable security finding from a Docker scan."""

    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    source: str         # file path or "live:<container_id>"
    evidence: str
    remediation: str


@dataclass(frozen=True)
class DockerScanResult:
    """Immutable result of a full Docker security scan."""

    findings: tuple[DockerFinding, ...]
    dockerfiles_scanned: int
    compose_files_scanned: int
    containers_inspected: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    path: Path = Path("."),
    include_live: bool = False,
    on_progress: Callable[[int, str], None] | None = None,
) -> DockerScanResult:
    """Run a Docker security scan.

    Args:
        path:         Directory to search for Dockerfiles and compose files.
        include_live: If True, also inspect running containers via `docker inspect`.
        on_progress:  Optional callback(pct, message) called at each scan step.

    Returns:
        DockerScanResult with all findings.
    """
    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    findings: list[DockerFinding] = []
    dockerfiles_scanned = 0
    compose_files_scanned = 0
    containers_inspected = 0
    errors: list[str] = []

    emit(0, "Starting Docker security scan…")

    # Discover files first so we can calculate realistic progress
    dockerfiles = _find_dockerfiles(path)
    compose_files = _find_compose_files(path)
    total_static = len(dockerfiles) + len(compose_files)

    emit(
        5,
        f"Found {len(dockerfiles)} Dockerfile(s) and {len(compose_files)} compose file(s)"
        + (f" in {path}" if str(path) != "." else ""),
    )

    # Static analysis — spread progress across 5 → 75 % range
    all_static = [(f, "dockerfile") for f in dockerfiles] + [(f, "compose") for f in compose_files]
    for i, (fpath, ftype) in enumerate(all_static):
        pct = 5 + int(70 * i / max(total_static, 1))
        label = "Dockerfile" if ftype == "dockerfile" else "compose"
        emit(pct, f"Scanning {label}: {fpath.name} ({i + 1}/{total_static})")
        try:
            if ftype == "dockerfile":
                findings.extend(_scan_dockerfile(fpath))
                dockerfiles_scanned += 1
            else:
                findings.extend(_scan_compose(fpath))
                compose_files_scanned += 1
        except Exception as exc:
            errors.append(f"{label} {fpath}: {exc}")
            logger.debug("Error scanning %s: %s", fpath, exc)

    if total_static == 0:
        emit(50, "No Dockerfiles or compose files found in the specified path")

    # Live container inspection — 80 → 95 %
    if include_live:
        emit(80, "Inspecting live containers via docker inspect…")
        live_findings, count, err = _scan_live_containers()
        findings.extend(live_findings)
        containers_inspected = count
        if err:
            errors.append(err)
        if count > 0:
            emit(95, f"Inspected {count} running container(s)")
        else:
            emit(95, "No running containers found")
    else:
        emit(80, "Skipping live container inspection (use --live to enable)")

    finding_word = "finding" if len(findings) == 1 else "findings"
    emit(100, f"Scan complete — {len(findings)} {finding_word} found")

    return DockerScanResult(
        findings=tuple(findings),
        dockerfiles_scanned=dockerfiles_scanned,
        compose_files_scanned=compose_files_scanned,
        containers_inspected=containers_inspected,
        error="; ".join(errors) if errors else None,
    )


# ---------------------------------------------------------------------------
# File discovery
# ---------------------------------------------------------------------------

def _find_dockerfiles(root: Path) -> list[Path]:
    """Find all Dockerfile variants under root."""
    found: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and (
            p.name == "Dockerfile"
            or p.name.startswith("Dockerfile.")
            or p.suffix == ".dockerfile"
        ):
            found.append(p)
    return found


def _find_compose_files(root: Path) -> list[Path]:
    """Find all docker-compose YAML files under root."""
    names = {"docker-compose.yml", "docker-compose.yaml",
             "compose.yml", "compose.yaml"}
    found: list[Path] = []
    for p in root.rglob("*"):
        if p.is_file() and p.name in names:
            found.append(p)
    return found


# ---------------------------------------------------------------------------
# Dockerfile static analysis
# ---------------------------------------------------------------------------

def _scan_dockerfile(path: Path) -> list[DockerFinding]:
    findings: list[DockerFinding] = []
    src = path.read_text(encoding="utf-8", errors="ignore")
    lines = src.splitlines()
    source = str(path)

    has_user = False

    for i, raw_line in enumerate(lines, 1):
        line = raw_line.strip()
        upper = line.upper()

        # FROM with :latest tag
        if upper.startswith("FROM ") and ":LATEST" in upper and " AS " not in upper.split(":LATEST")[1]:
            image = line.split()[1] if len(line.split()) > 1 else line
            findings.append(DockerFinding(
                severity="MEDIUM",
                title="Unpinned image tag (:latest)",
                source=source,
                evidence=f"Line {i}: {line}",
                remediation=(
                    "Pin to a specific digest or version tag, e.g. "
                    "FROM python:3.12.3-slim@sha256:... to ensure reproducible builds."
                ),
            ))

        # USER instruction present
        elif upper.startswith("USER "):
            user_val = line.split(None, 1)[1].strip() if len(line.split(None, 1)) > 1 else ""
            if user_val.lower() not in ("root", "0"):
                has_user = True
            elif user_val.lower() in ("root", "0"):
                findings.append(DockerFinding(
                    severity="HIGH",
                    title="Container explicitly set to run as root",
                    source=source,
                    evidence=f"Line {i}: {line}",
                    remediation="Change USER to a non-root user, e.g. USER 1001.",
                ))

        # ADD instead of COPY (can download remote URLs)
        elif upper.startswith("ADD ") and ("http://" in line or "https://" in line):
            findings.append(DockerFinding(
                severity="LOW",
                title="ADD with remote URL — use COPY or RUN curl instead",
                source=source,
                evidence=f"Line {i}: {line}",
                remediation=(
                    "Use RUN curl --fail -o file URL && ... to make download failures "
                    "explicit, or COPY for local files only."
                ),
            ))

        # Secrets in ENV
        elif upper.startswith("ENV "):
            env_rest = line[4:].strip()
            for part in env_rest.replace("\\", "").split():
                if "=" in part:
                    key, _, val = part.partition("=")
                    if _SECRET_KEYS.search(key) and val:
                        findings.append(DockerFinding(
                            severity="CRITICAL",
                            title="Secret hardcoded in ENV instruction",
                            source=source,
                            evidence=f"Line {i}: ENV {key}=*** (value redacted)",
                            remediation=(
                                "Pass secrets at runtime via --env-file or Docker secrets. "
                                "Never bake credentials into image layers."
                            ),
                        ))

        # Pipe to shell pattern (curl|bash etc.)
        elif upper.startswith("RUN ") and re.search(r"\|\s*(ba)?sh", line, re.IGNORECASE):
            findings.append(DockerFinding(
                severity="HIGH",
                title="Pipe-to-shell pattern in RUN instruction",
                source=source,
                evidence=f"Line {i}: {line[:120]}",
                remediation=(
                    "Download the script, verify its checksum, then execute it. "
                    "Never blindly pipe remote content to a shell."
                ),
            ))

        # SSH exposed
        elif upper.startswith("EXPOSE ") and "22" in line.split():
            findings.append(DockerFinding(
                severity="MEDIUM",
                title="SSH port 22 exposed in image",
                source=source,
                evidence=f"Line {i}: {line}",
                remediation=(
                    "Avoid running SSH inside containers. Use docker exec or "
                    "kubectl exec for interactive access instead."
                ),
            ))

    # No USER instruction at all → runs as root
    if not has_user:
        findings.append(DockerFinding(
            severity="HIGH",
            title="No USER instruction — container runs as root",
            source=source,
            evidence="No USER instruction found in Dockerfile",
            remediation=(
                "Add a USER instruction before CMD/ENTRYPOINT: "
                "RUN useradd -r app && USER app"
            ),
        ))

    return findings


# ---------------------------------------------------------------------------
# docker-compose static analysis
# ---------------------------------------------------------------------------

def _scan_compose(path: Path) -> list[DockerFinding]:
    findings: list[DockerFinding] = []
    source = str(path)

    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f) or {}
    except yaml.YAMLError as exc:
        logger.debug("YAML parse error in %s: %s", path, exc)
        return []

    services: dict = data.get("services", {}) or {}

    for svc_name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        svc_source = f"{source} → service '{svc_name}'"

        # privileged: true
        if svc.get("privileged") is True:
            findings.append(DockerFinding(
                severity="CRITICAL",
                title=f"Service '{svc_name}' runs in privileged mode",
                source=svc_source,
                evidence="privileged: true",
                remediation=(
                    "Remove 'privileged: true'. Grant only the specific Linux "
                    "capabilities needed with cap_add."
                ),
            ))

        # network_mode: host
        if svc.get("network_mode") == "host":
            findings.append(DockerFinding(
                severity="HIGH",
                title=f"Service '{svc_name}' uses host networking",
                source=svc_source,
                evidence="network_mode: host",
                remediation=(
                    "Use bridge networking and map only required ports. "
                    "Host networking bypasses container network isolation."
                ),
            ))

        # Docker socket mounted
        volumes = svc.get("volumes", []) or []
        for vol in volumes:
            vol_str = str(vol)
            if "/var/run/docker.sock" in vol_str:
                findings.append(DockerFinding(
                    severity="CRITICAL",
                    title=f"Service '{svc_name}' mounts Docker socket",
                    source=svc_source,
                    evidence=f"volume: {vol_str}",
                    remediation=(
                        "Mounting the Docker socket gives the container full control "
                        "over the Docker daemon — effectively root on the host. Remove it."
                    ),
                ))

        # Dangerous capabilities
        cap_add = svc.get("cap_add", []) or []
        for cap in cap_add:
            if str(cap).upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"):
                findings.append(DockerFinding(
                    severity="HIGH",
                    title=f"Service '{svc_name}' adds dangerous capability: {cap}",
                    source=svc_source,
                    evidence=f"cap_add: [{cap}]",
                    remediation=(
                        f"Remove or replace cap_add: {cap} with the minimum "
                        "capability required for the workload."
                    ),
                ))

        # Secrets in environment block
        env = svc.get("environment", {}) or {}
        env_items = env.items() if isinstance(env, dict) else []
        for key, val in env_items:
            if _SECRET_KEYS.search(str(key)) and val:
                findings.append(DockerFinding(
                    severity="CRITICAL",
                    title=f"Service '{svc_name}' has secret in environment variable",
                    source=svc_source,
                    evidence=f"environment: {key}=*** (value redacted)",
                    remediation=(
                        "Use Docker secrets (secrets: in compose) or an external "
                        "secrets manager. Never store credentials as plain environment variables."
                    ),
                ))

    return findings


# ---------------------------------------------------------------------------
# Live container inspection
# ---------------------------------------------------------------------------

def _scan_live_containers() -> tuple[list[DockerFinding], int, str | None]:
    """Inspect running containers via `docker inspect`. Returns (findings, count, error)."""
    findings: list[DockerFinding] = []

    # Get running container IDs
    try:
        ids_proc = subprocess.run(
            ["docker", "ps", "-q"],
            capture_output=True, text=True, timeout=10,
        )
    except FileNotFoundError:
        return [], 0, "docker not found — install Docker Desktop"
    except Exception as exc:
        return [], 0, str(exc)

    if ids_proc.returncode != 0:
        return [], 0, f"docker ps failed: {ids_proc.stderr.strip()}"

    container_ids = [cid.strip() for cid in ids_proc.stdout.splitlines() if cid.strip()]
    if not container_ids:
        return [], 0, None

    # Inspect all at once
    try:
        inspect_proc = subprocess.run(
            ["docker", "inspect"] + container_ids,
            capture_output=True, text=True, timeout=20,
        )
    except Exception as exc:
        return [], 0, str(exc)

    if inspect_proc.returncode != 0:
        return [], 0, f"docker inspect failed: {inspect_proc.stderr.strip()}"

    try:
        containers: list[dict] = json.loads(inspect_proc.stdout)
    except json.JSONDecodeError as exc:
        return [], 0, f"JSON parse error: {exc}"

    for ctr in containers:
        cid = ctr.get("Id", "")[:12]
        name = (ctr.get("Name") or cid).lstrip("/")
        host_cfg = ctr.get("HostConfig", {}) or {}
        cfg = ctr.get("Config", {}) or {}
        source = f"live:container/{name}"

        # Privileged
        if host_cfg.get("Privileged") is True:
            findings.append(DockerFinding(
                severity="CRITICAL",
                title=f"Running container '{name}' is privileged",
                source=source,
                evidence=f"HostConfig.Privileged: true  (ID: {cid})",
                remediation="Stop the container and relaunch without --privileged.",
            ))

        # Host networking
        if host_cfg.get("NetworkMode") == "host":
            findings.append(DockerFinding(
                severity="HIGH",
                title=f"Running container '{name}' uses host networking",
                source=source,
                evidence=f"HostConfig.NetworkMode: host  (ID: {cid})",
                remediation="Relaunch with bridge networking and explicit port mapping.",
            ))

        # Docker socket
        binds = host_cfg.get("Binds") or []
        for bind in binds:
            if "/var/run/docker.sock" in str(bind):
                findings.append(DockerFinding(
                    severity="CRITICAL",
                    title=f"Running container '{name}' has Docker socket mounted",
                    source=source,
                    evidence=f"bind: {bind}  (ID: {cid})",
                    remediation="Remove the Docker socket bind mount and restart the container.",
                ))

        # Dangerous caps
        cap_add = host_cfg.get("CapAdd") or []
        for cap in cap_add:
            if str(cap).upper() in ("ALL", "SYS_ADMIN", "SYS_PTRACE", "NET_ADMIN"):
                findings.append(DockerFinding(
                    severity="HIGH",
                    title=f"Running container '{name}' has capability: {cap}",
                    source=source,
                    evidence=f"HostConfig.CapAdd: {cap}  (ID: {cid})",
                    remediation=f"Restart container without --cap-add={cap}.",
                ))

        # Running as root
        user = cfg.get("User") or ""
        if not user or user in ("root", "0", "0:0"):
            findings.append(DockerFinding(
                severity="HIGH",
                title=f"Running container '{name}' runs as root",
                source=source,
                evidence=f"Config.User: '{user or 'root (empty)'}'  (ID: {cid})",
                remediation=(
                    "Add a non-root USER to the Dockerfile and rebuild the image."
                ),
            ))

    return findings, len(containers), None
