"""Kubernetes security scanner — static analysis of YAML manifests plus
live cluster inspection via kubectl.

Checks for common misconfigurations that allow privilege escalation,
host access, and over-permissioned RBAC.

USE ONLY AGAINST CLUSTERS AND MANIFESTS YOU OWN OR HAVE PERMISSION TO TEST.
"""

from __future__ import annotations

import json
import logging
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import yaml

logger = logging.getLogger("webscanner.kubernetes.scanner")


@dataclass(frozen=True)
class K8sFinding:
    """Immutable security finding from a Kubernetes scan."""

    severity: str       # CRITICAL / HIGH / MEDIUM / LOW / INFO
    title: str
    source: str         # file path or "live:<resource>"
    namespace: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class K8sScanResult:
    """Immutable result of a full Kubernetes security scan."""

    findings: tuple[K8sFinding, ...]
    manifests_scanned: int
    live_resources_checked: int
    error: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan(
    path: Path = Path("."),
    include_live: bool = False,
    on_progress: Callable[[int, str], None] | None = None,
) -> K8sScanResult:
    """Run a Kubernetes security scan.

    Args:
        path:         Directory to walk for *.yaml / *.yml manifest files.
        include_live: If True, also query a running cluster via kubectl.
        on_progress:  Optional callback(pct, message) called at each scan step.

    Returns:
        K8sScanResult with all findings.
    """
    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    findings: list[K8sFinding] = []
    manifests_scanned = 0
    live_resources_checked = 0
    errors: list[str] = []

    emit(0, "Starting Kubernetes security scan…")

    # Discover manifests first for accurate progress
    manifests = _find_manifests(path)
    total = len(manifests)
    emit(5, f"Found {total} YAML manifest file(s)" + (f" in {path}" if str(path) != "." else ""))

    # Static manifest analysis — spread 5 → 75 %
    for i, manifest in enumerate(manifests):
        pct = 5 + int(70 * i / max(total, 1))
        emit(pct, f"Scanning {manifest.name} ({i + 1}/{total})")
        try:
            found, count = _scan_manifest(manifest)
            findings.extend(found)
            manifests_scanned += count
        except Exception as exc:
            errors.append(f"{manifest}: {exc}")
            logger.debug("Error scanning manifest %s: %s", manifest, exc)

    if total == 0:
        emit(50, "No YAML manifests found in the specified path")

    # Live cluster inspection — 80 → 95 %
    if include_live:
        emit(80, "Querying live cluster via kubectl…")
        live_findings, count, err = _scan_live_cluster()
        findings.extend(live_findings)
        live_resources_checked = count
        if err:
            errors.append(err)
        emit(95, f"Checked {count} live resource(s)")
    else:
        emit(80, "Skipping live cluster inspection (use --live to enable)")

    finding_word = "finding" if len(findings) == 1 else "findings"
    emit(100, f"Scan complete — {len(findings)} {finding_word} found")

    return K8sScanResult(
        findings=tuple(findings),
        manifests_scanned=manifests_scanned,
        live_resources_checked=live_resources_checked,
        error="; ".join(errors) if errors else None,
    )


# ---------------------------------------------------------------------------
# Manifest discovery
# ---------------------------------------------------------------------------

def _find_manifests(root: Path) -> list[Path]:
    found: list[Path] = []
    for p in root.rglob("*.yaml"):
        found.append(p)
    for p in root.rglob("*.yml"):
        found.append(p)
    return found


# ---------------------------------------------------------------------------
# Static YAML manifest analysis
# ---------------------------------------------------------------------------

def _scan_manifest(path: Path) -> tuple[list[K8sFinding], int]:
    """Scan a single YAML file (may contain multiple documents). Returns (findings, doc_count)."""
    findings: list[K8sFinding] = []
    source = str(path)
    doc_count = 0

    with open(path, encoding="utf-8", errors="ignore") as f:
        raw = f.read()

    # A file can contain multiple YAML documents separated by ---
    for doc in yaml.safe_load_all(raw):
        if not isinstance(doc, dict):
            continue
        kind = doc.get("kind", "")
        if not kind:
            continue
        doc_count += 1
        ns = doc.get("metadata", {}).get("namespace", "default") or "default"
        name = doc.get("metadata", {}).get("name", "<unnamed>")

        if kind in ("Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet", "Job", "CronJob"):
            findings.extend(_check_workload(doc, source, ns, name, kind))

        elif kind in ("ClusterRoleBinding", "RoleBinding"):
            findings.extend(_check_rbac_binding(doc, source, ns, name, kind))

        elif kind == "ClusterRole":
            findings.extend(_check_cluster_role(doc, source, ns, name))

    return findings, doc_count


def _get_pod_spec(doc: dict) -> dict:
    """Extract pod spec regardless of wrapping resource kind."""
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec", {}) or {}
    # Deployment, DaemonSet, etc.
    if kind == "CronJob":
        return (doc.get("spec", {}) or {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {}) or {}
    return (doc.get("spec", {}) or {}).get("template", {}).get("spec", {}) or {}


def _check_workload(doc: dict, source: str, ns: str, name: str, kind: str) -> list[K8sFinding]:
    findings: list[K8sFinding] = []
    spec = _get_pod_spec(doc)

    resource_label = f"{kind}/{name}"

    # hostPID / hostNetwork / hostIPC
    for flag in ("hostPID", "hostNetwork", "hostIPC"):
        if spec.get(flag) is True:
            findings.append(K8sFinding(
                severity="HIGH",
                title=f"{resource_label} uses {flag}: true",
                source=source, namespace=ns,
                evidence=f"spec.{flag}: true",
                remediation=f"Remove {flag}: true from the pod spec.",
            ))

    containers: list[dict] = (
        spec.get("containers", [])
        + spec.get("initContainers", [])
    )

    for ctr in containers:
        if not isinstance(ctr, dict):
            continue
        ctr_name = ctr.get("name", "<unnamed>")
        sc = ctr.get("securityContext", {}) or {}

        # privileged
        if sc.get("privileged") is True:
            findings.append(K8sFinding(
                severity="CRITICAL",
                title=f"Container '{ctr_name}' in {resource_label} is privileged",
                source=source, namespace=ns,
                evidence="securityContext.privileged: true",
                remediation="Remove privileged: true. Use specific capabilities instead.",
            ))

        # runAsRoot
        run_as_user = sc.get("runAsUser")
        run_as_non_root = sc.get("runAsNonRoot")
        if run_as_user == 0:
            findings.append(K8sFinding(
                severity="HIGH",
                title=f"Container '{ctr_name}' in {resource_label} runs as UID 0 (root)",
                source=source, namespace=ns,
                evidence="securityContext.runAsUser: 0",
                remediation="Set runAsUser to a non-zero UID and runAsNonRoot: true.",
            ))
        elif run_as_non_root is not True and run_as_user is None:
            findings.append(K8sFinding(
                severity="MEDIUM",
                title=f"Container '{ctr_name}' in {resource_label} may run as root",
                source=source, namespace=ns,
                evidence="No runAsNonRoot: true or runAsUser set",
                remediation="Set securityContext.runAsNonRoot: true and a non-zero runAsUser.",
            ))

        # readOnlyRootFilesystem
        if sc.get("readOnlyRootFilesystem") is not True:
            findings.append(K8sFinding(
                severity="MEDIUM",
                title=f"Container '{ctr_name}' in {resource_label} has writable root filesystem",
                source=source, namespace=ns,
                evidence="securityContext.readOnlyRootFilesystem not set to true",
                remediation="Set securityContext.readOnlyRootFilesystem: true.",
            ))

        # Missing resource limits
        resources = ctr.get("resources", {}) or {}
        if not resources.get("limits"):
            findings.append(K8sFinding(
                severity="MEDIUM",
                title=f"Container '{ctr_name}' in {resource_label} has no resource limits",
                source=source, namespace=ns,
                evidence="resources.limits not set",
                remediation=(
                    "Set resources.limits.cpu and resources.limits.memory to prevent "
                    "resource exhaustion (DoS)."
                ),
            ))

    # hostPath volumes
    volumes = spec.get("volumes", []) or []
    for vol in volumes:
        if isinstance(vol, dict) and "hostPath" in vol:
            hp = vol.get("hostPath", {})
            host_path_val = hp.get("path", "") if isinstance(hp, dict) else ""
            findings.append(K8sFinding(
                severity="HIGH",
                title=f"{resource_label} mounts hostPath volume",
                source=source, namespace=ns,
                evidence=f"volumes[{vol.get('name', '')}].hostPath.path: {host_path_val}",
                remediation=(
                    "Replace hostPath with a PersistentVolumeClaim. "
                    "hostPath mounts give pods direct access to the host filesystem."
                ),
            ))

    # Default service account
    sa = spec.get("serviceAccountName", "")
    if sa in ("default", "") and doc.get("kind") not in ("Job", "CronJob"):
        findings.append(K8sFinding(
            severity="MEDIUM",
            title=f"{resource_label} uses the default service account",
            source=source, namespace=ns,
            evidence=f"serviceAccountName: '{sa or 'default'}'",
            remediation=(
                "Create a dedicated service account with only the permissions the "
                "workload needs and reference it in serviceAccountName."
            ),
        ))

    return findings


def _check_rbac_binding(doc: dict, source: str, ns: str, name: str, kind: str) -> list[K8sFinding]:
    findings: list[K8sFinding] = []
    role_ref = doc.get("roleRef", {}) or {}
    role_name = role_ref.get("name", "")

    # Binding to cluster-admin
    if role_name == "cluster-admin":
        subjects = doc.get("subjects", []) or []
        for subj in subjects:
            subj_name = subj.get("name", "<unknown>")
            findings.append(K8sFinding(
                severity="CRITICAL",
                title=f"{kind}/{name} grants cluster-admin to '{subj_name}'",
                source=source, namespace=ns,
                evidence=f"roleRef.name: cluster-admin → subject: {subj_name}",
                remediation=(
                    "Remove the cluster-admin binding. Grant only the specific verbs "
                    "and resources the subject needs."
                ),
            ))

    return findings


def _check_cluster_role(doc: dict, source: str, ns: str, name: str) -> list[K8sFinding]:
    findings: list[K8sFinding] = []
    rules = doc.get("rules", []) or []

    for rule in rules:
        if not isinstance(rule, dict):
            continue
        verbs = rule.get("verbs", [])
        resources = rule.get("resources", [])

        if "*" in verbs:
            res_str = ", ".join(str(r) for r in resources) or "*"
            findings.append(K8sFinding(
                severity="HIGH" if name != "cluster-admin" else "INFO",
                title=f"ClusterRole/{name} has wildcard verbs on: {res_str}",
                source=source, namespace=ns,
                evidence=f"rules: verbs: ['*'] on resources: {resources}",
                remediation=(
                    "Replace wildcard verbs with the specific verbs required "
                    "(get, list, watch, create, update, delete)."
                ),
            ))
        if "*" in resources:
            verb_str = ", ".join(str(v) for v in verbs)
            findings.append(K8sFinding(
                severity="HIGH" if name != "cluster-admin" else "INFO",
                title=f"ClusterRole/{name} applies to all resources (*) with verbs: {verb_str}",
                source=source, namespace=ns,
                evidence=f"rules: resources: ['*'] with verbs: {verbs}",
                remediation="Restrict to specific resource types instead of using '*'.",
            ))

    return findings


# ---------------------------------------------------------------------------
# Live cluster inspection
# ---------------------------------------------------------------------------

def _scan_live_cluster() -> tuple[list[K8sFinding], int, str | None]:
    """Query running cluster via kubectl. Returns (findings, resource_count, error)."""
    findings: list[K8sFinding] = []
    count = 0

    try:
        subprocess.run(
            ["kubectl", "version", "--client"],
            capture_output=True, timeout=5,
        )
    except FileNotFoundError:
        return [], 0, "kubectl not found — install kubectl to enable live cluster scanning"
    except Exception as exc:
        return [], 0, str(exc)

    # Check cluster reachable
    version_proc = subprocess.run(
        ["kubectl", "version", "--short"],
        capture_output=True, text=True, timeout=10,
    )
    if version_proc.returncode != 0:
        return [], 0, "No cluster reachable — configure kubectl with a valid kubeconfig"

    # Pods across all namespaces
    pod_findings, pod_count, err = _kubectl_check_pods()
    findings.extend(pod_findings)
    count += pod_count
    if err:
        logger.debug("Pod check error: %s", err)

    # ClusterRoleBindings
    crb_findings, crb_count, err = _kubectl_check_clusterrolebindings()
    findings.extend(crb_findings)
    count += crb_count
    if err:
        logger.debug("CRB check error: %s", err)

    # NetworkPolicies
    np_findings, err = _kubectl_check_network_policies()
    findings.extend(np_findings)
    if err:
        logger.debug("NetworkPolicy check error: %s", err)

    return findings, count, None


def _kubectl_json(args: list[str]) -> tuple[dict | list | None, str | None]:
    """Run kubectl with -o json and return parsed JSON or error string."""
    try:
        proc = subprocess.run(
            ["kubectl"] + args + ["-o", "json"],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return None, proc.stderr.strip()
        return json.loads(proc.stdout), None
    except Exception as exc:
        return None, str(exc)


def _kubectl_check_pods() -> tuple[list[K8sFinding], int, str | None]:
    findings: list[K8sFinding] = []
    data, err = _kubectl_json(["get", "pods", "--all-namespaces"])
    if err or not data:
        return [], 0, err

    items: list[dict] = data.get("items", [])  # type: ignore[union-attr]
    for pod in items:
        ns = pod.get("metadata", {}).get("namespace", "default")
        name = pod.get("metadata", {}).get("name", "<unnamed>")
        source = f"live:pod/{ns}/{name}"
        spec = pod.get("spec", {}) or {}

        for flag in ("hostPID", "hostNetwork", "hostIPC"):
            if spec.get(flag) is True:
                findings.append(K8sFinding(
                    severity="HIGH",
                    title=f"Live Pod '{name}' uses {flag}: true",
                    source=source, namespace=ns,
                    evidence=f"spec.{flag}: true",
                    remediation=f"Restart pod without {flag}: true.",
                ))

        for ctr in spec.get("containers", []):
            sc = ctr.get("securityContext", {}) or {}
            if sc.get("privileged") is True:
                findings.append(K8sFinding(
                    severity="CRITICAL",
                    title=f"Live Pod '{name}' / container '{ctr.get('name')}' is privileged",
                    source=source, namespace=ns,
                    evidence="securityContext.privileged: true",
                    remediation="Restart pod/container without privileged: true.",
                ))

        for vol in spec.get("volumes", []):
            if isinstance(vol, dict) and "hostPath" in vol:
                hp = vol.get("hostPath", {})
                hp_path = hp.get("path", "") if isinstance(hp, dict) else ""
                findings.append(K8sFinding(
                    severity="HIGH",
                    title=f"Live Pod '{name}' mounts hostPath",
                    source=source, namespace=ns,
                    evidence=f"hostPath.path: {hp_path}",
                    remediation="Migrate to PVC; restart pod without hostPath mounts.",
                ))

    return findings, len(items), None


def _kubectl_check_clusterrolebindings() -> tuple[list[K8sFinding], int, str | None]:
    findings: list[K8sFinding] = []
    data, err = _kubectl_json(["get", "clusterrolebindings"])
    if err or not data:
        return [], 0, err

    items: list[dict] = data.get("items", [])  # type: ignore[union-attr]
    for crb in items:
        name = crb.get("metadata", {}).get("name", "<unnamed>")
        role_ref = crb.get("roleRef", {}) or {}
        if role_ref.get("name") == "cluster-admin":
            subjects = crb.get("subjects", []) or []
            for subj in subjects:
                subj_name = subj.get("name", "<unknown>")
                subj_kind = subj.get("kind", "")
                findings.append(K8sFinding(
                    severity="CRITICAL",
                    title=f"ClusterRoleBinding '{name}' grants cluster-admin to {subj_kind}/{subj_name}",
                    source=f"live:clusterrolebinding/{name}",
                    namespace="cluster",
                    evidence=f"roleRef: cluster-admin → {subj_kind}/{subj_name}",
                    remediation=(
                        "Remove or replace this binding with a least-privilege role."
                    ),
                ))

    return findings, len(items), None


def _kubectl_check_network_policies() -> tuple[list[K8sFinding], str | None]:
    findings: list[K8sFinding] = []

    # Get all namespaces
    ns_data, err = _kubectl_json(["get", "namespaces"])
    if err or not ns_data:
        return [], err

    namespaces = [
        ns.get("metadata", {}).get("name", "")
        for ns in ns_data.get("items", [])  # type: ignore[union-attr]
        if ns.get("metadata", {}).get("name", "") not in ("kube-system", "kube-public", "kube-node-lease")
    ]

    # Get all NetworkPolicies
    np_data, err = _kubectl_json(["get", "networkpolicies", "--all-namespaces"])
    if err or not np_data:
        return [], err

    covered_ns = {
        np.get("metadata", {}).get("namespace", "")
        for np in np_data.get("items", [])  # type: ignore[union-attr]
    }

    for ns in namespaces:
        if ns not in covered_ns:
            findings.append(K8sFinding(
                severity="MEDIUM",
                title=f"Namespace '{ns}' has no NetworkPolicy",
                source=f"live:namespace/{ns}",
                namespace=ns,
                evidence="No NetworkPolicy resources found in this namespace",
                remediation=(
                    "Add a default-deny NetworkPolicy and explicit allow rules "
                    "for required traffic."
                ),
            ))

    return findings, None
