"use client";

import { useState, useEffect, useRef } from "react";
import {
  Box, CheckCircle, RefreshCw, ChevronDown, ChevronUp,
  AlertTriangle, Circle, Loader2, Terminal,
} from "lucide-react";

interface DockerFinding {
  severity: string; title: string; source: string; evidence: string; remediation: string;
}
interface DockerScanResult {
  dockerfiles_scanned: number; compose_files_scanned: number;
  containers_inspected: number; findings: DockerFinding[]; error?: string;
}
interface DockerStatus {
  installed: boolean; running: boolean; version: string | null; error: string | null;
}
interface LogEntry { time: string; pct: number; msg: string; }

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4 };
const SEV_COLORS: Record<string, string> = {
  CRITICAL: "bg-red-900/30 border-red-700 text-red-300",
  HIGH: "bg-orange-900/30 border-orange-700 text-orange-300",
  MEDIUM: "bg-yellow-900/30 border-yellow-700 text-yellow-300",
  LOW: "bg-blue-900/30 border-blue-700 text-blue-300",
  INFO: "bg-slate-800 border-slate-600 text-slate-400",
};
const SEV_BADGE: Record<string, string> = {
  CRITICAL: "bg-red-500 text-white", HIGH: "bg-orange-500 text-white",
  MEDIUM: "bg-yellow-500 text-black", LOW: "bg-blue-500 text-white",
  INFO: "bg-slate-600 text-white",
};
function sevKey(s: string) { return s.toUpperCase(); }

function StatusDot({ ok, loading }: { ok: boolean; loading?: boolean }) {
  if (loading) return <Loader2 className="w-3.5 h-3.5 animate-spin text-slate-400" />;
  return ok
    ? <Circle className="w-3 h-3 fill-green-400 text-green-400" />
    : <Circle className="w-3 h-3 fill-red-400 text-red-400" />;
}

type Phase = "idle" | "starting" | "running" | "done" | "failed";

export default function DockerPage() {
  const [path, setPath] = useState(".");
  const [includeLive, setIncludeLive] = useState(false);
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [result, setResult] = useState<DockerScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());
  const [showLog, setShowLog] = useState(true);

  const [dockerStatus, setDockerStatus] = useState<DockerStatus | null>(null);
  const [statusLoading, setStatusLoading] = useState(true);

  const logEndRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);

  useEffect(() => {
    fetch("/api/infra/status")
      .then((r) => r.json())
      .then((d) => setDockerStatus(d.docker))
      .catch(() => setDockerStatus({ installed: false, running: false, version: null, error: "Could not reach API" }))
      .finally(() => setStatusLoading(false));
    return () => { esRef.current?.close(); };
  }, []);

  // Auto-scroll log to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  function addLog(pct: number, msg: string) {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs((prev) => [...prev, { time, pct, msg }]);
  }

  async function startScan() {
    esRef.current?.close();
    setPhase("starting");
    setProgress(0);
    setProgressMsg("Connecting…");
    setLogs([]);
    setResult(null);
    setScanError(null);
    setExpanded(new Set());

    try {
      const res = await fetch("/api/docker/scan/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ path, include_live: includeLive }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error(body.detail || `HTTP ${res.status}`);
      }
      const { job_id } = await res.json() as { job_id: string };

      const es = new EventSource(`/api/jobs/${job_id}/stream`);
      esRef.current = es;
      setPhase("running");

      es.addEventListener("progress", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { pct: number; message: string };
        setProgress(data.pct);
        setProgressMsg(data.message);
        addLog(data.pct, data.message);
      });

      es.addEventListener("log", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { message: string };
        addLog(-1, data.message);
      });

      es.addEventListener("completed", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { result: DockerScanResult };
        setResult(data.result);
        setProgress(100);
        setPhase("done");
        es.close();
      });

      es.addEventListener("error", (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data) as { message: string };
          setScanError(data.message);
          addLog(-1, `Error: ${data.message}`);
        } catch {
          setScanError("Scan error");
        }
        setPhase("failed");
        es.close();
      });

      es.onerror = () => {
        if (phase !== "done") {
          setScanError("Connection to server lost");
          setPhase("failed");
        }
        es.close();
      };
    } catch (e) {
      setScanError(e instanceof Error ? e.message : "Failed to start scan");
      setPhase("failed");
    }
  }

  function toggleExpand(i: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });
  }

  const sortedFindings = result
    ? [...result.findings].sort(
        (a, b) => (SEV_ORDER[sevKey(a.severity)] ?? 5) - (SEV_ORDER[sevKey(b.severity)] ?? 5)
      )
    : [];

  const isRunning = phase === "running" || phase === "starting";

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <a href="/" className="text-slate-400 hover:text-slate-200 transition-colors text-sm">← Back</a>
          <div className="w-px h-4 bg-slate-700" />
          <Box className="w-5 h-5 text-blue-400" />
          <h1 className="font-semibold text-lg">Docker Security Scanner</h1>
        </div>
        <button
          onClick={startScan}
          disabled={isRunning}
          className="flex items-center gap-2 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isRunning ? "animate-spin" : ""}`} />
          {isRunning ? "Scanning…" : "Run Scan"}
        </button>
      </header>

      <main className="max-w-4xl mx-auto px-6 py-8 space-y-4">
        {/* Docker status banner */}
        <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl px-5 py-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Docker Status</span>
            <button
              onClick={() => {
                setStatusLoading(true);
                fetch("/api/infra/status").then((r) => r.json()).then((d) => setDockerStatus(d.docker)).catch(() => {}).finally(() => setStatusLoading(false));
              }}
              className="text-slate-500 hover:text-slate-300"
            >
              <RefreshCw className="w-3.5 h-3.5" />
            </button>
          </div>
          <div className="flex flex-wrap gap-4">
            <div className="flex items-center gap-2">
              <StatusDot ok={!!dockerStatus?.installed} loading={statusLoading} />
              <span className="text-sm">{statusLoading ? "Checking…" : dockerStatus?.installed ? "Installed" : "Not installed"}</span>
              {dockerStatus?.version && <span className="text-xs text-slate-500 font-mono">{dockerStatus.version.replace("Docker version ", "v")}</span>}
            </div>
            <div className="flex items-center gap-2">
              <StatusDot ok={!!dockerStatus?.running} loading={statusLoading} />
              <span className="text-sm">{statusLoading ? "Checking…" : dockerStatus?.running ? "Daemon running" : "Daemon stopped"}</span>
            </div>
          </div>
          {!statusLoading && dockerStatus?.error && (
            <div className="flex items-start gap-2 mt-2 bg-slate-900 rounded-lg px-3 py-2">
              <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <p className="text-xs text-yellow-300">{dockerStatus.error}</p>
            </div>
          )}
        </div>

        {/* Config */}
        <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl px-5 py-4">
          <h2 className="text-xs font-semibold text-slate-400 uppercase tracking-wide mb-3">Scan Configuration</h2>
          <div className="flex flex-col sm:flex-row gap-4">
            <div className="flex-1">
              <label className="block text-xs text-slate-500 mb-1.5">Directory path</label>
              <input
                type="text" value={path} onChange={(e) => setPath(e.target.value)}
                disabled={isRunning}
                className="w-full bg-slate-900 border border-slate-700 rounded-lg px-3 py-2 text-sm font-mono text-slate-200 focus:outline-none focus:border-blue-600 disabled:opacity-50"
                placeholder=". or /path/to/project"
              />
            </div>
            <div className="flex items-end">
              <label className={`flex items-center gap-2 select-none ${dockerStatus?.running ? "cursor-pointer" : "cursor-not-allowed opacity-50"}`}>
                <input
                  type="checkbox" checked={includeLive}
                  onChange={(e) => setIncludeLive(e.target.checked)}
                  disabled={isRunning || !dockerStatus?.running}
                  className="w-4 h-4 rounded accent-blue-500"
                />
                <span className="text-sm">Include live containers</span>
              </label>
            </div>
          </div>
        </div>

        {/* Progress + live log (shown while scanning and after) */}
        {(isRunning || phase === "done" || phase === "failed") && logs.length > 0 && (
          <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl overflow-hidden">
            {/* Progress bar */}
            <div className="px-5 pt-4 pb-3">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Progress</span>
                <span className="text-xs font-mono text-blue-400">{progress}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-2 rounded-full transition-all duration-500 ${
                    phase === "failed" ? "bg-red-500" : phase === "done" ? "bg-green-500" : "bg-blue-500"
                  }`}
                  style={{ width: `${progress}%` }}
                />
              </div>
              {progressMsg && (
                <p className="text-xs text-slate-400 mt-1.5 truncate">{progressMsg}</p>
              )}
            </div>

            {/* Log panel toggle */}
            <button
              onClick={() => setShowLog((v) => !v)}
              className="w-full flex items-center gap-2 px-5 py-2 border-t border-slate-700 text-xs text-slate-400 hover:text-slate-200 hover:bg-slate-800/30 transition-colors"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span className="font-medium">Live Log</span>
              <span className="text-slate-600">({logs.length} lines)</span>
              {showLog ? <ChevronUp className="w-3.5 h-3.5 ml-auto" /> : <ChevronDown className="w-3.5 h-3.5 ml-auto" />}
            </button>

            {showLog && (
              <div className="h-48 overflow-y-auto bg-slate-950 font-mono text-xs p-3 space-y-0.5">
                {logs.map((entry, i) => (
                  <div key={i} className="flex gap-2 leading-5">
                    <span className="text-slate-600 flex-shrink-0">{entry.time}</span>
                    {entry.pct >= 0 && (
                      <span className="text-blue-400 flex-shrink-0 w-8 text-right">{entry.pct}%</span>
                    )}
                    <span className="text-slate-300 break-all">{entry.msg}</span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            )}
          </div>
        )}

        {/* Idle state */}
        {phase === "idle" && (
          <div className="text-center py-16">
            <Box className="w-14 h-14 text-blue-400/30 mx-auto mb-4" />
            <p className="text-slate-500 max-w-sm mx-auto">
              Checks Dockerfiles, docker-compose files, and running containers for
              misconfigurations. Progress and live logs shown during scan.
            </p>
          </div>
        )}

        {/* Error */}
        {phase === "failed" && scanError && (
          <div className="bg-red-900/30 border border-red-700 rounded-xl px-5 py-4">
            <div className="flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-red-300 font-medium">Scan failed</p>
                <p className="text-red-400/80 text-sm mt-1">{scanError}</p>
              </div>
            </div>
          </div>
        )}

        {/* Results */}
        {result && (
          <>
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              {[
                { label: "Dockerfiles", value: result.dockerfiles_scanned, color: "text-blue-400" },
                { label: "Compose files", value: result.compose_files_scanned, color: "text-blue-400" },
                { label: "Containers", value: result.containers_inspected, color: "text-slate-300" },
                { label: "Findings", value: result.findings.length, color: result.findings.length > 0 ? "text-orange-400" : "text-green-400" },
              ].map(({ label, value, color }) => (
                <div key={label} className="bg-[#1a1f2e] rounded-xl border border-slate-800 p-4 text-center">
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-slate-500 uppercase mt-1">{label}</p>
                </div>
              ))}
            </div>

            {result.error && (
              <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-xl px-5 py-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-400 flex-shrink-0 mt-0.5" />
                  <p className="text-yellow-300 text-sm"><span className="font-medium">Warning: </span>{result.error}</p>
                </div>
              </div>
            )}

            {sortedFindings.length > 0 ? (
              <section>
                <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-3">
                  Security Findings ({sortedFindings.length})
                </h2>
                <div className="space-y-2">
                  {sortedFindings.map((f, i) => {
                    const sk = sevKey(f.severity);
                    return (
                      <div key={i} className={`rounded-xl border overflow-hidden ${SEV_COLORS[sk] || SEV_COLORS.INFO}`}>
                        <button
                          className="w-full text-left px-4 py-3 flex items-center gap-3 hover:brightness-110 transition-all"
                          onClick={() => toggleExpand(i)}
                        >
                          <span className={`text-xs font-bold px-2 py-0.5 rounded flex-shrink-0 ${SEV_BADGE[sk] || SEV_BADGE.INFO}`}>{sk}</span>
                          <span className="font-medium flex-1 min-w-0 truncate">{f.title}</span>
                          <span className="text-xs opacity-50 font-mono truncate max-w-[160px] hidden sm:block">{f.source.split("/").pop()}</span>
                          {expanded.has(i) ? <ChevronUp className="w-4 h-4 opacity-40 flex-shrink-0" /> : <ChevronDown className="w-4 h-4 opacity-40 flex-shrink-0" />}
                        </button>
                        {expanded.has(i) && (
                          <div className="px-4 pb-4 pt-2 space-y-3 border-t border-current/20">
                            <p className="text-xs text-slate-400 font-mono break-all">{f.source}</p>
                            <div className="bg-black/20 rounded px-3 py-2 font-mono text-xs break-all">{f.evidence}</div>
                            <p className="text-sm opacity-80"><span className="font-medium">Fix: </span>{f.remediation}</p>
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </section>
            ) : (
              <div className="flex items-center gap-3 bg-green-900/20 border border-green-700/40 rounded-xl px-5 py-4">
                <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                <p className="text-green-300">No security issues found in Docker configuration.</p>
              </div>
            )}
          </>
        )}
      </main>
    </div>
  );
}
