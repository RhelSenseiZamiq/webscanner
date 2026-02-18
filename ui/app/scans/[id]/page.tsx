"use client";

import { useEffect, useState, useCallback, useRef } from "react";
import { useParams, useRouter } from "next/navigation";
import { getScan, streamScan, type Scan, type Finding, type ScanStatus } from "@/lib/api";
import { formatDuration } from "@/lib/utils";
import StatusBadge from "@/components/StatusBadge";
import SummaryCards from "@/components/SummaryCards";
import FindingsTable from "@/components/FindingsTable";
import { Shield, ArrowLeft, Download, Terminal, ChevronDown, ChevronUp } from "lucide-react";

interface LogEntry { time: string; pct: number; msg: string; }

export default function ScanDetailPage() {
  const params = useParams();
  const router = useRouter();
  const scanId = params.id as string;

  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [status, setStatus] = useState<ScanStatus>("pending");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  // Progress + live log state
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [showLog, setShowLog] = useState(true);

  const logEndRef = useRef<HTMLDivElement>(null);

  // Auto-scroll log to bottom
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  function addLog(pct: number, msg: string) {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs((prev) => [...prev, { time, pct, msg }]);
  }

  const loadScan = useCallback(async () => {
    try {
      const data = await getScan(scanId);
      setScan(data);
      setFindings(data.findings);
      setStatus(data.status);
    } catch {
      setError("Failed to load scan");
    } finally {
      setLoading(false);
    }
  }, [scanId]);

  useEffect(() => {
    loadScan();
  }, [loadScan]);

  useEffect(() => {
    if (!scan || scan.status === "completed" || scan.status === "failed") return;

    const cleanup = streamScan(
      scanId,
      (finding) => setFindings((prev) => [...prev, finding]),
      (newStatus) => setStatus(newStatus),
      () => {
        setStatus("completed");
        setProgress(100);
        loadScan();
      },
      (err) => {
        setError(err);
        setStatus("failed");
      },
      (pct, message) => {
        setProgress(pct);
        setProgressMsg(message);
        addLog(pct, message);
      },
    );

    return cleanup;
  }, [scan?.scan_id, scan?.status, scanId, loadScan]);

  function downloadJson() {
    if (!scan) return;
    const data = {
      scan_id: scan.scan_id,
      target: scan.target_url,
      program: scan.program,
      started_at: scan.started_at,
      finished_at: scan.finished_at,
      summary: scan.summary,
      findings,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `scan-${scanId.slice(0, 8)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  }

  // Build live summary from streaming findings
  const liveSummary = scan
    ? {
        critical: findings.filter((f) => f.severity === "critical").length,
        high: findings.filter((f) => f.severity === "high").length,
        medium: findings.filter((f) => f.severity === "medium").length,
        low: findings.filter((f) => f.severity === "low").length,
        info: findings.filter((f) => f.severity === "info").length,
      }
    : null;

  const isRunning = status === "running" || status === "pending";

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f1117] flex items-center justify-center text-slate-500">
        Loading...
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="min-h-screen bg-[#0f1117] flex flex-col items-center justify-center gap-3 text-slate-500">
        <p>Scan not found</p>
        <button onClick={() => router.push("/")} className="text-cyan-400 hover:text-cyan-300 text-sm">
          ← Back to dashboard
        </button>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-[#0f1117]">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-3">
            <button
              onClick={() => router.push("/")}
              className="p-1.5 text-slate-400 hover:text-slate-200 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
            </button>
            <Shield className="w-5 h-5 text-cyan-400" />
            <div>
              <div className="flex items-center gap-2">
                <StatusBadge status={status} />
                <span className="text-sm font-medium text-slate-200 truncate max-w-md">
                  {scan.target_url}
                </span>
              </div>
              <div className="text-xs text-slate-500 mt-0.5">
                {scan.program} · {formatDuration(scan.started_at, scan.finished_at)}
              </div>
            </div>
          </div>
          <button
            onClick={downloadJson}
            disabled={status !== "completed"}
            className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-slate-200 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          >
            <Download className="w-4 h-4" />
            Export JSON
          </button>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-6">
        {error && (
          <div className="bg-red-900/30 border border-red-700 rounded-lg px-4 py-3 text-sm text-red-300">
            {error}
          </div>
        )}

        {/* Progress bar + live log — shown while running or after */}
        {(isRunning || status === "completed" || status === "failed") && logs.length > 0 && (
          <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl overflow-hidden">
            {/* Progress bar */}
            <div className="px-5 pt-4 pb-3">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Progress</span>
                <span className="text-xs font-mono text-cyan-400">{progress}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-2 rounded-full transition-all duration-500 ${
                    status === "failed" ? "bg-red-500" : status === "completed" ? "bg-green-500" : "bg-cyan-500"
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
                      <span className="text-cyan-400 flex-shrink-0 w-8 text-right">{entry.pct}%</span>
                    )}
                    <span className="text-slate-300 break-all">{entry.msg}</span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            )}
          </div>
        )}

        {/* Live scanning indicator when no log entries yet */}
        {isRunning && logs.length === 0 && (
          <div className="flex items-center gap-2 text-sm text-cyan-400">
            <span className="w-2 h-2 bg-cyan-400 rounded-full animate-pulse" />
            Scan in progress — connecting to live stream…
          </div>
        )}

        {/* Summary */}
        {liveSummary && (
          <div>
            <h2 className="text-sm font-medium text-slate-400 mb-3 uppercase tracking-wide">
              Findings Summary
            </h2>
            <SummaryCards summary={liveSummary} />
          </div>
        )}

        {/* Findings */}
        <div>
          <h2 className="text-sm font-medium text-slate-400 mb-3 uppercase tracking-wide">
            Findings ({findings.length})
          </h2>
          <FindingsTable findings={findings} />
        </div>
      </main>
    </div>
  );
}
