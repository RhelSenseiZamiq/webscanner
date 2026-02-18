"use client";

import { useState, useRef, useEffect } from "react";
import {
  Wifi, AlertTriangle, CheckCircle, RefreshCw, X, Zap,
  ShieldAlert, ChevronDown, ChevronUp, Terminal, MapPin,
} from "lucide-react";

interface WiFiNetwork {
  ssid: string;
  bssid: string;
  signal_dbm: number;
  channel: number;
  security: string;
  wps_enabled: boolean;
  band: string;
}

interface WiFiFinding {
  network_ssid: string;
  bssid: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  remediation: string;
}

interface WiFiScanResult {
  status: string;
  platform: string;
  scan_duration_seconds: number;
  networks: WiFiNetwork[];
  findings: WiFiFinding[];
  summary: {
    total_networks: number;
    open: number;
    wep: number;
    wps_enabled: number;
    wpa2: number;
    wpa3: number;
    total_findings: number;
  };
  error?: string;
}

interface AttackResult {
  ssid: string;
  password_found: boolean;
  password?: string;
  attempts: number;
  duration_seconds: number;
  wordlist_used: string;
  error?: string;
}

interface LogEntry { time: string; pct: number; msg: string; }

const SEV_COLORS: Record<string, string> = {
  critical: "bg-red-900/30 border-red-700 text-red-300",
  high: "bg-orange-900/30 border-orange-700 text-orange-300",
  medium: "bg-yellow-900/30 border-yellow-700 text-yellow-300",
  low: "bg-blue-900/30 border-blue-700 text-blue-300",
  info: "bg-slate-800 border-slate-600 text-slate-400",
};

const SEV_BADGE: Record<string, string> = {
  critical: "bg-red-500 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-slate-600 text-white",
};

function signalBar(dbm: number): string {
  if (dbm >= -50) return "████";
  if (dbm >= -60) return "███░";
  if (dbm >= -70) return "██░░";
  if (dbm >= -80) return "█░░░";
  return "░░░░";
}

function securityColor(security: string): string {
  const s = security.toUpperCase();
  if (s.includes("WEP") || s === "OPEN" || s === "" || s === "--") return "text-red-400";
  if (s.includes("WPA3")) return "text-green-400";
  return "text-yellow-400";
}

function isRedacted(ssid: string): boolean {
  return !ssid || ssid === "<redacted>" || ssid === "<hidden>";
}

type Phase = "idle" | "starting" | "running" | "done" | "failed";
type AttackPhase = "idle" | "running" | "done" | "failed";

export default function WiFiPage() {
  // Passive scan state
  const [phase, setPhase] = useState<Phase>("idle");
  const [progress, setProgress] = useState(0);
  const [progressMsg, setProgressMsg] = useState("");
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [showLog, setShowLog] = useState(true);
  const [result, setResult] = useState<WiFiScanResult | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  // Per-network actions
  const [vulnFilter, setVulnFilter] = useState<{ bssid: string; ssid: string } | null>(null);
  const [attackTarget, setAttackTarget] = useState<WiFiNetwork | null>(null);

  // Attack state
  const [attackPhase, setAttackPhase] = useState<AttackPhase>("idle");
  const [attackProgress, setAttackProgress] = useState(0);
  const [attackProgressMsg, setAttackProgressMsg] = useState("");
  const [attackLogs, setAttackLogs] = useState<LogEntry[]>([]);
  const [showAttackLog, setShowAttackLog] = useState(true);
  const [attackWordlist, setAttackWordlist] = useState("wordlists/wifi-passwords.txt");
  const [attackMaxAttempts, setAttackMaxAttempts] = useState(10);
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);
  // Manual SSID override (for when target SSID is <redacted>)
  const [manualSsid, setManualSsid] = useState("");
  const [knownNetworks, setKnownNetworks] = useState<string[]>([]);

  const logEndRef = useRef<HTMLDivElement>(null);
  const attackLogEndRef = useRef<HTMLDivElement>(null);
  const esRef = useRef<EventSource | null>(null);
  const attackEsRef = useRef<EventSource | null>(null);
  const findingsRef = useRef<HTMLElement>(null);

  useEffect(() => {
    return () => {
      esRef.current?.close();
      attackEsRef.current?.close();
    };
  }, []);

  // Auto-scroll logs
  useEffect(() => {
    logEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  useEffect(() => {
    attackLogEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [attackLogs]);

  // Scroll to findings when filter changes
  useEffect(() => {
    if (vulnFilter && findingsRef.current) {
      findingsRef.current.scrollIntoView({ behavior: "smooth", block: "start" });
    }
  }, [vulnFilter]);

  function addLog(pct: number, msg: string) {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setLogs((prev) => [...prev, { time, pct, msg }]);
  }

  function addAttackLog(pct: number, msg: string) {
    const time = new Date().toLocaleTimeString("en-US", { hour12: false });
    setAttackLogs((prev) => [...prev, { time, pct, msg }]);
  }

  async function runScan() {
    esRef.current?.close();
    setPhase("starting");
    setProgress(0);
    setProgressMsg("Connecting…");
    setLogs([]);
    setResult(null);
    setScanError(null);
    setExpanded(new Set());
    setVulnFilter(null);

    try {
      const res = await fetch("/api/wifi/scan/start", { method: "POST" });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { detail?: string }).detail || `HTTP ${res.status}`);
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
        const data = JSON.parse(e.data) as { result: WiFiScanResult };
        if (data.result.error) {
          setScanError(data.result.error);
          setPhase("failed");
        } else {
          setResult(data.result);
          setProgress(100);
          setPhase("done");
        }
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

  async function runAttack() {
    if (!attackTarget) return;

    const targetSsid = manualSsid.trim() || attackTarget.ssid;
    if (isRedacted(targetSsid)) return; // button disabled, but guard anyway

    attackEsRef.current?.close();
    setAttackPhase("running");
    setAttackProgress(0);
    setAttackProgressMsg("Starting…");
    setAttackLogs([]);
    setAttackResult(null);

    try {
      const res = await fetch("/api/wifi/attack/start", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          ssid: targetSsid,
          wordlist: attackWordlist,
          max_attempts: attackMaxAttempts,
          interface: "en0",
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        throw new Error((body as { detail?: string }).detail || `HTTP ${res.status}`);
      }
      const { job_id } = await res.json() as { job_id: string };

      const es = new EventSource(`/api/jobs/${job_id}/stream`);
      attackEsRef.current = es;

      es.addEventListener("progress", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { pct: number; message: string };
        setAttackProgress(data.pct);
        setAttackProgressMsg(data.message);
        addAttackLog(data.pct, data.message);
      });

      es.addEventListener("log", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { message: string };
        addAttackLog(-1, data.message);
      });

      es.addEventListener("completed", (e: MessageEvent) => {
        const data = JSON.parse(e.data) as { result: AttackResult };
        setAttackResult(data.result);
        setAttackProgress(100);
        setAttackPhase(data.result.error ? "failed" : "done");
        es.close();
      });

      es.addEventListener("error", (e: MessageEvent) => {
        try {
          const data = JSON.parse(e.data) as { message: string };
          setAttackResult({
            ssid: targetSsid, password_found: false,
            attempts: 0, duration_seconds: 0,
            wordlist_used: attackWordlist, error: data.message,
          });
        } catch {
          setAttackResult({
            ssid: targetSsid, password_found: false,
            attempts: 0, duration_seconds: 0,
            wordlist_used: attackWordlist, error: "Attack failed",
          });
        }
        setAttackPhase("failed");
        es.close();
      });

      es.onerror = () => {
        if (attackPhase === "running") {
          setAttackResult({
            ssid: targetSsid, password_found: false,
            attempts: 0, duration_seconds: 0,
            wordlist_used: attackWordlist, error: "Connection lost",
          });
          setAttackPhase("failed");
        }
        es.close();
      };
    } catch (e) {
      setAttackResult({
        ssid: targetSsid, password_found: false,
        attempts: 0, duration_seconds: 0,
        wordlist_used: attackWordlist,
        error: e instanceof Error ? e.message : "Attack failed",
      });
      setAttackPhase("failed");
    }
  }

  function toggleExpand(i: number) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(i) ? next.delete(i) : next.add(i);
      return next;
    });
  }

  function toggleVulnFilter(network: WiFiNetwork) {
    setExpanded(new Set());
    setVulnFilter((v) =>
      v?.bssid === network.bssid ? null : { bssid: network.bssid, ssid: network.ssid }
    );
  }

  async function openAttack(network: WiFiNetwork) {
    attackEsRef.current?.close();
    setAttackTarget(network);
    setAttackResult(null);
    setAttackLogs([]);
    setAttackPhase("idle");
    setAttackProgress(0);
    setManualSsid(isRedacted(network.ssid) ? "" : network.ssid);
    // Fetch saved networks so user can pick from a dropdown
    try {
      const res = await fetch("/api/wifi/known-networks");
      if (res.ok) {
        const data = await res.json() as { networks: string[] };
        setKnownNetworks(data.networks);
      }
    } catch { /* ignore — dropdown just won't be populated */ }
  }

  function closeAttack() {
    attackEsRef.current?.close();
    setAttackTarget(null);
    setAttackResult(null);
    setAttackPhase("idle");
  }

  const shownFindings = result
    ? vulnFilter
      ? result.findings.filter((f) => {
          if (vulnFilter.bssid && f.bssid && f.bssid === vulnFilter.bssid) return true;
          if (vulnFilter.ssid && f.network_ssid && f.network_ssid === vulnFilter.ssid) return true;
          return false;
        })
      : result.findings
    : [];

  const filteredNetwork = result?.networks.find((n) => n.bssid === vulnFilter?.bssid);

  const isRunning = phase === "running" || phase === "starting";
  const attackRunning = attackPhase === "running";

  // Detect if all SSIDs are redacted (Location Services disabled)
  const allRedacted = result
    ? result.networks.length > 0 && result.networks.every((n) => isRedacted(n.ssid))
    : false;

  const effectiveSsid = manualSsid.trim() || (attackTarget?.ssid ?? "");
  const canStartAttack = !attackRunning && !!attackWordlist && !isRedacted(effectiveSsid);

  return (
    <div className="min-h-screen bg-[#0a0d14] text-slate-200">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <a href="/" className="text-slate-400 hover:text-slate-200 transition-colors text-sm">
            ← Back
          </a>
          <div className="w-px h-4 bg-slate-700" />
          <Wifi className="w-5 h-5 text-cyan-400" />
          <h1 className="font-semibold text-lg">WiFi Security Scanner</h1>
        </div>
        <button
          onClick={runScan}
          disabled={isRunning}
          className="flex items-center gap-2 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white text-sm font-medium rounded-lg px-4 py-2 transition-colors"
        >
          <RefreshCw className={`w-4 h-4 ${isRunning ? "animate-spin" : ""}`} />
          {isRunning ? "Scanning…" : "Scan Networks"}
        </button>
      </header>

      <main className="max-w-5xl mx-auto px-6 py-8 space-y-6">
        {/* Idle intro */}
        {phase === "idle" && (
          <div className="text-center py-20">
            <Wifi className="w-16 h-16 text-cyan-400/40 mx-auto mb-4" />
            <h2 className="text-xl font-semibold text-slate-300 mb-2">
              Passive WiFi Security Scan
            </h2>
            <p className="text-slate-500 max-w-md mx-auto mb-6">
              Discovers nearby wireless networks and identifies security weaknesses — open
              networks, WEP encryption, WPS-enabled access points, and more.
            </p>
            <button
              onClick={runScan}
              className="bg-cyan-600 hover:bg-cyan-500 text-white font-medium rounded-lg px-6 py-3 transition-colors"
            >
              Start Scan
            </button>
          </div>
        )}

        {/* Progress + live log */}
        {(isRunning || phase === "done" || phase === "failed") && logs.length > 0 && (
          <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl overflow-hidden">
            <div className="px-5 pt-4 pb-3">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-xs font-semibold text-slate-400 uppercase tracking-wide">Progress</span>
                <span className="text-xs font-mono text-cyan-400">{progress}%</span>
              </div>
              <div className="w-full bg-slate-700 rounded-full h-2 overflow-hidden">
                <div
                  className={`h-2 rounded-full transition-all duration-500 ${
                    phase === "failed" ? "bg-red-500" : phase === "done" ? "bg-green-500" : "bg-cyan-500"
                  }`}
                  style={{ width: `${progress}%` }}
                />
              </div>
              {progressMsg && (
                <p className="text-xs text-slate-400 mt-1.5 truncate">{progressMsg}</p>
              )}
            </div>

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
              <div className="h-40 overflow-y-auto bg-slate-950 font-mono text-xs p-3 space-y-0.5">
                {logs.map((entry, i) => (
                  <div key={i} className="flex gap-2 leading-5">
                    <span className="text-slate-600 flex-shrink-0">{entry.time}</span>
                    {entry.pct >= 0 && (
                      <span className="text-cyan-400 flex-shrink-0 w-8 text-right">{entry.pct}%</span>
                    )}
                    <span className={`break-all ${entry.msg.startsWith("⚠") ? "text-yellow-400" : "text-slate-300"}`}>
                      {entry.msg}
                    </span>
                  </div>
                ))}
                <div ref={logEndRef} />
              </div>
            )}
          </div>
        )}

        {/* Scan error */}
        {phase === "failed" && scanError && (
          <div className="bg-red-900/30 border border-red-700 rounded-xl px-5 py-4">
            <p className="text-red-300 font-medium">Scan error</p>
            <p className="text-red-400/80 text-sm mt-1">{scanError}</p>
          </div>
        )}

        {/* Location Services warning */}
        {allRedacted && (
          <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-xl px-5 py-4">
            <div className="flex items-start gap-3">
              <MapPin className="w-5 h-5 text-yellow-400 flex-shrink-0 mt-0.5" />
              <div>
                <p className="text-yellow-300 font-medium text-sm">
                  SSIDs hidden — Location Services not enabled
                </p>
                <p className="text-yellow-400/80 text-xs mt-1">
                  macOS is hiding network names (showing &lt;redacted&gt;) because Location Services
                  is not enabled for this app. To see real SSIDs and BSSIDs:
                </p>
                <ol className="text-yellow-400/70 text-xs mt-2 space-y-0.5 list-decimal list-inside">
                  <li>Open <strong>System Settings → Privacy &amp; Security → Location Services</strong></li>
                  <li>Enable Location Services for <strong>Terminal</strong> (or your IDE)</li>
                  <li>Click <strong>Scan Networks</strong> again</li>
                </ol>
              </div>
            </div>
          </div>
        )}

        {result && (
          <>
            {/* Summary cards */}
            <div className="grid grid-cols-3 sm:grid-cols-6 gap-3">
              {[
                { label: "Networks", value: result.summary.total_networks, color: "text-cyan-400" },
                { label: "Open", value: result.summary.open, color: "text-red-400" },
                { label: "WEP", value: result.summary.wep, color: "text-red-400" },
                { label: "WPS", value: result.summary.wps_enabled, color: "text-yellow-400" },
                { label: "WPA2", value: result.summary.wpa2, color: "text-yellow-300" },
                { label: "WPA3", value: result.summary.wpa3, color: "text-green-400" },
              ].map(({ label, value, color }) => (
                <div
                  key={label}
                  className="bg-[#1a1f2e] rounded-xl border border-slate-800 p-4 text-center"
                >
                  <p className={`text-2xl font-bold ${color}`}>{value}</p>
                  <p className="text-xs text-slate-500 uppercase mt-1">{label}</p>
                </div>
              ))}
            </div>

            {/* Networks table */}
            <section>
              <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-3">
                Discovered Networks ({result.networks.length})
              </h2>
              <div className="bg-[#1a1f2e] rounded-xl border border-slate-800 overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="border-b border-slate-700">
                    <tr className="text-xs text-slate-500 uppercase">
                      <th className="text-left px-4 py-3">SSID</th>
                      <th className="text-left px-4 py-3 hidden sm:table-cell">BSSID</th>
                      <th className="text-center px-4 py-3">Signal</th>
                      <th className="text-center px-4 py-3 hidden sm:table-cell">Ch</th>
                      <th className="text-center px-4 py-3 hidden sm:table-cell">Band</th>
                      <th className="text-left px-4 py-3">Security</th>
                      <th className="text-center px-4 py-3">WPS</th>
                      <th className="text-right px-4 py-3">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-800">
                    {result.networks.map((n, i) => (
                      <tr
                        key={i}
                        className={`transition-colors ${
                          vulnFilter?.bssid === n.bssid
                            ? "bg-cyan-900/10"
                            : "hover:bg-slate-800/30"
                        }`}
                      >
                        <td className="px-4 py-3 font-medium">
                          {isRedacted(n.ssid)
                            ? <span className="text-slate-500 italic text-xs">&lt;redacted&gt;</span>
                            : n.ssid}
                        </td>
                        <td className="px-4 py-3 font-mono text-xs text-slate-400 hidden sm:table-cell">
                          {n.bssid || <span className="text-slate-600">—</span>}
                        </td>
                        <td className="px-4 py-3 text-center font-mono text-xs">
                          <span title={`${n.signal_dbm} dBm`}>{signalBar(n.signal_dbm)}</span>
                        </td>
                        <td className="px-4 py-3 text-center text-slate-400 hidden sm:table-cell">
                          {n.channel || <span className="text-slate-600">—</span>}
                        </td>
                        <td className="px-4 py-3 text-center text-slate-400 text-xs hidden sm:table-cell">
                          {n.band}
                        </td>
                        <td className={`px-4 py-3 font-medium ${securityColor(n.security)}`}>
                          {n.security || "Open"}
                        </td>
                        <td className="px-4 py-3 text-center">
                          {n.wps_enabled ? (
                            <span className="text-yellow-400 text-xs font-bold">YES</span>
                          ) : (
                            <span className="text-slate-600 text-xs">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right whitespace-nowrap space-x-1">
                          <button
                            onClick={() => toggleVulnFilter(n)}
                            className={`text-xs font-medium px-2 py-1 rounded transition-colors ${
                              vulnFilter?.bssid === n.bssid
                                ? "bg-cyan-700 text-white"
                                : "text-cyan-400 hover:text-cyan-300 hover:bg-cyan-900/30"
                            }`}
                            title="Show vulnerability findings for this network"
                          >
                            <ShieldAlert className="w-3 h-3 inline-block mr-1" />
                            Vuln
                          </button>
                          <button
                            onClick={() => openAttack(n)}
                            className="text-xs font-medium text-orange-400 hover:text-orange-300 hover:bg-orange-900/30 px-2 py-1 rounded transition-colors"
                            title="Brute-force attack this network"
                          >
                            <Zap className="w-3 h-3 inline-block mr-1" />
                            Attack
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <p className="text-xs text-slate-600 mt-2">
                Scanned in {result.scan_duration_seconds.toFixed(1)}s on {result.platform}
              </p>
            </section>

            {/* Findings */}
            <section ref={findingsRef}>
              <div className="flex items-center gap-3 mb-3">
                <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide">
                  Security Findings
                  {vulnFilter && filteredNetwork
                    ? ` for "${filteredNetwork.ssid || filteredNetwork.bssid}"`
                    : ` (${result.findings.length})`}
                </h2>
                {vulnFilter && (
                  <button
                    onClick={() => { setVulnFilter(null); setExpanded(new Set()); }}
                    className="flex items-center gap-1 bg-cyan-900/30 border border-cyan-700 text-cyan-300 text-xs rounded-full px-3 py-0.5 hover:bg-cyan-900/50 transition-colors"
                  >
                    <X className="w-3 h-3" />
                    Show all
                  </button>
                )}
              </div>

              {shownFindings.length > 0 ? (
                <div className="space-y-2">
                  {shownFindings.map((f, i) => (
                    <div
                      key={i}
                      className={`rounded-xl border overflow-hidden ${SEV_COLORS[f.severity] || SEV_COLORS.info}`}
                    >
                      <button
                        className="w-full text-left px-4 py-3 flex items-center gap-3 hover:brightness-110 transition-all"
                        onClick={() => toggleExpand(i)}
                      >
                        <span className={`text-xs font-bold px-2 py-0.5 rounded flex-shrink-0 ${SEV_BADGE[f.severity] || SEV_BADGE.info}`}>
                          {f.severity.toUpperCase()}
                        </span>
                        <span className="font-medium flex-1">{f.title}</span>
                        <span className="text-xs opacity-60 font-mono flex-shrink-0">{f.network_ssid}</span>
                        {expanded.has(i)
                          ? <ChevronUp className="w-4 h-4 opacity-40 flex-shrink-0" />
                          : <ChevronDown className="w-4 h-4 opacity-40 flex-shrink-0" />}
                      </button>
                      {expanded.has(i) && (
                        <div className="px-4 pb-4 pt-2 space-y-3 border-t border-current/20">
                          <p className="text-sm opacity-90">{f.description}</p>
                          <div className="bg-black/20 rounded px-3 py-2 font-mono text-xs">
                            {f.evidence}
                          </div>
                          <p className="text-sm opacity-80">
                            <span className="font-medium">Fix: </span>{f.remediation}
                          </p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="flex items-center gap-3 bg-green-900/20 border border-green-700/40 rounded-xl px-5 py-4">
                  <CheckCircle className="w-5 h-5 text-green-400 flex-shrink-0" />
                  <p className="text-green-300">
                    {vulnFilter
                      ? `No security issues found for "${filteredNetwork?.ssid || vulnFilter.bssid}".`
                      : "No security issues found in nearby networks."}
                  </p>
                </div>
              )}
            </section>
          </>
        )}
      </main>

      {/* Attack panel */}
      {attackTarget && (
        <div className="fixed inset-0 z-50 flex items-start justify-end">
          <div className="absolute inset-0 bg-black/50" onClick={closeAttack} />
          <div className="relative w-full max-w-md h-full bg-[#111827] border-l border-slate-700 shadow-2xl flex flex-col overflow-y-auto">
            {/* Panel header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700">
              <div className="flex items-center gap-2">
                <Zap className="w-4 h-4 text-orange-400" />
                <span className="font-semibold text-slate-200">WiFi Attack</span>
              </div>
              <button
                onClick={closeAttack}
                className="text-slate-500 hover:text-slate-300 transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            <div className="px-5 py-5 flex-1 space-y-5">
              {/* Target info */}
              <div className="bg-slate-800 rounded-lg px-4 py-3 space-y-2">
                <p className="text-xs text-slate-400">Target Network</p>

                {/* SSID — editable when redacted */}
                {isRedacted(attackTarget.ssid) ? (
                  <div>
                    <div className="flex items-center gap-2 mb-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 text-yellow-400 flex-shrink-0" />
                      <p className="text-xs text-yellow-400">
                        SSID hidden by macOS — select or type the network name
                      </p>
                    </div>
                    <input
                      type="text"
                      list="known-networks-list"
                      value={manualSsid}
                      onChange={(e) => setManualSsid(e.target.value)}
                      disabled={attackRunning}
                      placeholder="Type or pick from saved networks…"
                      autoFocus
                      className="w-full bg-slate-700 border border-yellow-700/60 rounded-lg px-3 py-2 text-sm text-slate-100 placeholder-slate-500 focus:outline-none focus:border-yellow-500 disabled:opacity-50"
                    />
                    {knownNetworks.length > 0 && (
                      <datalist id="known-networks-list">
                        {knownNetworks.map((n) => (
                          <option key={n} value={n} />
                        ))}
                      </datalist>
                    )}
                    {knownNetworks.length > 0 ? (
                      <p className="text-xs text-slate-500 mt-1">
                        {knownNetworks.length} saved network(s) available — start typing or click ▼ to browse
                      </p>
                    ) : (
                      <p className="text-xs text-slate-500 mt-1">
                        Look at the WiFi icon in your menu bar to find the network name
                      </p>
                    )}
                  </div>
                ) : (
                  <div>
                    <p className="font-semibold text-slate-100">{attackTarget.ssid}</p>
                    {attackTarget.bssid && (
                      <p className="text-xs font-mono text-slate-500 mt-0.5">{attackTarget.bssid}</p>
                    )}
                  </div>
                )}

                <p className={`text-xs ${securityColor(attackTarget.security)}`}>
                  {attackTarget.security || "Open"} · {attackTarget.band} · ch {attackTarget.channel || "?"}
                </p>
              </div>

              {/* Authorization warning */}
              <div className="bg-orange-900/20 border border-orange-700/50 rounded-lg px-4 py-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />
                  <p className="text-xs text-orange-300">
                    Only attack networks you own or have explicit written permission to test.
                    Unauthorized access is illegal. Each attempt takes ~8–10 seconds.
                  </p>
                </div>
              </div>

              {/* Config */}
              <div className="space-y-4">
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    Wordlist path (on server)
                  </label>
                  <input
                    type="text"
                    value={attackWordlist}
                    onChange={(e) => setAttackWordlist(e.target.value)}
                    disabled={attackRunning}
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600 disabled:opacity-50"
                    placeholder="wordlists/wifi-passwords.txt"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-400 mb-1.5">
                    Max attempts (1–50)
                  </label>
                  <input
                    type="number"
                    min={1}
                    max={50}
                    value={attackMaxAttempts}
                    onChange={(e) =>
                      setAttackMaxAttempts(Math.min(50, Math.max(1, Number(e.target.value))))
                    }
                    disabled={attackRunning}
                    className="w-full bg-slate-800 border border-slate-600 rounded-lg px-3 py-2 text-sm text-slate-200 focus:outline-none focus:border-cyan-600 disabled:opacity-50"
                  />
                  <p className="text-xs text-slate-500 mt-1">
                    Est. time: ~{Math.ceil(attackMaxAttempts * 9 / 60)}–{Math.ceil(attackMaxAttempts * 10 / 60)} min
                  </p>
                </div>
              </div>

              {/* Attack progress bar + log */}
              {(attackRunning || attackPhase === "done" || attackPhase === "failed") && (
                <div className="bg-[#0f1420] border border-slate-700 rounded-lg overflow-hidden">
                  <div className="px-4 pt-3 pb-2">
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-xs font-semibold text-slate-500 uppercase tracking-wide">Attack Progress</span>
                      <span className="text-xs font-mono text-orange-400">{attackProgress}%</span>
                    </div>
                    <div className="w-full bg-slate-700 rounded-full h-1.5 overflow-hidden">
                      <div
                        className={`h-1.5 rounded-full transition-all duration-500 ${
                          attackPhase === "failed" ? "bg-red-500"
                          : attackPhase === "done" ? "bg-green-500"
                          : "bg-orange-500"
                        }`}
                        style={{ width: `${attackProgress}%` }}
                      />
                    </div>
                    {attackProgressMsg && (
                      <p className="text-xs text-slate-500 mt-1 truncate">{attackProgressMsg}</p>
                    )}
                  </div>

                  <button
                    onClick={() => setShowAttackLog((v) => !v)}
                    className="w-full flex items-center gap-2 px-4 py-1.5 border-t border-slate-700 text-xs text-slate-500 hover:text-slate-300 hover:bg-slate-800/30 transition-colors"
                  >
                    <Terminal className="w-3 h-3" />
                    <span>Log</span>
                    <span className="text-slate-700">({attackLogs.length} lines)</span>
                    {showAttackLog ? <ChevronUp className="w-3 h-3 ml-auto" /> : <ChevronDown className="w-3 h-3 ml-auto" />}
                  </button>

                  {showAttackLog && attackLogs.length > 0 && (
                    <div className="h-36 overflow-y-auto bg-black/40 font-mono text-xs p-2.5 space-y-0.5">
                      {attackLogs.map((entry, i) => (
                        <div key={i} className="flex gap-2 leading-5">
                          <span className="text-slate-700 flex-shrink-0">{entry.time}</span>
                          {entry.pct >= 0 && (
                            <span className="text-orange-500 flex-shrink-0 w-7 text-right">{entry.pct}%</span>
                          )}
                          <span className={`break-all ${
                            entry.msg.startsWith("✓") ? "text-green-400"
                            : entry.msg.startsWith("⚠") ? "text-yellow-400"
                            : "text-slate-400"
                          }`}>
                            {entry.msg}
                          </span>
                        </div>
                      ))}
                      <div ref={attackLogEndRef} />
                    </div>
                  )}
                </div>
              )}

              {/* Result */}
              {attackResult && (
                <div className={`rounded-lg border px-4 py-4 ${
                  attackResult.error
                    ? "bg-red-900/20 border-red-700"
                    : attackResult.password_found
                    ? "bg-green-900/20 border-green-600"
                    : "bg-slate-800 border-slate-600"
                }`}>
                  {attackResult.error ? (
                    <>
                      <p className="text-red-300 font-medium text-sm">Error</p>
                      <p className="text-red-400/80 text-xs mt-1">{attackResult.error}</p>
                    </>
                  ) : attackResult.password_found ? (
                    <>
                      <p className="text-green-300 font-semibold text-sm flex items-center gap-1.5">
                        <CheckCircle className="w-4 h-4" /> Password found!
                      </p>
                      <p className="font-mono text-green-200 text-base mt-2 bg-green-900/30 px-3 py-2 rounded">
                        {attackResult.password}
                      </p>
                      <p className="text-xs text-slate-400 mt-2">
                        Found in {attackResult.attempts} attempt{attackResult.attempts !== 1 ? "s" : ""} •{" "}
                        {attackResult.duration_seconds.toFixed(1)}s
                      </p>
                    </>
                  ) : (
                    <>
                      <p className="text-slate-300 font-medium text-sm">Password not found</p>
                      <p className="text-xs text-slate-400 mt-1">
                        Tried {attackResult.attempts} password{attackResult.attempts !== 1 ? "s" : ""} in{" "}
                        {attackResult.duration_seconds.toFixed(1)}s. Try a larger wordlist.
                      </p>
                    </>
                  )}
                </div>
              )}
            </div>

            {/* Panel footer */}
            <div className="px-5 py-4 border-t border-slate-700 flex gap-3">
              <button
                onClick={runAttack}
                disabled={!canStartAttack}
                title={isRedacted(effectiveSsid) ? "Enter target SSID above first" : undefined}
                className="flex-1 flex items-center justify-center gap-2 bg-orange-600 hover:bg-orange-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium text-sm rounded-lg px-4 py-2.5 transition-colors"
              >
                {attackRunning ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    Attacking…
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4" />
                    Start Attack
                  </>
                )}
              </button>
              <button
                onClick={closeAttack}
                className="px-4 py-2.5 text-sm text-slate-400 hover:text-slate-200 border border-slate-600 hover:border-slate-500 rounded-lg transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
