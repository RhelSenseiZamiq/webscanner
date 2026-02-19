"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { listScans, type ScanListItem } from "@/lib/api";
import { formatDuration, formatTime, totalFindings } from "@/lib/utils";
import StatusBadge from "@/components/StatusBadge";
import SummaryCards from "@/components/SummaryCards";
import NewScanForm from "@/components/NewScanForm";
import StatsPanel from "@/components/StatsPanel";
import { Shield, Plus, RefreshCw, Box, Server, Search } from "lucide-react";

const STATUS_OPTIONS = ["all", "running", "completed", "failed"] as const;
type StatusFilter = (typeof STATUS_OPTIONS)[number];

export default function Home() {
  const [scans, setScans] = useState<ScanListItem[]>([]);
  const [showForm, setShowForm] = useState(false);
  const [loading, setLoading] = useState(true);
  const [apiError, setApiError] = useState(false);

  // Filter state
  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [hasCritical, setHasCritical] = useState(false);
  const [hasHigh, setHasHigh] = useState(false);
  const [searchText, setSearchText] = useState("");

  async function fetchScans() {
    try {
      const data = await listScans();
      setScans(data);
      setApiError(false);
    } catch {
      setApiError(true);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    fetchScans();
    const id = setInterval(fetchScans, 5000);
    return () => clearInterval(id);
  }, []);

  const filteredScans = useMemo(() => {
    return scans.filter((s) => {
      if (statusFilter !== "all" && s.status !== statusFilter) return false;
      if (hasCritical && s.summary.critical === 0) return false;
      if (hasHigh && s.summary.high === 0) return false;
      if (searchText) {
        const q = searchText.toLowerCase();
        if (!s.target_url.toLowerCase().includes(q) && !s.program.toLowerCase().includes(q)) return false;
      }
      return true;
    });
  }, [scans, statusFilter, hasCritical, hasHigh, searchText]);

  return (
    <div className="min-h-screen bg-[#0f1117]">
      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4">
        <div className="max-w-6xl mx-auto flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-6 h-6 text-cyan-400" />
            <span className="text-lg font-semibold text-slate-100">WebScanner</span>
            <span className="text-xs text-slate-500 ml-1">v0.1.0</span>
          </div>
          <div className="flex gap-2">
            <Link
              href="/docker"
              className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-blue-400 border border-slate-700 hover:border-blue-600 px-3 py-1.5 rounded-lg transition-colors"
            >
              <Box className="w-4 h-4" />
              Docker
            </Link>
            <Link
              href="/k8s"
              className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-purple-400 border border-slate-700 hover:border-purple-600 px-3 py-1.5 rounded-lg transition-colors"
            >
              <Server className="w-4 h-4" />
              K8s
            </Link>
            <button
              onClick={fetchScans}
              className="p-2 text-slate-400 hover:text-slate-200 transition-colors"
              title="Refresh"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowForm((v) => !v)}
              className="flex items-center gap-1.5 bg-cyan-600 hover:bg-cyan-500 text-white text-sm font-medium px-3 py-1.5 rounded-lg transition-colors"
            >
              <Plus className="w-4 h-4" />
              New Scan
            </button>
          </div>
        </div>
      </header>

      <main className="max-w-6xl mx-auto px-6 py-8 space-y-8">
        {/* API offline banner */}
        {apiError && (
          <div className="flex items-center gap-2 bg-yellow-900/30 border border-yellow-700/50 text-yellow-300 text-sm px-4 py-3 rounded-lg">
            <span>⚠</span>
            <span>Cannot reach the API — make sure the backend is running on port 8000</span>
          </div>
        )}

        {/* New Scan Form */}
        {showForm && (
          <div className="bg-[#1a1f2e] border border-slate-700 rounded-xl p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-base font-semibold text-slate-100">New Scan</h2>
              <button
                onClick={() => setShowForm(false)}
                className="text-slate-500 hover:text-slate-300 text-sm"
              >
                ✕ Close
              </button>
            </div>
            <NewScanForm />
          </div>
        )}

        {/* Dashboard stats */}
        {!loading && scans.length > 0 && <StatsPanel scans={scans} />}

        {/* Scan History */}
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-base font-semibold text-slate-200">
              Scan History
              {scans.length > 0 && (
                <span className="ml-2 text-xs text-slate-500 font-normal">
                  Showing {filteredScans.length} of {scans.length}
                </span>
              )}
            </h2>
          </div>

          {/* Filter bar */}
          {scans.length > 0 && (
            <div className="flex flex-wrap items-center gap-3 mb-4">
              {/* Search */}
              <div className="relative flex-1 min-w-[180px] max-w-xs">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-500" />
                <input
                  type="text"
                  value={searchText}
                  onChange={(e) => setSearchText(e.target.value)}
                  placeholder="Search URL or program…"
                  className="w-full pl-8 pr-3 py-1.5 bg-slate-800 border border-slate-700 rounded-lg text-sm text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-600"
                />
              </div>

              {/* Status pills */}
              <div className="flex gap-1">
                {STATUS_OPTIONS.map((s) => (
                  <button
                    key={s}
                    onClick={() => setStatusFilter(s)}
                    className={`px-3 py-1 text-xs rounded-full font-medium transition-colors capitalize ${
                      statusFilter === s
                        ? "bg-cyan-600 text-white"
                        : "bg-slate-800 text-slate-400 hover:text-slate-200"
                    }`}
                  >
                    {s}
                  </button>
                ))}
              </div>

              {/* Severity toggles */}
              <label className="flex items-center gap-1.5 cursor-pointer text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={hasCritical}
                  onChange={(e) => setHasCritical(e.target.checked)}
                  className="accent-red-500"
                />
                Has Critical
              </label>
              <label className="flex items-center gap-1.5 cursor-pointer text-xs text-slate-400">
                <input
                  type="checkbox"
                  checked={hasHigh}
                  onChange={(e) => setHasHigh(e.target.checked)}
                  className="accent-orange-500"
                />
                Has High
              </label>
            </div>
          )}

          {loading && <div className="text-slate-500 text-sm">Loading...</div>}

          {!loading && scans.length === 0 && (
            <div className="text-center py-16 text-slate-500">
              <Shield className="w-10 h-10 mx-auto mb-3 opacity-30" />
              <p>No scans yet.</p>
              <button
                onClick={() => setShowForm(true)}
                className="mt-3 text-cyan-400 hover:text-cyan-300 text-sm"
              >
                Start your first scan →
              </button>
            </div>
          )}

          {!loading && scans.length > 0 && filteredScans.length === 0 && (
            <div className="text-center py-10 text-slate-500 text-sm">
              No scans match the current filters.
            </div>
          )}

          <div className="space-y-3">
            {filteredScans.map((scan) => (
              <Link
                key={scan.scan_id}
                href={`/scans/${scan.scan_id}`}
                className="block bg-[#1a1f2e] hover:bg-slate-800/60 border border-slate-800 rounded-xl p-4 transition-colors"
              >
                <div className="flex items-start justify-between gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <StatusBadge status={scan.status} />
                      <span className="text-sm font-medium text-slate-200 truncate">
                        {scan.target_url}
                      </span>
                    </div>
                    <div className="flex gap-3 mt-1 text-xs text-slate-500">
                      <span>{scan.program}</span>
                      <span>{formatTime(scan.created_at)}</span>
                      <span>Duration: {formatDuration(scan.created_at, scan.finished_at)}</span>
                    </div>
                  </div>
                  <div className="flex gap-2 text-xs flex-shrink-0">
                    {(["critical", "high", "medium"] as const).map((sev) =>
                      scan.summary[sev] > 0 ? (
                        <span
                          key={sev}
                          className={`px-1.5 py-0.5 rounded font-medium ${
                            sev === "critical"
                              ? "bg-red-600/20 text-red-400"
                              : sev === "high"
                              ? "bg-orange-600/20 text-orange-400"
                              : "bg-yellow-600/20 text-yellow-400"
                          }`}
                        >
                          {scan.summary[sev]} {sev}
                        </span>
                      ) : null
                    )}
                    {totalFindings(scan.summary) === 0 && scan.status === "completed" && (
                      <span className="text-green-400">Clean</span>
                    )}
                  </div>
                </div>

                {scan.status === "completed" && (
                  <div className="mt-3">
                    <SummaryCards summary={scan.summary} />
                  </div>
                )}
              </Link>
            ))}
          </div>
        </div>
      </main>
    </div>
  );
}
