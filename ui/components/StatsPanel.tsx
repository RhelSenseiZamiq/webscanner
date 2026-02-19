"use client";

import type { ScanListItem } from "@/lib/api";

interface Props {
  scans: ScanListItem[];
}

const SEV_CONFIG = [
  { key: "critical" as const, label: "Critical", color: "#f44", bg: "bg-red-500" },
  { key: "high" as const, label: "High", color: "#f80", bg: "bg-orange-500" },
  { key: "medium" as const, label: "Medium", color: "#fc0", bg: "bg-yellow-400" },
  { key: "low" as const, label: "Low", color: "#48f", bg: "bg-blue-500" },
  { key: "info" as const, label: "Info", color: "#888", bg: "bg-slate-500" },
];

export default function StatsPanel({ scans }: Props) {
  const completed = scans.filter((s) => s.status === "completed");
  const running = scans.filter((s) => s.status === "running").length;
  const failed = scans.filter((s) => s.status === "failed").length;
  const successRate = scans.length > 0 ? Math.round((completed.length / scans.length) * 100) : 0;

  // Aggregate severity totals from completed scans
  const totals = SEV_CONFIG.map(({ key }) => ({
    key,
    count: completed.reduce((sum, s) => sum + s.summary[key], 0),
  }));
  const totalFindings = totals.reduce((sum, t) => sum + t.count, 0);

  return (
    <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl p-5">
      <h2 className="text-sm font-semibold text-slate-400 uppercase tracking-wide mb-4">
        Dashboard Overview
      </h2>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 mb-5">
        <StatCard label="Total Scans" value={scans.length} color="text-cyan-400" />
        <StatCard label="Completed" value={completed.length} color="text-green-400" />
        <StatCard label="Running" value={running} color="text-blue-400" />
        <StatCard label="Failed" value={failed} color="text-red-400" />
      </div>

      {/* Severity bar chart */}
      {totalFindings > 0 && (
        <div className="mb-4">
          <div className="flex items-center justify-between mb-1.5">
            <span className="text-xs text-slate-400">Findings by Severity</span>
            <span className="text-xs text-slate-500">{totalFindings} total</span>
          </div>
          {/* Stacked bar */}
          <div className="flex h-3 rounded-full overflow-hidden w-full bg-slate-700">
            {totals.map(({ key, count }) => {
              if (count === 0) return null;
              const pct = (count / totalFindings) * 100;
              const cfg = SEV_CONFIG.find((c) => c.key === key)!;
              return (
                <div
                  key={key}
                  className={`${cfg.bg} h-full transition-all`}
                  style={{ width: `${pct}%` }}
                  title={`${cfg.label}: ${count}`}
                />
              );
            })}
          </div>
          {/* Legend */}
          <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
            {totals.filter((t) => t.count > 0).map(({ key, count }) => {
              const cfg = SEV_CONFIG.find((c) => c.key === key)!;
              return (
                <span key={key} className="flex items-center gap-1 text-xs text-slate-400">
                  <span className={`w-2 h-2 rounded-sm ${cfg.bg}`} />
                  {cfg.label}: {count}
                </span>
              );
            })}
          </div>
        </div>
      )}

      {/* Success rate */}
      <div>
        <div className="flex items-center justify-between mb-1">
          <span className="text-xs text-slate-400">Scan Success Rate</span>
          <span className="text-xs font-mono text-slate-300">{successRate}%</span>
        </div>
        <div className="w-full bg-slate-700 rounded-full h-1.5">
          <div
            className="bg-green-500 h-1.5 rounded-full transition-all"
            style={{ width: `${successRate}%` }}
          />
        </div>
      </div>
    </div>
  );
}

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="bg-slate-800/50 rounded-lg px-4 py-3 text-center">
      <div className={`text-2xl font-bold ${color}`}>{value}</div>
      <div className="text-xs text-slate-500 mt-0.5">{label}</div>
    </div>
  );
}
