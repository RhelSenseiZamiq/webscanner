"use client";

import { useState } from "react";
import type { Finding } from "@/lib/api";
import { SEVERITY_ORDER } from "@/lib/utils";
import SeverityBadge from "./SeverityBadge";
import { ChevronDown, ChevronRight } from "lucide-react";

type RemediationStatus = "fixed" | "in_progress" | "accepted" | "";

interface Props {
  findings: Finding[];
  remediation?: Record<string, RemediationStatus>;
  onRemediation?: (findingId: string, status: RemediationStatus) => void;
}

const REMEDIATION_BUTTONS: { value: RemediationStatus; label: string; activeClass: string }[] = [
  { value: "fixed", label: "Fixed", activeClass: "bg-green-700 text-green-100 border-green-600" },
  { value: "in_progress", label: "In Progress", activeClass: "bg-yellow-700 text-yellow-100 border-yellow-600" },
  { value: "accepted", label: "Accepted Risk", activeClass: "bg-slate-600 text-slate-200 border-slate-500" },
];

export default function FindingsTable({ findings, remediation = {}, onRemediation }: Props) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [filter, setFilter] = useState<string>("all");
  const [search, setSearch] = useState("");

  const filtered = findings
    .filter((f) => filter === "all" || f.severity === filter)
    .filter((f) =>
      !search ||
      f.title.toLowerCase().includes(search.toLowerCase()) ||
      f.url.toLowerCase().includes(search.toLowerCase())
    )
    .sort((a, b) =>
      SEVERITY_ORDER.indexOf(a.severity as never) -
      SEVERITY_ORDER.indexOf(b.severity as never)
    );

  function toggle(id: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  function handleRemediation(findingId: string, value: RemediationStatus) {
    if (!onRemediation) return;
    // Clicking the active button clears it
    onRemediation(findingId, remediation[findingId] === value ? "" : value);
  }

  return (
    <div className="space-y-3">
      {/* Filters */}
      <div className="flex gap-2 flex-wrap items-center">
        <input
          type="text"
          placeholder="Search findings..."
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          className="bg-[#1a1f2e] border border-slate-700 rounded px-3 py-1.5 text-sm text-slate-200 placeholder-slate-500 flex-1 min-w-40"
        />
        <div className="flex gap-1">
          {(["all", ...SEVERITY_ORDER] as string[]).map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-2.5 py-1 rounded text-xs font-medium uppercase transition-colors ${
                filter === sev
                  ? "bg-cyan-600 text-white"
                  : "bg-[#1a1f2e] text-slate-400 hover:text-slate-200"
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-8 text-slate-500">
          {findings.length === 0 ? "No findings yet..." : "No findings match filter"}
        </div>
      )}

      {/* Findings list */}
      <div className="space-y-1.5">
        {filtered.map((f) => {
          const isOpen = expanded.has(f.id);
          const remStatus = remediation[f.id] ?? "";
          return (
            <div key={f.id} className="bg-[#1a1f2e] rounded-lg border border-slate-800 overflow-hidden">
              <button
                className="w-full text-left px-4 py-3 flex items-center gap-3 hover:bg-slate-800/40 transition-colors"
                onClick={() => toggle(f.id)}
              >
                {isOpen ? (
                  <ChevronDown className="w-4 h-4 text-slate-500 flex-shrink-0" />
                ) : (
                  <ChevronRight className="w-4 h-4 text-slate-500 flex-shrink-0" />
                )}
                <SeverityBadge severity={f.severity} />
                <span className="text-xs text-slate-500 font-mono bg-slate-800 px-1.5 py-0.5 rounded">
                  {f.module}
                </span>
                <span className="text-sm text-slate-200 flex-1 truncate">{f.title}</span>
                {remStatus && (
                  <span className={`text-xs px-2 py-0.5 rounded border ${
                    REMEDIATION_BUTTONS.find((b) => b.value === remStatus)?.activeClass ?? ""
                  }`}>
                    {REMEDIATION_BUTTONS.find((b) => b.value === remStatus)?.label}
                  </span>
                )}
                <span className="text-xs text-slate-500 truncate max-w-48 hidden md:block">{f.url}</span>
              </button>

              {isOpen && (
                <div className="px-4 pb-4 space-y-3 border-t border-slate-800">
                  {/* Remediation tracker buttons */}
                  {onRemediation && (
                    <div className="flex items-center gap-2 mt-3">
                      <span className="text-xs text-slate-500">Status:</span>
                      {REMEDIATION_BUTTONS.map((btn) => (
                        <button
                          key={btn.value}
                          onClick={() => handleRemediation(f.id, btn.value)}
                          className={`text-xs px-2.5 py-1 rounded border transition-colors ${
                            remStatus === btn.value
                              ? btn.activeClass
                              : "border-slate-700 text-slate-400 hover:text-slate-200"
                          }`}
                        >
                          {btn.label}
                        </button>
                      ))}
                    </div>
                  )}

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                    <div>
                      <div className="text-xs text-slate-500 uppercase mb-1">Description</div>
                      <div className="text-sm text-slate-300">{f.description}</div>
                    </div>
                    <div>
                      <div className="text-xs text-slate-500 uppercase mb-1">Remediation</div>
                      <div className="text-sm text-slate-300">{f.remediation}</div>
                    </div>
                  </div>
                  <div>
                    <div className="text-xs text-slate-500 uppercase mb-1">Evidence</div>
                    <pre className="text-xs text-slate-300 bg-[#0f1117] rounded p-2 overflow-x-auto">
                      {f.evidence}
                    </pre>
                  </div>
                  <div className="flex gap-4 text-xs text-slate-500">
                    <span>URL: <span className="text-slate-400 font-mono">{f.url}</span></span>
                    {f.cwe_id && <span>CWE: <span className="text-slate-400">{f.cwe_id}</span></span>}
                    {f.cvss_score && <span>CVSS: <span className="text-slate-400">{f.cvss_score}</span></span>}
                  </div>
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
