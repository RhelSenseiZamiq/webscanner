"use client";

import type { ScanSummary } from "@/lib/api";
import { SEVERITY_TEXT, SEVERITY_BORDER, SEVERITY_ORDER } from "@/lib/utils";

export default function SummaryCards({ summary }: { summary: ScanSummary }) {
  return (
    <div className="grid grid-cols-5 gap-3">
      {SEVERITY_ORDER.map((sev) => (
        <div
          key={sev}
          className={`bg-[#1a1f2e] rounded-lg p-3 border-l-4 ${SEVERITY_BORDER[sev]} text-center`}
        >
          <div className={`text-2xl font-bold ${SEVERITY_TEXT[sev]}`}>
            {summary[sev as keyof ScanSummary]}
          </div>
          <div className="text-xs text-slate-400 uppercase mt-0.5">{sev}</div>
        </div>
      ))}
    </div>
  );
}
