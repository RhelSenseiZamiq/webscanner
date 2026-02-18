"use client";

import type { ScanStatus } from "@/lib/api";

const STATUS_STYLES: Record<ScanStatus, string> = {
  pending: "bg-slate-700 text-slate-300",
  running: "bg-cyan-900 text-cyan-300 animate-pulse",
  completed: "bg-green-900 text-green-300",
  failed: "bg-red-900 text-red-300",
};

export default function StatusBadge({ status }: { status: ScanStatus }) {
  return (
    <span className={`inline-block px-2 py-0.5 rounded text-xs font-medium uppercase ${STATUS_STYLES[status]}`}>
      {status}
    </span>
  );
}
