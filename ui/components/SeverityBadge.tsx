"use client";

import { SEVERITY_COLORS } from "@/lib/utils";

interface Props {
  severity: string;
  size?: "sm" | "md";
}

export default function SeverityBadge({ severity, size = "md" }: Props) {
  const cls = SEVERITY_COLORS[severity] ?? "bg-gray-600 text-white";
  const px = size === "sm" ? "px-1.5 py-0.5 text-xs" : "px-2 py-0.5 text-xs font-semibold";
  return (
    <span className={`inline-block rounded ${px} uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}
