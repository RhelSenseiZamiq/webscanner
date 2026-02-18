import type { ScanSummary } from "./api";

export const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-400 text-black",
  low: "bg-blue-500 text-white",
  info: "bg-gray-500 text-white",
};

export const SEVERITY_BORDER: Record<string, string> = {
  critical: "border-red-600",
  high: "border-orange-500",
  medium: "border-yellow-400",
  low: "border-blue-500",
  info: "border-gray-500",
};

export const SEVERITY_TEXT: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  info: "text-gray-400",
};

export function totalFindings(summary: ScanSummary): number {
  return (
    summary.critical +
    summary.high +
    summary.medium +
    summary.low +
    summary.info
  );
}

export function formatDuration(start: string | null, end: string | null): string {
  if (!start) return "—";
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.round((e - s) / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  const rem = sec % 60;
  return `${min}m ${rem}s`;
}

export function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}
