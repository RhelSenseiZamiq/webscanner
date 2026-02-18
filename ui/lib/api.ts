const API_BASE = process.env.NEXT_PUBLIC_API_URL ?? "http://localhost:8000";

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export interface ScanSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

export interface Finding {
  id: string;
  module: string;
  check_name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  url: string;
  evidence: string;
  remediation: string;
  cvss_score: number | null;
  cwe_id: string | null;
  timestamp: string;
}

export interface Scan {
  scan_id: string;
  status: ScanStatus;
  target_url: string;
  program: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  summary: ScanSummary;
  findings: Finding[];
  error: string | null;
}

export interface ScanListItem {
  scan_id: string;
  status: ScanStatus;
  target_url: string;
  program: string;
  created_at: string;
  finished_at: string | null;
  summary: ScanSummary;
}

export interface StartScanPayload {
  target_url: string;
  authorized_domains: string[];
  excluded_paths: string[];
  program: string;
  modules: string[];
  rate_limit: number;
  passive_only: boolean;
  timeout_seconds: number;
  contact_email: string;
  bruteforce_wordlist?: string;
  bruteforce_usernames?: string;
  bruteforce_max_attempts?: number;
}

export async function startScan(payload: StartScanPayload): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err?.detail ?? `HTTP ${res.status}`);
  }
  return res.json();
}

export async function listScans(): Promise<ScanListItem[]> {
  const res = await fetch(`${API_BASE}/api/scans`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export async function getScan(scanId: string): Promise<Scan> {
  const res = await fetch(`${API_BASE}/api/scans/${scanId}`);
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

export function streamScan(
  scanId: string,
  onFinding: (finding: Finding) => void,
  onStatus: (status: ScanStatus) => void,
  onComplete: () => void,
  onError: (err: string) => void,
  onProgress?: (pct: number, message: string) => void,
): () => void {
  const es = new EventSource(`${API_BASE}/api/scans/${scanId}/stream`);

  es.addEventListener("finding", (e) => {
    try {
      const data = JSON.parse(e.data);
      onFinding(data.finding);
    } catch {}
  });

  es.addEventListener("status", (e) => {
    try {
      const data = JSON.parse(e.data);
      onStatus(data.status);
    } catch {}
  });

  es.addEventListener("progress", (e) => {
    try {
      const data = JSON.parse(e.data);
      onProgress?.(data.pct, data.message);
    } catch {}
  });

  es.addEventListener("completed", () => {
    onComplete();
    es.close();
  });

  es.addEventListener("error", (e) => {
    try {
      const data = JSON.parse((e as MessageEvent).data ?? "{}");
      onError(data.error ?? "Stream error");
    } catch {
      onError("Connection lost");
    }
    es.close();
  });

  return () => es.close();
}
