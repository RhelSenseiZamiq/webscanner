"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { startScan } from "@/lib/api";
import { Shield, Plus, X } from "lucide-react";

export default function NewScanForm() {
  const router = useRouter();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [targetUrl, setTargetUrl] = useState("");
  const [program, setProgram] = useState("");
  const [domains, setDomains] = useState<string[]>([""]);
  const [excludedPaths, setExcludedPaths] = useState("/logout\n/delete-account");
  const [modules, setModules] = useState<Set<string>>(
    new Set(["recon", "headers", "owasp", "api"])
  );
  const [bruteforceWordlist, setBruteforceWordlist] = useState("wordlists/common_passwords.txt");
  const [bruteforceMaxAttempts, setBruteforceMaxAttempts] = useState(300);
  const [rateLimit, setRateLimit] = useState(5);
  const [passiveOnly, setPassiveOnly] = useState(false);
  const [contactEmail, setContactEmail] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);

  function toggleModule(mod: string) {
    setModules((prev) => {
      const next = new Set(prev);
      next.has(mod) ? next.delete(mod) : next.add(mod);
      return next;
    });
  }

  function updateDomain(i: number, value: string) {
    setDomains((prev) => prev.map((d, idx) => (idx === i ? value : d)));
  }

  function removeDomain(i: number) {
    setDomains((prev) => prev.filter((_, idx) => idx !== i));
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError(null);

    const cleanDomains = domains.filter((d) => d.trim());
    if (!cleanDomains.length) {
      setError("At least one authorized domain is required");
      return;
    }
    if (modules.size === 0) {
      setError("Select at least one module");
      return;
    }

    setLoading(true);
    try {
      const scan = await startScan({
        target_url: targetUrl,
        authorized_domains: cleanDomains,
        excluded_paths: excludedPaths
          .split("\n")
          .map((p) => p.trim())
          .filter(Boolean),
        program,
        modules: Array.from(modules),
        rate_limit: rateLimit,
        passive_only: passiveOnly,
        timeout_seconds: 10,
        contact_email: contactEmail,
        bruteforce_wordlist: modules.has("bruteforce") ? bruteforceWordlist : "",
        bruteforce_max_attempts: bruteforceMaxAttempts,
      });
      router.push(`/scans/${scan.scan_id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start scan");
      setLoading(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-5">
      {/* Target URL */}
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Target URL <span className="text-red-400">*</span>
        </label>
        <input
          required
          type="url"
          placeholder="https://example.com"
          value={targetUrl}
          onChange={(e) => setTargetUrl(e.target.value)}
          className="w-full bg-[#0f1117] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
        />
      </div>

      {/* Program */}
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Bug Bounty Program <span className="text-red-400">*</span>
        </label>
        <input
          required
          type="text"
          placeholder="example-bug-bounty"
          value={program}
          onChange={(e) => setProgram(e.target.value)}
          className="w-full bg-[#0f1117] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
        />
      </div>

      {/* Authorized Domains */}
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-1">
          Authorized Domains <span className="text-red-400">*</span>
        </label>
        <div className="space-y-2">
          {domains.map((d, i) => (
            <div key={i} className="flex gap-2">
              <input
                type="text"
                placeholder="example.com"
                value={d}
                onChange={(e) => updateDomain(i, e.target.value)}
                className="flex-1 bg-[#0f1117] border border-slate-700 rounded-lg px-3 py-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 transition-colors"
              />
              {domains.length > 1 && (
                <button
                  type="button"
                  onClick={() => removeDomain(i)}
                  className="p-2 text-slate-500 hover:text-red-400 transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              )}
            </div>
          ))}
          <button
            type="button"
            onClick={() => setDomains((prev) => [...prev, ""])}
            className="flex items-center gap-1 text-sm text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            <Plus className="w-3.5 h-3.5" /> Add domain
          </button>
        </div>
      </div>

      {/* Modules */}
      <div>
        <label className="block text-sm font-medium text-slate-300 mb-2">Scan Modules</label>
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
          {[
            { id: "recon", label: "Recon", hint: "DNS, ports, paths" },
            { id: "headers", label: "Headers", hint: "CSP, HSTS, TLS" },
            { id: "owasp", label: "OWASP", hint: "SQLi, XSS, SSRF…" },
            { id: "api", label: "API", hint: "Endpoints, auth" },
            { id: "bruteforce", label: "Brute Force", hint: "Login + HTTP auth" },
          ].map(({ id, label, hint }) => (
            <button
              key={id}
              type="button"
              onClick={() => toggleModule(id)}
              title={hint}
              className={`px-3 py-2 rounded-lg text-sm font-medium border transition-all ${
                modules.has(id)
                  ? "bg-cyan-600/20 border-cyan-500 text-cyan-300"
                  : "bg-[#0f1117] border-slate-700 text-slate-400 hover:border-slate-500"
              }`}
            >
              {label}
            </button>
          ))}
        </div>
        {modules.has("bruteforce") && (
          <p className="mt-1.5 text-xs text-amber-400/80">
            Brute force is active — only run against authorized targets.
          </p>
        )}
      </div>

      {/* Advanced */}
      <div>
        <button
          type="button"
          onClick={() => setShowAdvanced((v) => !v)}
          className="text-sm text-slate-400 hover:text-slate-300 transition-colors"
        >
          {showAdvanced ? "▲" : "▼"} Advanced options
        </button>

        {showAdvanced && (
          <div className="mt-3 space-y-4 p-4 bg-[#0f1117] rounded-lg border border-slate-800">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <label className="block text-xs text-slate-400 mb-1">Rate limit (req/s)</label>
                <input
                  type="number"
                  min={0.5}
                  max={20}
                  step={0.5}
                  value={rateLimit}
                  onChange={(e) => setRateLimit(Number(e.target.value))}
                  className="w-full bg-[#1a1f2e] border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                />
              </div>
              <div>
                <label className="block text-xs text-slate-400 mb-1">Contact email</label>
                <input
                  type="email"
                  placeholder="you@example.com"
                  value={contactEmail}
                  onChange={(e) => setContactEmail(e.target.value)}
                  className="w-full bg-[#1a1f2e] border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs text-slate-400 mb-1">Excluded paths (one per line)</label>
              <textarea
                rows={3}
                value={excludedPaths}
                onChange={(e) => setExcludedPaths(e.target.value)}
                className="w-full bg-[#1a1f2e] border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 font-mono focus:outline-none focus:border-cyan-500"
              />
            </div>

            <div className="flex items-center gap-2">
              <input
                type="checkbox"
                id="passive"
                checked={passiveOnly}
                onChange={(e) => setPassiveOnly(e.target.checked)}
                className="w-4 h-4 rounded border-slate-600"
              />
              <label htmlFor="passive" className="text-sm text-slate-300">
                Passive only (no active injection probes)
              </label>
            </div>

            {modules.has("bruteforce") && (
              <div className="border-t border-slate-700 pt-4 space-y-3">
                <p className="text-xs font-medium text-slate-400 uppercase tracking-wide">
                  Brute Force Options
                </p>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    Password wordlist path (server-side)
                  </label>
                  <input
                    type="text"
                    value={bruteforceWordlist}
                    onChange={(e) => setBruteforceWordlist(e.target.value)}
                    placeholder="wordlists/common_passwords.txt"
                    className="w-full bg-[#1a1f2e] border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 font-mono placeholder-slate-600 focus:outline-none focus:border-cyan-500"
                  />
                  <p className="mt-1 text-xs text-slate-500">
                    Run <code className="text-cyan-400">webscanner wordlists</code> to download rockyou &amp; SecLists
                  </p>
                </div>
                <div>
                  <label className="block text-xs text-slate-400 mb-1">
                    Max attempts per endpoint
                  </label>
                  <input
                    type="number"
                    min={10}
                    max={5000}
                    step={50}
                    value={bruteforceMaxAttempts}
                    onChange={(e) => setBruteforceMaxAttempts(Number(e.target.value))}
                    className="w-32 bg-[#1a1f2e] border border-slate-700 rounded px-2 py-1.5 text-sm text-slate-200 focus:outline-none focus:border-cyan-500"
                  />
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-700 rounded-lg px-3 py-2 text-sm text-red-300">
          {error}
        </div>
      )}

      {/* Safety notice */}
      <div className="bg-amber-900/20 border border-amber-700/40 rounded-lg px-3 py-2 flex gap-2 text-xs text-amber-300/80">
        <Shield className="w-4 h-4 flex-shrink-0 mt-0.5" />
        By starting a scan you confirm you have explicit written authorization to test the target.
      </div>

      <button
        type="submit"
        disabled={loading}
        className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 disabled:cursor-not-allowed text-white font-medium rounded-lg py-2.5 transition-colors"
      >
        {loading ? "Starting scan..." : "Start Scan"}
      </button>
    </form>
  );
}
