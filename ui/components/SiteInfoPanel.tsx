"use client";

import { useState } from "react";
import { ChevronDown, ChevronUp, Globe, Cpu, Lock, Server, FileText, AlignLeft } from "lucide-react";
import type { SiteInfo } from "@/lib/api";

interface Props {
  siteInfo: SiteInfo;
}

export default function SiteInfoPanel({ siteInfo }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [showHeaders, setShowHeaders] = useState(false);

  const headerCount = Object.keys(siteInfo.response_headers).length;

  return (
    <div className="bg-[#1a1f2e] border border-slate-800 rounded-xl overflow-hidden">
      {/* Toggle header */}
      <button
        onClick={() => setExpanded((v) => !v)}
        className="w-full flex items-center justify-between px-5 py-4 text-left hover:bg-slate-800/30 transition-colors"
      >
        <div className="flex items-center gap-2 min-w-0">
          <Globe className="w-4 h-4 text-cyan-400 flex-shrink-0" />
          <span className="text-sm font-semibold text-slate-200">Site Overview</span>
          <span className="text-xs text-slate-500 truncate ml-1">{siteInfo.final_url}</span>
        </div>
        {expanded
          ? <ChevronUp className="w-4 h-4 text-slate-400 flex-shrink-0" />
          : <ChevronDown className="w-4 h-4 text-slate-400 flex-shrink-0" />}
      </button>

      {expanded && (
        <div className="border-t border-slate-800 divide-y divide-slate-800">

          {/* ── Overview strip ── */}
          <div className="px-5 py-4 flex flex-wrap gap-2">
            <Chip
              label="Status"
              value={String(siteInfo.status_code)}
              color={siteInfo.status_code > 0 && siteInfo.status_code < 400 ? "green" : "red"}
            />
            <Chip label="Response" value={`${siteInfo.response_time_ms} ms`} />
            {siteInfo.ip_address && <Chip label="IP" value={siteInfo.ip_address} />}
            {siteInfo.server && <Chip label="Server" value={siteInfo.server} />}
            {siteInfo.powered_by && <Chip label="Powered By" value={siteInfo.powered_by} />}
            {siteInfo.cdn && <Chip label="CDN" value={siteInfo.cdn} color="cyan" />}
            {siteInfo.language && <Chip label="Lang" value={siteInfo.language} />}
            {siteInfo.redirect_chain.length > 1 && (
              <Chip label="Redirects" value={String(siteInfo.redirect_chain.length - 1)} color="yellow" />
            )}
          </div>

          {/* ── Page Metadata ── */}
          {(siteInfo.title || siteInfo.description || siteInfo.favicon_url || siteInfo.og_title || siteInfo.og_description) && (
            <SectionBlock icon={<Globe className="w-3.5 h-3.5" />} title="Page">
              <dl className="space-y-2 text-sm">
                {siteInfo.title && <Row label="Title" value={siteInfo.title} />}
                {siteInfo.description && <Row label="Description" value={siteInfo.description} />}
                {siteInfo.og_title && <Row label="OG Title" value={siteInfo.og_title} />}
                {siteInfo.og_description && <Row label="OG Description" value={siteInfo.og_description} />}
                {siteInfo.favicon_url && (
                  <div className="flex gap-3">
                    <dt className="text-slate-500 w-36 flex-shrink-0 text-sm">Favicon</dt>
                    <dd className="text-slate-300 flex items-center gap-2 min-w-0">
                      {/* eslint-disable-next-line @next/next/no-img-element */}
                      <img
                        src={siteInfo.favicon_url}
                        alt=""
                        width={16}
                        height={16}
                        className="w-4 h-4 flex-shrink-0"
                        onError={(e) => { (e.currentTarget as HTMLImageElement).style.display = "none"; }}
                      />
                      <span className="text-xs text-slate-400 truncate">{siteInfo.favicon_url}</span>
                    </dd>
                  </div>
                )}
              </dl>
            </SectionBlock>
          )}

          {/* ── Technology Stack ── */}
          {siteInfo.technologies.length > 0 && (
            <SectionBlock icon={<Cpu className="w-3.5 h-3.5" />} title="Technology">
              <div className="flex flex-wrap gap-2">
                {siteInfo.technologies.map((tech) => (
                  <span
                    key={tech}
                    className="px-2.5 py-1 bg-slate-700 text-slate-300 rounded-lg text-xs font-medium"
                  >
                    {tech}
                  </span>
                ))}
              </div>
            </SectionBlock>
          )}

          {/* ── SSL Certificate ── */}
          <SectionBlock icon={<Lock className="w-3.5 h-3.5" />} title="SSL Certificate">
            {siteInfo.ssl_issuer ? (
              <dl className="space-y-2 text-sm">
                <Row label="Issuer" value={siteInfo.ssl_issuer} />
                <Row label="Subject" value={siteInfo.ssl_subject ?? "—"} />
                {siteInfo.ssl_expiry && (
                  <div className="flex gap-3 items-center">
                    <dt className="text-slate-500 w-36 flex-shrink-0 text-sm">Expiry</dt>
                    <dd className="text-slate-300 flex items-center gap-2">
                      <span>{siteInfo.ssl_expiry.slice(0, 10)}</span>
                      {siteInfo.ssl_days_remaining !== null && (
                        <span className={`px-1.5 py-0.5 rounded text-xs font-bold ${
                          siteInfo.ssl_days_remaining < 7
                            ? "bg-red-800/60 text-red-300"
                            : siteInfo.ssl_days_remaining < 30
                              ? "bg-yellow-800/60 text-yellow-300"
                              : "bg-green-800/60 text-green-300"
                        }`}>
                          {siteInfo.ssl_days_remaining}d
                        </span>
                      )}
                    </dd>
                  </div>
                )}
                {siteInfo.ssl_sans.length > 0 && (
                  <div className="flex gap-3">
                    <dt className="text-slate-500 w-36 flex-shrink-0 text-sm">SANs</dt>
                    <dd className="text-slate-300 text-xs font-mono break-all">
                      {siteInfo.ssl_sans.join(", ")}
                    </dd>
                  </div>
                )}
              </dl>
            ) : (
              <p className="text-sm text-slate-500 italic">No SSL certificate (HTTP only or unreachable)</p>
            )}
          </SectionBlock>

          {/* ── DNS Records ── */}
          <SectionBlock icon={<Server className="w-3.5 h-3.5" />} title="DNS Records">
            <table className="text-xs w-full font-mono">
              <tbody>
                {([
                  { type: "A", records: siteInfo.dns_a },
                  { type: "MX", records: siteInfo.dns_mx },
                  { type: "NS", records: siteInfo.dns_ns },
                  { type: "TXT", records: siteInfo.dns_txt },
                ] as const).map(({ type, records }) => (
                  <tr key={type} className="border-b border-slate-800 last:border-0">
                    <td className="py-1.5 pr-5 text-slate-500 w-10 align-top">{type}</td>
                    <td className="py-1.5 text-slate-300 break-all">
                      {records.length
                        ? records.join(", ")
                        : <span className="text-slate-600">—</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </SectionBlock>

          {/* ── Crawl Files ── */}
          <SectionBlock icon={<FileText className="w-3.5 h-3.5" />} title="Crawl Files">
            <div className="space-y-3 text-sm">
              <div className="space-y-1.5">
                <div className="flex items-center gap-2">
                  <span className={`w-2 h-2 rounded-full flex-shrink-0 ${siteInfo.has_robots_txt ? "bg-green-400" : "bg-slate-600"}`} />
                  <span className="text-slate-300">robots.txt</span>
                  {!siteInfo.has_robots_txt && <span className="text-slate-600 text-xs">not found</span>}
                </div>
                {siteInfo.robots_txt_preview && (
                  <pre className="text-xs bg-slate-950 rounded p-2.5 text-slate-400 overflow-x-auto whitespace-pre-wrap max-h-28 ml-4">
                    {siteInfo.robots_txt_preview}
                  </pre>
                )}
              </div>
              <div className="flex items-center gap-2">
                <span className={`w-2 h-2 rounded-full flex-shrink-0 ${siteInfo.has_sitemap ? "bg-green-400" : "bg-slate-600"}`} />
                <span className="text-slate-300">sitemap.xml</span>
                {!siteInfo.has_sitemap && <span className="text-slate-600 text-xs">not found</span>}
              </div>
            </div>
          </SectionBlock>

          {/* ── Response Headers ── */}
          {headerCount > 0 && (
            <div className="px-5 py-4">
              <button
                onClick={() => setShowHeaders((v) => !v)}
                className="flex items-center gap-2 text-xs font-semibold text-slate-400 uppercase tracking-wide hover:text-slate-200 transition-colors mb-0"
              >
                <AlignLeft className="w-3.5 h-3.5" />
                Response Headers
                <span className="text-slate-600 normal-case font-normal">({headerCount})</span>
                {showHeaders
                  ? <ChevronUp className="w-3.5 h-3.5" />
                  : <ChevronDown className="w-3.5 h-3.5" />}
              </button>
              {showHeaders && (
                <table className="mt-3 text-xs w-full font-mono">
                  <tbody>
                    {Object.entries(siteInfo.response_headers).map(([k, v]) => (
                      <tr key={k} className="border-b border-slate-800 last:border-0">
                        <td className="py-1 pr-5 text-slate-500 align-top whitespace-nowrap">{k}</td>
                        <td className="py-1 text-slate-300 break-all">{v}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

        </div>
      )}
    </div>
  );
}

// ── Small helpers ──────────────────────────────────────────────────────────

function SectionBlock({
  icon,
  title,
  children,
}: {
  icon: React.ReactNode;
  title: string;
  children: React.ReactNode;
}) {
  return (
    <div className="px-5 py-4">
      <div className="flex items-center gap-1.5 text-xs font-semibold text-slate-400 uppercase tracking-wide mb-3">
        {icon}
        {title}
      </div>
      {children}
    </div>
  );
}

function Row({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex gap-3">
      <dt className="text-slate-500 w-36 flex-shrink-0 text-sm">{label}</dt>
      <dd className="text-slate-300 break-words min-w-0">{value}</dd>
    </div>
  );
}

type ChipColor = "slate" | "green" | "red" | "cyan" | "yellow";

function Chip({ label, value, color = "slate" }: { label: string; value: string; color?: ChipColor }) {
  const colors: Record<ChipColor, string> = {
    slate:  "bg-slate-800 text-slate-300",
    green:  "bg-green-900/50 text-green-300",
    red:    "bg-red-900/50 text-red-300",
    cyan:   "bg-cyan-900/50 text-cyan-300",
    yellow: "bg-yellow-900/50 text-yellow-300",
  };
  return (
    <div className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs ${colors[color]}`}>
      <span className="text-slate-500">{label}</span>
      <span className="font-medium">{value}</span>
    </div>
  );
}
