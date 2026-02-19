# Changelog

All notable changes to WebScanner are documented here.

Format: `## [version] — YYYY-MM-DD`

---

## [0.3.0] — 2026-02-19

### Added

#### Site Overview panel
Every completed scan report now includes a collapsible **Site Overview** section at the top of the page. Collected automatically during Phase 1 recon and persisted with the scan record so it survives server restarts.

**Sections inside the panel:**

| Section | Contents |
|---------|----------|
| Overview strip | HTTP status code badge, response time, resolved IP, server header, Powered-By, CDN (Cloudflare / CloudFront / Fastly / Akamai / Azure CDN / Varnish / Sucuri / Plesk), language, redirect count |
| Page | Page title, meta description, OG title, OG description, favicon thumbnail |
| Technology | Pill badge for each fingerprinted framework or library (sourced from the recon fingerprint module) |
| SSL Certificate | Issuer, subject CN, expiry date, days-remaining badge (green ≥30 d / yellow ≥7 d / red <7 d), Subject Alternative Names |
| DNS Records | A / MX / NS / TXT records (A via stdlib `socket`, MX/NS/TXT via optional `dnspython`) |
| Crawl Files | robots.txt presence + first 500-character preview, sitemap.xml presence |
| Response Headers | Full collapsible table of all HTTP response headers |

Panel is **collapsed by default** — click the header bar to expand.

**Backend changes:**
- New module `src/webscanner/recon/site_info.py` — `SiteInfo` frozen dataclass + `SiteInfoGatherer` class. All four sub-tasks (HTTP fetch, SSL, DNS, file checks) run concurrently via `asyncio.gather`. Best-effort — individual failures never block the scan.
- `src/webscanner/orchestrator/engine.py` — `run_scan()` accepts a new `on_site_info` callback; called after Phase 1 recon completes with a fully populated `SiteInfo` (technologies filled from fingerprint findings).
- `src/webscanner/api/models.py` — new `SiteInfoResponse` Pydantic model; `ScanResponse` gains `site_info: SiteInfoResponse | None`.
- `src/webscanner/api/store.py` — `ScanRecord` gains `site_info` field; `_record_to_dict` / `_record_from_dict` / `to_response()` all updated so site info is persisted to disk and restored on restart.
- `src/webscanner/api/app.py` — `_run_scan_task()` wires the `on_site_info` callback.

**Frontend changes:**
- New component `ui/components/SiteInfoPanel.tsx` — collapsible panel with all sections above.
- `ui/lib/api.ts` — new `SiteInfo` TypeScript interface; `Scan` gains `site_info: SiteInfo | null`.
- `ui/app/scans/[id]/page.tsx` — renders `<SiteInfoPanel>` above the findings summary when `scan.site_info` is present.

---

## [0.2.0] — 2026-02-19

### Added

- **Cancel running scan** — `POST /api/scans/{id}/cancel` endpoint cancels the asyncio task and immediately persists the final state. A red **Stop Scan** button appears in the scan detail header while a scan is running.
- **Export findings** — `GET /api/scans/{id}/export?format=json|csv|html` endpoint. The HTML export is a fully self-contained single-file report. A dropdown **Export** button appears on completed scan pages.
- **Filter & search on homepage** — live search bar (URL or program name), status pill filters (All / Running / Completed / Failed), Has Critical and Has High checkboxes. All filtering is client-side.
- **Dashboard statistics panel** — shown above the scan list when at least one scan exists. Shows total / completed / running / failed count cards, a stacked severity bar chart across all completed scans, and a success-rate progress bar. Extracted into `ui/components/StatsPanel.tsx`.
- **Remediation tracker** — per-finding status buttons on each completed scan: Fixed (green), In Progress (yellow), Accepted Risk (grey). State is stored in `localStorage` keyed by scan ID and survives page reloads. A progress bar above the findings list shows resolved count and percentage.
- **Docker + docker-compose deployment** — `Dockerfile.api`, `Dockerfile.ui`, and `docker-compose.yml` added. `docker compose up --build` starts both services. `ui/next.config.ts` updated with `output: "standalone"` and an `API_URL` environment variable for the internal proxy.

### Fixed

- `DELETE /api/scans/{id}` was validating the record but never removing it — `store.delete()` is now called correctly.
- `_load_from_disk()` was sorting files ascending (oldest first), causing the wrong 30 files to be loaded after a restart — sort is now descending (newest first).
- API connection failures on the homepage were silently swallowed — a yellow warning banner is now shown when the backend is unreachable.
- HTML export was building raw f-string HTML from finding fields — all user-controlled values are now wrapped with `html.escape()` to prevent XSS in exported reports.
- `asyncio.create_task()` result was immediately discarded, allowing the GC to cancel tasks before completion — tasks are now held in a module-level `_background_tasks` set with a `done_callback` that removes them on completion.
- `asyncio.CancelledError` was being caught by the broad `except Exception` block in `_run_scan_task()` — an explicit `except asyncio.CancelledError: raise` is now added before the general handler.

---

## [0.1.0] — initial release

### Added

- Web vulnerability scanning across four module groups:
  - **Recon** — subdomain enumeration (DNS brute-force + crt.sh certificate transparency), async port scanning, hidden path discovery (wordlist), tech-stack fingerprinting
  - **Headers** — security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), TLS version and certificate expiry, cookie flags (Secure / HttpOnly / SameSite)
  - **OWASP** — SQL injection (error-based + time-based), reflected and DOM-based XSS, open redirects, CSRF token absence, SSRF, exposed admin panels, debug mode leakage, CORS misconfigurations, directory listing, secrets/API keys in responses, path traversal / LFI (CWE-22), OS command injection (CWE-78), SSTI (CWE-94), HTTP method tampering (TRACE / PUT / DELETE)
  - **API security** — REST endpoint discovery, OpenAPI/Swagger and GraphQL introspection, JWT `none` algorithm bypass, missing authentication, IDOR via numeric ID enumeration, rate limit absence, malformed input handling
- Web brute force — auto-detects HTTP Basic auth and HTML login forms, tests credentials from a wordlist; scope-enforced and rate-limited
- Docker security scanner — static analysis of Dockerfiles and `docker-compose` files, optional live container inspection via Docker daemon
- Kubernetes security scanner — static analysis of YAML manifests, optional live cluster checks via `kubectl`
- FastAPI backend with Server-Sent Events (SSE) streaming for real-time scan progress
- Next.js 15 dark-themed web UI
- Typer CLI with Rich terminal output
- JSON, HTML, and terminal report formats
- Async token-bucket rate limiter (default 5 req/s, configurable)
- Three-layer authorization gate (scope YAML → domain allowlist → path exclusions)
- On-disk scan persistence (`data/scans/*.json`, last 30 scans)
