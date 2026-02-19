# WebScanner

A security scanner built for authorized testing. Covers web vulnerabilities, Docker misconfigurations, and Kubernetes security — all accessible from a dark-themed web UI or straight from the terminal.

> **Important:** This tool is for authorized testing only. It will refuse to run without a scope file that explicitly confirms you have permission to scan the target.

---

## Changelog

### v0.3.0 — 2026-02-19

**New features**
- **Site Overview panel** — every completed scan report now includes a collapsible Site Overview section at the top of the report. It is collected automatically during Phase 1 recon and persists with the scan record across server restarts. Sections:
  - *Overview strip* — HTTP status code badge, response time, resolved IP address, server header, Powered-By, CDN detection (Cloudflare, CloudFront, Fastly, Akamai, Azure CDN, Varnish, Sucuri, Plesk), language, redirect count
  - *Page* — page title, meta description, OG title and description, favicon thumbnail
  - *Technology* — pill badges for every fingerprinted framework or library
  - *SSL Certificate* — issuer, subject, expiry date, days-remaining badge (green ≥30 days, yellow ≥7 days, red <7 days), Subject Alternative Names
  - *DNS Records* — A / MX / NS / TXT records in a compact table (A via standard library, MX/NS/TXT via optional `dnspython`)
  - *Crawl Files* — robots.txt presence with a preview of the first 500 characters, sitemap.xml presence
  - *Response Headers* — full collapsible table of all HTTP response headers
- Panel is **collapsed by default**; click the header to expand.

---

### v0.2.0 — 2026-02-19

**New features**
- **Cancel running scan** — stop any in-progress scan from the web UI with a single click; the backend cancels the asyncio task and persists the final state immediately.
- **Export findings** — download completed scan results as JSON, CSV, or a self-contained HTML report directly from the scan detail page.
- **Filter & search** — homepage now has a live search bar (filter by URL or program name), status pill filters (All / Running / Completed / Failed), and Has Critical / Has High checkboxes.
- **Dashboard statistics** — a stats panel above the scan list shows total / completed / running / failed counts, a stacked severity bar chart across all completed scans, and an overall success rate bar.
- **Remediation tracker** — mark individual findings as Fixed, In Progress, or Accepted Risk. State is persisted in `localStorage` and survives page reloads. A progress bar above the findings list shows how many findings have been resolved.
- **Docker + docker-compose deployment** — `Dockerfile.api`, `Dockerfile.ui`, and `docker-compose.yml` added for one-command containerised deployment (`docker compose up --build`).

**Bug fixes**
- `DELETE /api/scans/{id}` was validating but never actually deleting the record — fixed.
- Scan history loaded oldest scans first after a server restart instead of newest — fixed sort order in `_load_from_disk()`.
- API connection errors were silently swallowed; the homepage now shows a warning banner when the backend is unreachable.
- HTML export output now uses `html.escape()` on all finding fields to prevent XSS in exported reports.
- Background scan tasks are now kept in a strong-reference set so they cannot be garbage-collected before completion.

---

### v0.1.0 — initial release

- Web vulnerability scanning (recon, headers, OWASP, API security, brute force)
- Docker security scanner (static + live)
- Kubernetes security scanner (static + live)
- FastAPI backend with Server-Sent Events streaming
- Next.js dark-themed web UI
- CLI with Typer + Rich output
- JSON / HTML / terminal report formats

---

## What it checks

### Web Vulnerability Scanning

**Security Headers & SSL**
Missing or misconfigured HTTP security headers (CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy), TLS version and certificate expiry, and cookie flags (Secure, HttpOnly, SameSite).

**Reconnaissance**
Subdomain enumeration via DNS brute-force and certificate transparency logs (crt.sh), port scanning, hidden path discovery, and tech stack fingerprinting.

**OWASP Top 10 Active Checks**
SQL injection (error-based and time-based), reflected and DOM-based XSS, open redirects, CSRF token absence, SSRF via URL parameters, exposed admin panels, debug mode leakage, CORS misconfigurations, directory listing, secrets/API keys in responses, path traversal / LFI (CWE-22), OS command injection (CWE-78), server-side template injection / SSTI (CWE-94), and HTTP method tampering (TRACE, PUT, DELETE).

**API Security**
REST endpoint discovery, OpenAPI/Swagger and GraphQL introspection checks, JWT `none` algorithm bypass, missing authentication, IDOR via numeric ID enumeration, rate limit absence, and malformed input handling.

**Web Brute Force**
Detects HTTP Basic auth and HTML login forms, then tests credentials from a wordlist. Scope-enforced, rate-limited.

---

### Docker Security Scanner

Static analysis of Dockerfiles and `docker-compose` files, plus optional live inspection of running containers.

**Dockerfile checks:**

| Check | Severity |
|-------|---------|
| No `USER` instruction — runs as root | HIGH |
| `FROM *:latest` — unpinned image tag | MEDIUM |
| `ADD` with remote URL | LOW |
| Secret hardcoded in `ENV` | CRITICAL |
| `RUN curl … \| sh` — pipe-to-shell | HIGH |
| `EXPOSE 22` — SSH in container | MEDIUM |

**docker-compose.yml checks:**

| Check | Severity |
|-------|---------|
| `privileged: true` | CRITICAL |
| `network_mode: host` | HIGH |
| Docker socket mounted (`/var/run/docker.sock`) | CRITICAL |
| `cap_add: [ALL/SYS_ADMIN/SYS_PTRACE/NET_ADMIN]` | HIGH |
| Secret in `environment:` block | CRITICAL |

**Live container checks** (optional, requires Docker daemon):

| Check | Severity |
|-------|---------|
| `HostConfig.Privileged: true` | CRITICAL |
| `NetworkMode: host` | HIGH |
| Docker socket bind mount | CRITICAL |
| Dangerous `CapAdd` | HIGH |
| Running as root | HIGH |

---

### Kubernetes Security Scanner

Static analysis of YAML manifests plus optional live cluster checks via `kubectl`.

**Manifest checks:**

| Check | Severity |
|-------|---------|
| `securityContext.privileged: true` | CRITICAL |
| `hostPID / hostNetwork / hostIPC: true` | HIGH |
| `runAsUser: 0` or missing `runAsNonRoot` | HIGH |
| `volumes[].hostPath` | HIGH |
| No `resources.limits` on containers | MEDIUM |
| `serviceAccountName: default` | MEDIUM |
| `readOnlyRootFilesystem` not set | MEDIUM |
| `imagePullPolicy` not `Always` | LOW |

**Live cluster checks** (optional, requires `kubectl` connected to a cluster):

| Check | Severity |
|-------|---------|
| Privileged pods running | CRITICAL |
| ClusterRoleBinding with wildcard verbs | CRITICAL |
| Pods with `hostNetwork/hostPID: true` | HIGH |
| `hostPath` volumes in running pods | HIGH |
| No NetworkPolicy in any namespace | MEDIUM |

---

## How it works

### Safety gate (web scanning)

Before a single HTTP request goes out, every scan passes through a three-layer authorization check:

1. **Startup** — the scope YAML file must contain `authorization_confirmed: true` and a list of domains.
2. **Per-request** — `ScopedHttpClient` validates every URL against the authorized domain list.
3. **Path exclusions** — paths listed under `excluded_paths` are never touched.

### Scan execution order (web scanning)

```
Start
  │
  ▼
Scope validation ──► fail fast if unauthorized
  │
  ▼
Phase 1: Recon (sequential)
  ├── Subdomain enumeration  (DNS + crt.sh)
  ├── Port scan              (async TCP)
  ├── Directory discovery    (wordlist)
  └── Tech fingerprinting    (headers + HTML)
  │
  ▼
Site Overview collection (concurrent, best-effort)
  ├── HTTP fetch       → status, headers, body, redirect chain, response time
  ├── HTML parsing     → title, description, favicon, language, OG tags
  ├── SSL certificate  → issuer, expiry, SANs (stdlib ssl module, thread executor)
  ├── DNS lookup       → A records (socket), MX/NS/TXT (dnspython if installed)
  └── Crawl files      → robots.txt preview, sitemap.xml presence
  │
  ▼
Phase 2: Analysis (parallel, all at once)
  ├── Headers module    → security headers, SSL/TLS, cookies
  ├── OWASP module      → SQLi, XSS, CSRF, SSRF, open redirect, auth, misconfig, secrets
  └── API module        → endpoint discovery, auth bypass, IDOR, rate limit, input validation
  │
  ▼
Report  (terminal / JSON / HTML)
```

### Live streaming progress (Web UI)

All scan types in the web UI use Server-Sent Events (SSE) for real-time progress:

1. A `POST /api/<type>/scan/start` call immediately returns a `job_id`.
2. The frontend opens an `EventSource` connection to `GET /api/jobs/{job_id}/stream`.
3. The backend emits `progress` events (percentage + message) as the scan runs.
4. A final `completed` event delivers the full result; an `error` event delivers the failure reason.
5. The UI shows a progress bar, the current step message, and a collapsible live log panel that auto-scrolls as lines arrive.

This pattern covers: Docker scan, K8s scan, and web vulnerability scans.

Late-connecting clients receive the full event history (buffered server-side), so page refreshes don't lose progress.

### Web scan persistence

Completed and failed web scans are saved to `data/scans/<scan_id>.json` and loaded back on server restart. The store keeps the latest 30 scans on disk; older files are removed automatically.

### Rate limiting

All web-scan modules share a single async token-bucket rate limiter (default: 5 req/s, burst 10). Configurable with `--rate-limit`.

---

## Project layout

```
webscanner/
├── Dockerfile.api                        # API container image
├── Dockerfile.ui                         # UI container image (multi-stage Next.js build)
├── docker-compose.yml                    # One-command deployment (API + UI)
├── wordlists/                            # Wordlists for brute force and directory scanning
│   ├── common_passwords.txt              # Built-in ~150 common passwords
│   ├── common_usernames.txt              # Built-in ~60 common usernames
│   ├── web_paths.txt                     # Built-in ~150 web paths
│   ├── web-content-common.txt            # Common web paths (SecLists)
│   ├── web-content-big.txt               # Large web paths list (SecLists)
│   ├── subdomains-top5000.txt            # Top 5K subdomain names (SecLists)
│   ├── subdomains-top20000.txt           # Top 20K subdomain names (SecLists)
│   └── download_wordlists.py             # Download script for SecLists + rockyou
├── data/scans/                           # Persisted web scan results (last 30, JSON)
├── src/webscanner/
│   ├── main.py                           # Typer CLI entry point
│   ├── core/                             # Shared foundations
│   │   ├── types.py                      # Immutable dataclasses: Finding, ScanResult, ScanTarget
│   │   ├── scope.py                      # Authorization gate (safety-critical)
│   │   ├── rate_limiter.py               # Async token-bucket
│   │   ├── http_client.py                # Shared aiohttp session with scope enforcement
│   │   ├── scanner.py                    # Scanner Protocol (interface)
│   │   └── exceptions.py                 # Custom exception hierarchy
│   ├── recon/                            # Subdomain, port, directory, fingerprint, site overview
│   │   └── site_info.py                  # SiteInfo dataclass + SiteInfoGatherer (HTTP/SSL/DNS/metadata)
│   ├── headers/                          # Security headers, SSL/TLS, cookies
│   ├── owasp/                            # SQLi, XSS, CSRF, SSRF, open redirect, auth, misconfig, secrets
│   │   ├── path_traversal.py             # LFI / path traversal scanner (CWE-22)
│   │   ├── command_injection.py          # OS command injection scanner (CWE-78)
│   │   ├── ssti.py                       # Server-side template injection scanner (CWE-94)
│   │   └── http_methods.py               # HTTP method tampering (TRACE/PUT/DELETE/OPTIONS)
│   ├── api_security/                     # Endpoint discovery, auth bypass, IDOR, rate limit, input validation
│   ├── bruteforce/                       # Web brute force: HTTP auth + HTML login forms
│   │   ├── http_auth.py                  # HTTP Basic/Digest auth brute force
│   │   └── form_login.py                 # Auto-detect login forms, test credentials
│   ├── docker_security/                  # Docker security scanner
│   │   ├── __init__.py
│   │   └── scanner.py                    # Dockerfile + docker-compose static analysis, live inspect
│   ├── kubernetes/                       # Kubernetes security scanner
│   │   ├── __init__.py
│   │   └── scanner.py                    # YAML manifest static analysis + live kubectl checks
│   ├── reporting/                        # JSON, HTML, terminal reporters
│   ├── orchestrator/engine.py            # Coordinates all web scan modules
│   └── api/                              # FastAPI backend
│       ├── app.py                        # All REST endpoints + SSE streams
│       ├── models.py                     # Pydantic request/response models (incl. SiteInfoResponse)
│       ├── store.py                      # Scan store with SSE broadcast + on-disk persistence (web scans)
│       └── job_store.py                  # Thread-safe job tracker with SSE fan-out (Docker/K8s)
├── ui/                                   # Next.js + TypeScript + Tailwind frontend
│   └── app/
│       ├── page.tsx                      # Homepage — scan history, filter bar, dashboard stats
│       ├── scans/[id]/page.tsx           # Scan detail — live stream, stop button, export, remediation tracker
│       ├── docker/page.tsx               # Docker security scanner with progress + live log
│       └── k8s/page.tsx                  # Kubernetes scanner with progress + live log
│   └── components/
│       ├── SiteInfoPanel.tsx             # Site Overview panel (HTTP/SSL/DNS/metadata/headers)
│       ├── StatsPanel.tsx                # Dashboard overview — counts, severity chart, success rate
│       ├── FindingsTable.tsx             # Findings list with filter, search, remediation buttons
│       ├── NewScanForm.tsx               # New scan form with module selection
│       ├── StatusBadge.tsx               # Scan status pill (running / completed / failed)
│       ├── SeverityBadge.tsx             # Finding severity badge
│       └── SummaryCards.tsx              # Per-severity finding count cards
├── tests/
│   ├── unit/                             # Per-module tests with mocked HTTP
│   ├── integration/                      # Real local HTTP server tests
│   └── e2e/                              # CLI flow tests
└── start.sh                              # Interactive launcher (7-option menu)
```

---

## Getting started

### Requirements

- Python 3.12+
- Node.js 20+ (for the web UI)
- Docker (optional — for live container inspection or containerised deployment)
- kubectl (optional — for live Kubernetes cluster checks)

### Option A — Local install

```bash
git clone <repo-url>
cd webscanner

# Python backend
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Web UI dependencies
cd ui && npm install && cd ..
```

### Option B — Docker Compose

```bash
git clone <repo-url>
cd webscanner

docker compose up --build
```

The API will be available at `http://localhost:8000` and the UI at `http://localhost:3000`.

> Scan data is persisted to `./data/scans/` on the host via a volume mount.

### Download wordlists

```bash
webscanner wordlists               # all SecLists wordlists
webscanner wordlists --skip-rockyou   # skip the 130 MB rockyou.txt
```

---

## CLI reference

### Web vulnerability scanning

```bash
# Full scan — all modules
webscanner scan https://example.com \
  --scope-file scope.yaml \
  --program "example-bug-bounty"

# Include brute force
webscanner scan https://example.com \
  --scope-file scope.yaml \
  --modules recon,headers,owasp,api,bruteforce \
  --wordlist wordlists/top-100k-passwords.txt

# Headers + SSL only, save JSON
webscanner scan https://example.com \
  --scope-file scope.yaml \
  --modules headers \
  --output-format json \
  --output-file results.json
```

#### All scan flags

| Flag | Default | Description |
|------|---------|-------------|
| `--scope-file` | required | Path to the authorization YAML file |
| `--program` | required | Bug bounty program name (used in User-Agent) |
| `--modules` | `recon,headers,owasp,api` | Comma-separated module list |
| `--rate-limit` | `5.0` | Max requests per second |
| `--output-format` | `terminal` | `terminal`, `json`, or `html` |
| `--output-file` | — | Required when format is `json` or `html` |
| `--passive-only` | false | Skip active payload injection and brute force |
| `--timeout` | `10` | Per-request timeout in seconds |
| `--wordlist` | built-in | Password wordlist for brute force |
| `--max-attempts` | `300` | Max brute force tries per endpoint |
| `--verbose` | false | Enable debug logging |

### Create a scope file

```yaml
# scope.yaml
authorization_confirmed: true   # required

authorized_domains:
  - example.com
  - api.example.com

excluded_paths:
  - /logout
  - /admin/delete*
```

---

### Docker security scanning

```bash
# Scan current directory for Dockerfiles and docker-compose files
webscanner docker

# Scan a specific project directory
webscanner docker --path /my/project

# Also inspect running containers (requires Docker daemon)
webscanner docker --live

# Save JSON report
webscanner docker --output-format json --output-file docker-report.json
```

### Kubernetes security scanning

```bash
# Scan current directory for YAML manifests
webscanner k8s

# Scan a specific manifests directory
webscanner k8s --path /my/k8s/manifests

# Also query running cluster (requires kubectl + connected context)
webscanner k8s --live

# Save JSON report
webscanner k8s --output-format json --output-file k8s-report.json
```

---

## Web UI

### Starting

```bash
./start.sh
```

Interactive menu:

```
[1] Start           — launch API (port 8000) + UI (port 3000)
[2] Stop            — stop both services
[3] Status          — running services + Docker/kubectl status + security tools
[4] Docker Scan     — Docker status check + security scan   [Docker: running ✓]
[5] K8s Scan        — kubectl status check + security scan  [kubectl: connected ✓]
[6] Download wordlists
[7] Install Tools   — install/update nmap, nikto, nuclei, gobuster, sqlmap, hydra, ffuf, and more
[0] Exit
```

Direct shortcuts:

```bash
./start.sh start
./start.sh stop
./start.sh status
./start.sh docker-scan
./start.sh k8s-scan
./start.sh wordlists
./start.sh install-tools
```

### Pages

| URL | Description |
|-----|-------------|
| `/` | Homepage — scan history, filter bar, dashboard stats panel |
| `/scans/{id}` | Scan detail — live stream, stop button, export dropdown, remediation tracker |
| `/docker` | Docker scanner — Dockerfile/compose analysis + live container check |
| `/k8s` | Kubernetes scanner — manifest analysis + live cluster check |

### Homepage features

- **Dashboard stats** — total/completed/running/failed count cards, stacked severity bar chart, success rate bar — visible when at least one scan exists
- **Filter bar** — search by URL or program name, filter by status (All / Running / Completed / Failed), toggle Has Critical / Has High checkboxes
- **API offline banner** — yellow warning shown when the backend is unreachable

### Scan detail features

- **Site Overview panel** — collapsible panel at the top of every completed report showing HTTP basics, server/CDN info, page metadata, detected technologies, SSL certificate details, DNS records, robots.txt preview, and all response headers
- **Live findings stream** — findings appear as they are discovered via SSE
- **Stop Scan button** — cancels a running scan immediately (red button, visible only while running)
- **Export dropdown** — download results as JSON / CSV / HTML Report (available once completed)
- **Remediation tracker** — mark each finding as Fixed, In Progress, or Accepted Risk; state saved in `localStorage`; progress bar shows resolved count
- **Collapsible live log** — timestamped progress messages with auto-scroll

### Features shared across Docker and K8s pages

- **Service status banner** — shows whether Docker/kubectl is installed and the daemon/cluster is reachable, with a refresh button
- **Progress bar** — fills in real time as the scan runs; blue → green on success, red on failure
- **Collapsible live log** — terminal-style panel showing timestamped progress messages; auto-scrolls to the latest line
- **Findings accordion** — sorted by severity (CRITICAL first), expandable to show evidence and remediation

---

## API endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/api/health` | Health check |
| `GET` | `/api/infra/status` | Docker + kubectl installed/running status |
| `POST` | `/api/scans` | Start a web vulnerability scan |
| `GET` | `/api/scans` | List all scans |
| `GET` | `/api/scans/{id}` | Get scan result |
| `DELETE` | `/api/scans/{id}` | Delete scan |
| `POST` | `/api/scans/{id}/cancel` | Cancel a running scan |
| `GET` | `/api/scans/{id}/stream` | SSE stream for web scan findings |
| `GET` | `/api/scans/{id}/export?format=json\|csv\|html` | Download scan report |
| `POST` | `/api/docker/scan` | Run Docker scan (sync) |
| `POST` | `/api/docker/scan/start` | Start streaming Docker scan → `{job_id}` |
| `POST` | `/api/k8s/scan` | Run K8s scan (sync) |
| `POST` | `/api/k8s/scan/start` | Start streaming K8s scan → `{job_id}` |
| `GET` | `/api/jobs/{job_id}/stream` | SSE stream for any async job |

---

## Output formats

**Terminal** — Rich-formatted tables with color-coded severity badges.

**JSON** — Full result with every finding: severity, module, evidence, remediation, CWE, CVSS, timestamp.

**CSV** — Spreadsheet-friendly export with columns: severity, module, check_name, title, url, cvss_score, cwe_id, description, remediation.

**HTML** — Self-contained single-file report. Works offline, suitable for bug bounty submissions.

---

## Running the tests

```bash
pytest                                    # all tests
pytest tests/unit/ -v                    # unit tests only (fast, no network)
pytest --cov=webscanner --cov-report=html   # with coverage report
```

---

## Dev toolchain

```bash
pip-audit           # dependency vulnerability audit
bandit -r src/      # static security analysis
mypy --strict src/  # type checking
ruff check src/     # linting
```

---

## Tech stack

| Layer | Technology |
|-------|-----------|
| CLI | Python 3.12 + Typer + Rich |
| HTTP | aiohttp (async) |
| HTML parsing | BeautifulSoup4 + lxml |
| SSL inspection | pyOpenSSL + cryptography |
| Config validation | Pydantic v2 |
| Scope files | PyYAML |
| API backend | FastAPI + Uvicorn |
| Live streaming | sse-starlette (Server-Sent Events) |
| Web frontend | Next.js 15 + TypeScript + Tailwind CSS |
| State persistence | localStorage (remediation tracker) |
| Docker scanning | subprocess → docker ps / docker inspect |
| K8s scanning | subprocess → kubectl get/describe |
| Containerisation | Docker + docker-compose |
| Wordlists | SecLists (GitHub) + built-in compact lists |
| Testing | pytest + pytest-asyncio + pytest-httpserver |

---

*© 2026 By Zamiq Mustafayev. For authorized security testing only.*
