# WebScanner

A security scanner built for authorized testing. Covers web vulnerabilities, WiFi security, Docker misconfigurations, and Kubernetes security — all accessible from a dark-themed web UI or straight from the terminal.

> **Important:** This tool is for authorized testing only. It will refuse to run without a scope file that explicitly confirms you have permission to scan the target.

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

### WiFi Security

**Passive WiFi Scanner**
Discovers nearby wireless networks using OS-native tools and identifies:
- Open networks (no encryption)
- WEP encryption (broken cipher)
- WPS-enabled access points
- TKIP-only ciphers
- Rogue / evil twin APs (two or more networks sharing the same SSID but different BSSIDs)
- Hidden SSIDs (broadcast suppression)
- Deauth attack surface (WPA2-Personal without 802.11w / PMF)
- WPA downgrade risk (mixed WPA + WPA2 mode)

No packets injected. On macOS, uses a CoreWLAN Swift helper for real SSIDs (falls back to `system_profiler` if Swift compilation fails). When SSIDs are hidden by macOS privacy, a warning banner guides you through enabling Location Services.

**WiFi Online Attack**
Brute-forces a live WPA/WPA2 network by trying each password from a wordlist via `networksetup`. Saves your current connection and reconnects to it when done (success or failure). Hard cap of 50 attempts. ~8–10 seconds per attempt — designed for targeted, small wordlists. Runs as a background streaming job with live progress bar and attack log. The SSID field auto-populates from your saved networks (no Location Services required) via a `<datalist>` dropdown.

> Only test networks you own or have explicit written permission to attack.

**WPA Password Audit**
Tests your own WiFi password strength by running a dictionary attack against a captured WPA handshake (`.cap` or `.hc22000`) via `aircrack-ng` or `hashcat`.

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

1. A `POST /api/<type>/scan/start` (or `/api/wifi/attack/start`) call immediately returns a `job_id`.
2. The frontend opens an `EventSource` connection to `GET /api/jobs/{job_id}/stream`.
3. The backend emits `progress` events (percentage + message) as the scan runs.
4. A final `completed` event delivers the full result; an `error` event delivers the failure reason.
5. The UI shows a progress bar, the current step message, and a collapsible live log panel that auto-scrolls as lines arrive.

This pattern covers: WiFi passive scan, WiFi online attack, Docker scan, K8s scan, and web vulnerability scans.

Late-connecting clients receive the full event history (buffered server-side), so page refreshes don't lose progress.

### Web scan persistence

Completed and failed web scans are saved to `data/scans/<scan_id>.json` and loaded back on server restart. The store keeps the latest 30 scans on disk; older files are removed automatically.

### Rate limiting

All web-scan modules share a single async token-bucket rate limiter (default: 5 req/s, burst 10). Configurable with `--rate-limit`.

---

## Project layout

```
webscanner/
├── wordlists/                        # Wordlists for brute force and directory scanning
│   ├── common_passwords.txt          # Built-in ~150 common passwords
│   ├── common_usernames.txt          # Built-in ~60 common usernames
│   ├── web_paths.txt                 # Built-in ~150 web paths
│   ├── wifi-passwords.txt            # 4,800 probable WPA passwords (SecLists)
│   ├── web-content-common.txt        # Common web paths (SecLists)
│   ├── web-content-big.txt           # Large web paths list (SecLists)
│   ├── subdomains-top5000.txt        # Top 5K subdomain names (SecLists)
│   ├── subdomains-top20000.txt       # Top 20K subdomain names (SecLists)
│   └── download_wordlists.py         # Download script for SecLists + rockyou
├── captures/                         # Drop .cap / .hc22000 files here for WPA audit
├── data/scans/                       # Persisted web scan results (last 30, JSON)
├── src/webscanner/
│   ├── main.py                       # Typer CLI entry point
│   ├── core/                         # Shared foundations
│   │   ├── types.py                  # Immutable dataclasses: Finding, ScanResult, ScanTarget
│   │   ├── scope.py                  # Authorization gate (safety-critical)
│   │   ├── rate_limiter.py           # Async token-bucket
│   │   ├── http_client.py            # Shared aiohttp session with scope enforcement
│   │   ├── scanner.py                # Scanner Protocol (interface)
│   │   └── exceptions.py             # Custom exception hierarchy
│   ├── recon/                        # Subdomain, port, directory, fingerprint
│   ├── headers/                      # Security headers, SSL/TLS, cookies
│   ├── owasp/                        # SQLi, XSS, CSRF, SSRF, open redirect, auth, misconfig, secrets
│   │   ├── path_traversal.py         # LFI / path traversal scanner (CWE-22)
│   │   ├── command_injection.py      # OS command injection scanner (CWE-78)
│   │   ├── ssti.py                   # Server-side template injection scanner (CWE-94)
│   │   └── http_methods.py           # HTTP method tampering (TRACE/PUT/DELETE/OPTIONS)
│   ├── api_security/                 # Endpoint discovery, auth bypass, IDOR, rate limit, input validation
│   ├── bruteforce/                   # Web brute force: HTTP auth + HTML login forms
│   │   ├── http_auth.py              # HTTP Basic/Digest auth brute force
│   │   └── form_login.py             # Auto-detect login forms, test credentials
│   ├── wifi/                         # WiFi security modules
│   │   ├── scanner.py                # Passive WiFi scan (CoreWLAN/system_profiler/nmcli/netsh) + get_preferred_networks()
│   │   ├── swift_helper.py           # CoreWLAN Swift helper for real SSIDs on macOS
│   │   ├── analyzer.py               # Security analysis: open/WEP/WPS/evil twin/deauth/downgrade findings
│   │   ├── online_attack.py          # Streaming online WPA brute force via networksetup
│   │   └── wpa_audit.py              # Dictionary attack on .cap/.hc22000 files
│   ├── docker_security/              # Docker security scanner
│   │   ├── __init__.py
│   │   └── scanner.py                # Dockerfile + docker-compose static analysis, live inspect
│   ├── kubernetes/                   # Kubernetes security scanner
│   │   ├── __init__.py
│   │   └── scanner.py                # YAML manifest static analysis + live kubectl checks
│   ├── reporting/                    # JSON, HTML, terminal reporters
│   ├── orchestrator/engine.py        # Coordinates all web scan modules
│   └── api/                          # FastAPI backend
│       ├── app.py                    # All REST endpoints + SSE streams
│       ├── models.py                 # Pydantic request/response models
│       ├── store.py                  # Scan store with SSE broadcast + on-disk persistence (web scans)
│       └── job_store.py              # Thread-safe job tracker with SSE fan-out (WiFi/Docker/K8s)
├── ui/                               # Next.js + TypeScript + Tailwind frontend
│   └── app/
│       ├── page.tsx                  # Homepage with navigation
│       ├── scans/[id]/page.tsx       # Live web scan detail with SSE streaming
│       ├── wifi/page.tsx             # WiFi scanner: passive scan + per-network attack panel
│       ├── docker/page.tsx           # Docker security scanner with progress + live log
│       └── k8s/page.tsx              # Kubernetes scanner with progress + live log
├── tests/
│   ├── unit/                         # Per-module tests with mocked HTTP
│   ├── integration/                  # Real local HTTP server tests
│   └── e2e/                          # CLI flow tests
└── start.sh                          # Interactive launcher (9-option menu)
```

---

## Getting started

### Requirements

- Python 3.12+
- Node.js 20+ (for the web UI)
- Docker (optional — for live container inspection)
- kubectl (optional — for live Kubernetes cluster checks)
- Swift (macOS) — auto-detected for CoreWLAN WiFi scanning
- aircrack-ng or hashcat (optional — for WPA audit)

### Install

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

### WiFi scanning

```bash
# Passive scan — discover nearby networks + security findings
webscanner wifi

# Save as JSON
webscanner wifi --output-format json --output-file wifi-report.json
```

### WiFi online attack

```bash
# Try up to 30 passwords from a wordlist against a live SSID
webscanner wifi-attack "MyNetwork" \
  --wordlist wordlists/wifi-passwords.txt \
  --max-attempts 30

# Use a custom interface
webscanner wifi-attack "MyNetwork" \
  --wordlist wordlists/wifi-passwords.txt \
  --interface en1
```

> Each attempt takes ~8–10 seconds. The tool reconnects you to your original network when done.

### WPA password audit

```bash
# Install tools (one-time)
brew install aircrack-ng hashcat      # macOS
sudo apt install aircrack-ng hashcat  # Debian / Ubuntu

# Drop capture file in captures/ and run
webscanner wifi-audit capture-01.cap
webscanner wifi-audit capture-01.cap --wordlist wordlists/rockyou.txt
webscanner wifi-audit capture-01.cap --bssid AA:BB:CC:DD:EE:FF
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
[3] Status          — running services + Docker/kubectl status + wordlist counts + security tools
[4] WPA Audit       — dictionary attack on a .cap/.hc22000 capture file
[5] WiFi Attack     — online brute force against a live SSID
[6] Docker Scan     — Docker status check + security scan   [Docker: running ✓]
[7] K8s Scan        — kubectl status check + security scan  [kubectl: connected ✓]
[8] Download wordlists
[9] Install Tools   — install/update nmap, aircrack-ng, hashcat, nikto, nuclei, gobuster, sqlmap, hydra, hcxtools, ffuf
[0] Exit
```

Direct shortcuts:

```bash
./start.sh start
./start.sh stop
./start.sh status
./start.sh wifi-attack
./start.sh docker-scan
./start.sh k8s-scan
./start.sh wpa-audit
./start.sh wordlists
./start.sh install-tools
```

### Pages

| URL | Description |
|-----|-------------|
| `/` | Homepage — navigation to all tools |
| `/scans` | Web vulnerability scanner — new scan form + live findings stream |
| `/wifi` | WiFi scanner — passive scan with live log + per-network attack panel |
| `/docker` | Docker scanner — Dockerfile/compose analysis + live container check |
| `/k8s` | Kubernetes scanner — manifest analysis + live cluster check |

### Features shared across Docker and K8s pages

- **Service status banner** — shows whether Docker/kubectl is installed and the daemon/cluster is reachable, with a refresh button
- **Progress bar** — fills in real time as the scan runs; blue → green on success, red on failure
- **Collapsible live log** — terminal-style panel showing timestamped progress messages; auto-scrolls to the latest line
- **Findings accordion** — sorted by severity (CRITICAL first), expandable to show evidence and remediation

### WiFi page features

- **Passive scan** with streaming progress bar and live log
- **Vuln Scan button** per network — filters the findings list to that network and auto-scrolls to it
- **Attack panel** — slide-in panel for per-network brute force with:
  - SSID field pre-filled from the selected network; editable if the SSID is hidden by macOS privacy
  - `<datalist>` dropdown auto-populated with all your saved networks (from `networksetup`, no Location Services required)
  - Streaming progress bar (orange while running, green/red on finish)
  - Collapsible live attack log with color-coded lines (green = success, yellow = warning)
  - Time estimate based on attempt count
- **Location Services warning** — yellow banner shown after scan when all SSIDs are `<redacted>`, with step-by-step instructions for enabling access

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
| `GET` | `/api/scans/{id}/stream` | SSE stream for web scan findings |
| `GET` | `/api/wifi/scan` | Run passive WiFi scan (sync) |
| `POST` | `/api/wifi/scan/start` | Start streaming WiFi scan → `{job_id}` |
| `POST` | `/api/wifi/attack/start` | Start streaming WiFi online attack → `{job_id}` |
| `GET` | `/api/wifi/known-networks` | List saved network SSIDs (via `networksetup`) |
| `POST` | `/api/docker/scan` | Run Docker scan (sync) |
| `POST` | `/api/docker/scan/start` | Start streaming Docker scan → `{job_id}` |
| `POST` | `/api/k8s/scan` | Run K8s scan (sync) |
| `POST` | `/api/k8s/scan/start` | Start streaming K8s scan → `{job_id}` |
| `GET` | `/api/jobs/{job_id}/stream` | SSE stream for any async job |

---

## Output formats

**Terminal** — Rich-formatted tables with color-coded severity badges.

**JSON** — Full result with every finding: severity, module, evidence, remediation, CWE, CVSS, timestamp.

**HTML** — Self-contained single-file report (Jinja2). Works offline, suitable for bug bounty submissions.

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
| Web frontend | Next.js + TypeScript + Tailwind CSS |
| WiFi scanning (macOS) | CoreWLAN via Swift helper, fallback to system_profiler |
| WiFi scanning (Linux) | nmcli / iwlist |
| WiFi scanning (Windows) | netsh |
| WiFi known networks | networksetup -listpreferredwirelessnetworks (macOS, no Location Services needed) |
| WiFi online attack | networksetup (macOS), streaming via SSE job |
| Docker scanning | subprocess → docker ps / docker inspect |
| K8s scanning | subprocess → kubectl get/describe |
| WPA auditing | aircrack-ng + hashcat |
| Wordlists | SecLists (GitHub) + built-in compact lists |
| Testing | pytest + pytest-asyncio + pytest-httpserver |

---