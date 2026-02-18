#!/usr/bin/env bash
# WebScanner — Interactive Launch Control

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

# ── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
print_banner() {
  clear
  echo -e "${CYAN}${BOLD}"
  echo "  ██╗    ██╗███████╗██████╗ ███████╗ ██████╗ █████╗ ███╗   ██╗███╗   ██╗███████╗██████╗ "
  echo "  ██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔══██╗████╗  ██║████╗  ██║██╔════╝██╔══██╗"
  echo "  ██║ █╗ ██║█████╗  ██████╔╝███████╗██║     ███████║██╔██╗ ██║██╔██╗ ██║█████╗  ██████╔╝"
  echo "  ██║███╗██║██╔══╝  ██╔══██╗╚════██║██║     ██╔══██║██║╚██╗██║██║╚██╗██║██╔══╝  ██╔══██╗"
  echo "  ╚███╔███╔╝███████╗██████╔╝███████║╚██████╗██║  ██║██║ ╚████║██║ ╚████║███████╗██║  ██║"
  echo "   ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝"
  echo -e "${RESET}"
  echo -e "  ${DIM}Authorized web & WiFi vulnerability scanner — v0.1.0${RESET}"
  echo -e "  ${DIM}Root: ${ROOT}${RESET}"
  echo
}

ok()   { echo -e "  ${GREEN}✓${RESET}  $*"; }
info() { echo -e "  ${CYAN}→${RESET}  $*"; }
warn() { echo -e "  ${YELLOW}⚠${RESET}  $*"; }
err()  { echo -e "  ${RED}✗${RESET}  $*"; }
sep()  { echo -e "  ${DIM}────────────────────────────────────────────${RESET}"; }

wait_for_url() {
  local url="$1" label="$2" timeout=60 elapsed=0
  local spin='⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏'
  echo -ne "  ${CYAN}${label}${RESET}"
  while ! curl -sf "$url" >/dev/null 2>&1; do
    local i=$(( elapsed % ${#spin} ))
    echo -ne "\r  ${CYAN}${spin:$i:1}${RESET}  ${label} ${DIM}(${elapsed}s)${RESET}"
    sleep 1
    (( elapsed++ ))
    if (( elapsed >= timeout )); then
      echo -e "\r  ${YELLOW}⚠${RESET}  ${label} — timed out after ${timeout}s"
      return 1
    fi
  done
  echo -e "\r  ${GREEN}✓${RESET}  ${label}"
}

open_browser() {
  local url="$1"
  if command -v open &>/dev/null; then       # macOS
    open "$url"
  elif command -v xdg-open &>/dev/null; then # Linux
    xdg-open "$url" &>/dev/null &
  fi
}

port_in_use() { lsof -i ":$1" -sTCP:LISTEN -t &>/dev/null; }

check_port() {
  local port="$1" name="$2"
  if port_in_use "$port"; then
    warn "Port ${port} is already in use — ${name} may conflict."
    warn "Kill it with: ${DIM}lsof -ti:${port} | xargs kill -9${RESET}"
    echo
    read -rp "  Continue anyway? [y/N] " yn
    [[ "$(echo "$yn" | tr '[:upper:]' '[:lower:]')" == "y" ]] || return 1
  fi
}

# ── Dependency checks ─────────────────────────────────────────────────────────
check_deps() {
  local ok=true
  if [[ ! -f "$ROOT/.venv/bin/activate" ]]; then
    err "Python venv not found. Run:"
    echo -e "       ${DIM}python -m venv .venv && source .venv/bin/activate && pip install -e '.[dev]'${RESET}"
    ok=false
  fi
  if ! command -v npm &>/dev/null; then
    err "npm not found — install Node.js 20+"
    ok=false
  fi
  if [[ ! -d "$ROOT/ui/node_modules" ]]; then
    err "UI dependencies not installed. Run: ${DIM}cd ui && npm install${RESET}"
    ok=false
  fi
  [[ "$ok" == true ]]
}

# Returns 0 if Docker is installed AND daemon is running
check_docker_running() {
  command -v docker &>/dev/null || return 1
  docker info &>/dev/null 2>&1 || return 1
  return 0
}

# Returns 0 if kubectl is installed
check_kubectl_installed() {
  command -v kubectl &>/dev/null || return 1
  return 0
}

# Returns 0 if kubectl can reach a cluster
check_kubectl_cluster() {
  command -v kubectl &>/dev/null || return 1
  kubectl cluster-info --request-timeout=5s &>/dev/null 2>&1 || return 1
  return 0
}

# Print Docker + kubectl status lines (used in status screen and menu)
print_infra_status() {
  # Docker
  if command -v docker &>/dev/null; then
    local docker_ver
    docker_ver=$(docker --version 2>/dev/null | sed 's/Docker version //' | cut -d, -f1)
    if docker info &>/dev/null 2>&1; then
      ok "Docker  ${GREEN}● running${RESET}  ${DIM}${docker_ver}${RESET}"
    else
      warn "Docker  ${YELLOW}● installed but daemon not running${RESET}  ${DIM}${docker_ver}${RESET}"
      echo -e "         ${DIM}Start Docker Desktop or run: sudo systemctl start docker${RESET}"
    fi
  else
    err "Docker  ${RED}● not installed${RESET}  ${DIM}https://docs.docker.com/get-docker/${RESET}"
  fi

  # kubectl
  if command -v kubectl &>/dev/null; then
    local kube_ver
    kube_ver=$(kubectl version --client=true --short 2>/dev/null | head -1 | sed 's/Client Version: //')
    if kubectl cluster-info --request-timeout=3s &>/dev/null 2>&1; then
      local ctx
      ctx=$(kubectl config current-context 2>/dev/null || echo "unknown")
      ok "kubectl ${GREEN}● cluster connected${RESET}  ${DIM}${kube_ver} · context: ${ctx}${RESET}"
    else
      warn "kubectl ${YELLOW}● installed, no cluster${RESET}  ${DIM}${kube_ver}${RESET}"
      echo -e "         ${DIM}Run: minikube start  or  kubectl config use-context <name>${RESET}"
    fi
  else
    err "kubectl ${RED}● not installed${RESET}  ${DIM}https://kubernetes.io/docs/tasks/tools/${RESET}"
  fi
}

# ── Wordlist / capture helpers ────────────────────────────────────────────────
list_wordlists() {
  echo -e "\n  ${BOLD}Available wordlists:${RESET}"
  local i=1
  while IFS= read -r f; do
    local size
    size=$(du -sh "$f" 2>/dev/null | awk '{print $1}')
    echo -e "    ${DIM}[$i]${RESET} $(basename "$f")  ${DIM}(${size})${RESET}"
    (( i++ ))
  done < <(find "$ROOT/wordlists" -name "*.txt" | sort)
}

pick_wordlist() {
  list_wordlists
  echo
  read -rp "  Enter wordlist name or number (Enter = wifi-passwords.txt): " choice
  if [[ -z "$choice" ]]; then
    echo "$ROOT/wordlists/wifi-passwords.txt"
    return
  fi
  if [[ "$choice" =~ ^[0-9]+$ ]]; then
    local files
    mapfile -t files < <(find "$ROOT/wordlists" -name "*.txt" | sort)
    echo "${files[$((choice-1))]}"
  else
    echo "$ROOT/wordlists/$choice"
  fi
}

pick_capture() {
  local caps
  mapfile -t caps < <(find "$ROOT/captures" -name "*.cap" -o -name "*.hc22000" 2>/dev/null | sort)
  if [[ ${#caps[@]} -eq 0 ]]; then
    warn "No capture files found in captures/"
    info "Drop your .cap or .hc22000 files into: ${DIM}${ROOT}/captures/${RESET}"
    return 1
  fi
  echo -e "\n  ${BOLD}Capture files:${RESET}"
  for i in "${!caps[@]}"; do
    echo -e "    ${DIM}[$((i+1))]${RESET} $(basename "${caps[$i]}")"
  done
  echo
  read -rp "  Select capture file [1]: " choice
  choice="${choice:-1}"
  echo "${caps[$((choice-1))]}"
}

# ── [1] Start ─────────────────────────────────────────────────────────────────
start_services() {
  print_banner
  echo -e "  ${BOLD}Starting WebScanner${RESET}  ${DIM}(Python venv + Next.js hot-reload)${RESET}\n"

  check_deps || { echo; read -rp "  Press Enter to return to menu..." _; return; }
  check_port 8000 "API" || return
  check_port 3000 "UI"  || return

  sep
  info "Starting API  →  http://localhost:8000"
  info "Starting UI   →  http://localhost:3000"
  sep
  echo

  source "$ROOT/.venv/bin/activate"
  python -m uvicorn webscanner.api.app:app --host 0.0.0.0 --port 8000 --reload \
    --log-level warning 2>&1 | sed 's/^/  [api] /' &
  API_PID=$!

  cd "$ROOT/ui" && npm run dev --silent 2>&1 | sed 's/^/  [ui]  /' &
  UI_PID=$!
  cd "$ROOT"

  trap '_cleanup' INT TERM

  wait_for_url "http://localhost:8000/api/health" "API ready"
  wait_for_url "http://localhost:3000"            "UI ready"

  echo
  sep
  echo -e "  ${GREEN}${BOLD}WebScanner is running!${RESET}"
  echo -e "  ${CYAN}UI  →${RESET}  http://localhost:3000"
  echo -e "  ${CYAN}API →${RESET}  http://localhost:8000/docs"
  sep
  echo -e "  ${DIM}Press Ctrl+C to stop.${RESET}"
  echo

  open_browser "http://localhost:3000"
  wait
}

_cleanup() {
  echo
  info "Stopping services..."
  kill "$API_PID" "$UI_PID" 2>/dev/null
  wait "$API_PID" "$UI_PID" 2>/dev/null
  ok "Stopped."
  exit 0
}

# ── [2] Stop ──────────────────────────────────────────────────────────────────
stop_services() {
  print_banner
  echo -e "  ${BOLD}Stopping WebScanner...${RESET}\n"

  local pids
  pids=$(lsof -ti:8000,3000 2>/dev/null)
  if [[ -n "$pids" ]]; then
    info "Killing processes on ports 8000 and 3000..."
    echo "$pids" | xargs kill -9 2>/dev/null
    ok "Stopped."
  else
    info "Nothing running on ports 8000/3000."
  fi

  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [3] Status ────────────────────────────────────────────────────────────────
show_status() {
  print_banner
  echo -e "  ${BOLD}WebScanner Services${RESET}\n"
  sep

  if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
    ok "API   http://localhost:8000  ${GREEN}RUNNING${RESET}"
  else
    err "API   http://localhost:8000  ${RED}OFFLINE${RESET}"
  fi

  if curl -sf http://localhost:3000 >/dev/null 2>&1; then
    ok "UI    http://localhost:3000  ${GREEN}RUNNING${RESET}"
  else
    err "UI    http://localhost:3000  ${RED}OFFLINE${RESET}"
  fi

  echo
  echo -e "  ${BOLD}Infrastructure Tools${RESET}\n"
  print_infra_status

  echo
  echo -e "  ${BOLD}Security Tools${RESET}\n"
  local sec_tools=(nmap aircrack-ng hashcat nikto nuclei gobuster sqlmap hydra hcxtools ffuf)
  for t in "${sec_tools[@]}"; do
    if command -v "$t" &>/dev/null; then
      ok "${t}"
    else
      err "${t}  ${DIM}(missing — run: ./start.sh install-tools)${RESET}"
    fi
  done

  sep
  local wl_count cap_count
  wl_count=$(find "$ROOT/wordlists" -name "*.txt" 2>/dev/null | wc -l | tr -d ' ')
  cap_count=$(find "$ROOT/captures" \( -name "*.cap" -o -name "*.hc22000" \) 2>/dev/null | wc -l | tr -d ' ')
  ok "Wordlists: ${CYAN}${wl_count}${RESET} files  │  Captures: ${CYAN}${cap_count}${RESET} files"
  sep

  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [5] WiFi Online Attack ────────────────────────────────────────────────────
run_wifi_attack() {
  print_banner
  echo -e "  ${BOLD}${MAGENTA}WiFi Online Attack${RESET}  ${DIM}(try connecting with each password)${RESET}\n"
  echo -e "  ${YELLOW}⚠  Authorized testing only — use on networks you own or have permission to test.${RESET}\n"

  if [[ ! -f "$ROOT/.venv/bin/activate" ]]; then
    err "Python venv not found. Run setup first."
    echo; read -rp "  Press Enter to return..." _; return
  fi

  read -rp "  Target SSID: " target_ssid
  if [[ -z "$target_ssid" ]]; then
    warn "No SSID entered."; sleep 1; return
  fi

  wl=$(pick_wordlist)
  echo
  read -rp "  Max attempts [30]: " max_att
  max_att="${max_att:-30}"

  sep; echo
  source "$ROOT/.venv/bin/activate"
  python -m webscanner wifi-attack "$target_ssid" \
    --wordlist "$wl" --max-attempts "$max_att"
  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [6] Docker Scan ───────────────────────────────────────────────────────────
run_docker_scan() {
  print_banner
  echo -e "  ${BOLD}Docker Security Scan${RESET}\n"

  if [[ ! -f "$ROOT/.venv/bin/activate" ]]; then
    err "Python venv not found."; echo; read -rp "  Press Enter to return..." _; return
  fi

  # Pre-flight: Docker status
  sep
  echo -e "  ${BOLD}Docker Status${RESET}\n"
  local docker_ok=false daemon_ok=false
  if command -v docker &>/dev/null; then
    local docker_ver
    docker_ver=$(docker --version 2>/dev/null | sed 's/Docker version //' | cut -d, -f1)
    ok "Docker installed  ${DIM}${docker_ver}${RESET}"
    docker_ok=true
    if docker info &>/dev/null 2>&1; then
      ok "Docker daemon is running"
      daemon_ok=true
    else
      warn "Docker daemon is NOT running"
      info "Start it with: ${DIM}open -a Docker${RESET}  (macOS)  or  ${DIM}sudo systemctl start docker${RESET}  (Linux)"
    fi
  else
    err "Docker is not installed"
    info "Install from: ${DIM}https://docs.docker.com/get-docker/${RESET}"
    info "Static Dockerfile/compose analysis will still work."
  fi
  sep; echo

  read -rp "  Directory to scan [.]: " scan_path
  scan_path="${scan_path:-.}"

  local live_flag=""
  if [[ "$daemon_ok" == true ]]; then
    read -rp "  Include live container inspection? [y/N]: " do_live
    [[ "$(echo "$do_live" | tr '[:upper:]' '[:lower:]')" == "y" ]] && live_flag="--live"
  else
    info "Skipping live container option (daemon not running)."
  fi

  sep; echo
  source "$ROOT/.venv/bin/activate"
  python -m webscanner docker --path "$scan_path" $live_flag
  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [7] Kubernetes Scan ───────────────────────────────────────────────────────
run_k8s_scan() {
  print_banner
  echo -e "  ${BOLD}Kubernetes Security Scan${RESET}\n"

  if [[ ! -f "$ROOT/.venv/bin/activate" ]]; then
    err "Python venv not found."; echo; read -rp "  Press Enter to return..." _; return
  fi

  # Pre-flight: kubectl status
  sep
  echo -e "  ${BOLD}kubectl Status${RESET}\n"
  local kubectl_ok=false cluster_ok=false
  if command -v kubectl &>/dev/null; then
    local kube_ver
    kube_ver=$(kubectl version --client=true --short 2>/dev/null | head -1 | sed 's/Client Version: //')
    ok "kubectl installed  ${DIM}${kube_ver}${RESET}"
    kubectl_ok=true
    echo -ne "  ${CYAN}→${RESET}  Checking cluster connectivity…"
    if kubectl cluster-info --request-timeout=5s &>/dev/null 2>&1; then
      local ctx
      ctx=$(kubectl config current-context 2>/dev/null || echo "unknown")
      echo -e "\r  ${GREEN}✓${RESET}  Cluster connected  ${DIM}(context: ${ctx})${RESET}"
      cluster_ok=true
    else
      echo -e "\r  ${YELLOW}⚠${RESET}  No cluster reachable"
      info "Start a cluster:  ${DIM}minikube start${RESET}"
      info "Or switch context: ${DIM}kubectl config use-context <name>${RESET}"
    fi
  else
    err "kubectl is not installed"
    info "Install from: ${DIM}https://kubernetes.io/docs/tasks/tools/${RESET}"
    info "Static YAML manifest analysis will still work."
  fi
  sep; echo

  read -rp "  Directory with YAML manifests [.]: " scan_path
  scan_path="${scan_path:-.}"

  local live_flag=""
  if [[ "$cluster_ok" == true ]]; then
    read -rp "  Include live cluster inspection? [y/N]: " do_live
    [[ "$(echo "$do_live" | tr '[:upper:]' '[:lower:]')" == "y" ]] && live_flag="--live"
  else
    info "Skipping live cluster option (no cluster connected)."
  fi

  sep; echo
  source "$ROOT/.venv/bin/activate"
  python -m webscanner k8s --path "$scan_path" $live_flag
  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [4] WPA Audit ─────────────────────────────────────────────────────────────
run_wpa_audit() {
  while true; do
    print_banner
    echo -e "  ${BOLD}${MAGENTA}WPA Password Audit${RESET}  ${DIM}(local aircrack-ng / hashcat)${RESET}\n"

    local has_aircrack=false has_hashcat=false
    command -v aircrack-ng &>/dev/null && has_aircrack=true
    command -v hashcat     &>/dev/null && has_hashcat=true

    if [[ "$has_aircrack" == false && "$has_hashcat" == false ]]; then
      warn "Neither aircrack-ng nor hashcat is installed."
      info "Install on macOS:        ${DIM}brew install aircrack-ng hashcat${RESET}"
      info "Install on Debian/Ubuntu:${DIM}sudo apt install aircrack-ng hashcat${RESET}"
      echo
      read -rp "  Press Enter to return to menu..." _
      return
    fi

    sep
    echo -e "  ${BOLD}What do you want to do?${RESET}\n"
    [[ "$has_aircrack" == true ]] && \
      echo -e "  ${CYAN}[1]${RESET}  aircrack-ng  — dictionary attack on a .cap file"
    [[ "$has_hashcat" == true ]] && \
      echo -e "  ${CYAN}[2]${RESET}  hashcat      — dictionary attack on a .hc22000 file"
    echo -e "  ${CYAN}[0]${RESET}  Back to main menu"
    echo
    read -rp "  Choice [0]: " choice
    choice="${choice:-0}"

    case "$choice" in
      1)
        if [[ "$has_aircrack" == false ]]; then warn "aircrack-ng not installed."; sleep 1; continue; fi
        cap=$(pick_capture) || { read -rp "  Press Enter to continue..." _; continue; }
        wl=$(pick_wordlist)
        echo
        info "Running aircrack-ng..."
        info "Capture:  $(basename "$cap")"
        info "Wordlist: $(basename "$wl")"
        sep; echo
        aircrack-ng -w "$wl" "$cap"
        echo
        read -rp "  Press Enter to continue..." _
        ;;
      2)
        if [[ "$has_hashcat" == false ]]; then warn "hashcat not installed."; sleep 1; continue; fi
        cap=$(pick_capture) || { read -rp "  Press Enter to continue..." _; continue; }
        wl=$(pick_wordlist)
        echo
        info "Running hashcat (mode 22000)..."
        info "Capture:  $(basename "$cap")"
        info "Wordlist: $(basename "$wl")"
        sep; echo
        hashcat -m 22000 "$cap" "$wl" -O --potfile-path "$ROOT/captures/hashcat.pot"
        echo
        read -rp "  Press Enter to continue..." _
        ;;
      0) return ;;
      *) warn "Invalid choice." ;;
    esac
  done
}

# ── [5] Download wordlists ────────────────────────────────────────────────────
download_wordlists() {
  print_banner
  echo -e "  ${BOLD}Download Wordlists${RESET}  ${DIM}(SecLists + optional rockyou)${RESET}\n"

  if [[ -f "$ROOT/.venv/bin/activate" ]]; then
    source "$ROOT/.venv/bin/activate"
    python "$ROOT/wordlists/download_wordlists.py"
  else
    python3 "$ROOT/wordlists/download_wordlists.py"
  fi

  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── [9] Install Security Tools ────────────────────────────────────────────────
run_install_tools() {
  print_banner
  echo -e "  ${BOLD}Security Tool Installer${RESET}  ${DIM}(via Homebrew)${RESET}\n"

  # Tools list: pairs of "name|description" — bash 3.x compatible (no declare -A)
  local TOOL_ENTRIES=(
    "nmap|Port scanning & service/OS detection"
    "aircrack-ng|WPA handshake dictionary cracking"
    "hashcat|GPU-accelerated password cracking"
    "nikto|Web vulnerability scanner"
    "nuclei|Fast template-based vulnerability scanner"
    "gobuster|Directory, DNS, and vhost brute force"
    "sqlmap|Automated SQL injection testing"
    "hydra|Network login brute force (SSH, FTP, HTTP)"
    "hcxtools|PMKID capture & WPA attack toolkit"
    "ffuf|Fast web fuzzer"
  )

  # Helper: get description for a tool name
  _tool_desc() {
    local name="$1"
    for entry in "${TOOL_ENTRIES[@]}"; do
      if [[ "${entry%%|*}" == "$name" ]]; then
        echo "${entry#*|}"
        return
      fi
    done
    echo ""
  }

  # ── Check brew ───────────────────────────────────────────────────────────────
  local has_brew=false
  command -v brew &>/dev/null && has_brew=true

  if [[ "$has_brew" == false ]]; then
    warn "Homebrew is not installed."
    echo
    info "Homebrew is required to install security tools."
    info "Install command: ${DIM}/bin/bash -c \"\$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\"${RESET}"
    echo
    read -rp "  Install Homebrew now? [y/N] " yn
    yn=$(echo "$yn" | tr '[:upper:]' '[:lower:]')
    if [[ "$yn" != "y" ]]; then
      info "Skipping — install Homebrew manually and re-run this option."
      echo; read -rp "  Press Enter to return to menu..." _; return
    fi
    echo
    info "Installing Homebrew…"
    sep
    /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
    if command -v brew &>/dev/null; then
      ok "Homebrew installed successfully."
      has_brew=true
    else
      err "Homebrew installation failed. Please install manually."
      echo; read -rp "  Press Enter to return to menu..." _; return
    fi
    echo
  fi

  # ── Update brew ──────────────────────────────────────────────────────────────
  info "Updating Homebrew…"
  brew update --quiet 2>&1 | tail -3 | sed 's/^/  /'
  echo

  # ── Show tool status table ───────────────────────────────────────────────────
  sep
  printf "  ${BOLD}%-18s %-10s %s${RESET}\n" "Tool" "Status" "Purpose"
  sep

  local missing=()
  for entry in "${TOOL_ENTRIES[@]}"; do
    local tool="${entry%%|*}"
    local desc="${entry#*|}"
    if command -v "$tool" &>/dev/null; then
      printf "  ${GREEN}✓${RESET}  %-16s ${GREEN}%-10s${RESET} %s\n" "$tool" "installed" "$desc"
    else
      printf "  ${RED}✗${RESET}  %-16s ${DIM}%-10s${RESET} %s\n" "$tool" "missing" "$desc"
      missing+=("$tool")
    fi
  done
  sep
  echo

  if [[ ${#missing[@]} -eq 0 ]]; then
    ok "All tools are already installed!"
    echo; read -rp "  Press Enter to return to menu..." _; return
  fi

  info "Missing tools: ${CYAN}${missing[*]}${RESET}"
  echo
  read -rp "  Install ${#missing[@]} missing tool(s) now? [y/N] " yn
  yn=$(echo "$yn" | tr '[:upper:]' '[:lower:]')
  if [[ "$yn" != "y" ]]; then
    info "No tools installed."
    echo; read -rp "  Press Enter to return to menu..." _; return
  fi

  # ── Install missing tools ────────────────────────────────────────────────────
  echo
  local installed=() failed=()
  for tool in "${missing[@]}"; do
    echo -ne "  ${CYAN}→${RESET}  Installing ${BOLD}${tool}${RESET}…"
    if brew install "$tool" &>/dev/null 2>&1; then
      echo -e "\r  ${GREEN}✓${RESET}  Installed  ${BOLD}${tool}${RESET}"
      installed+=("$tool")
    else
      echo -e "\r  ${RED}✗${RESET}  Failed     ${BOLD}${tool}${RESET}"
      failed+=("$tool")
    fi
  done

  # ── Summary ──────────────────────────────────────────────────────────────────
  echo
  sep
  [[ ${#installed[@]} -gt 0 ]] && ok "Installed (${#installed[@]}): ${installed[*]}"
  [[ ${#failed[@]}    -gt 0 ]] && err "Failed    (${#failed[@]}):    ${failed[*]}"
  sep

  echo
  read -rp "  Press Enter to return to menu..." _
}

# ── Main menu ─────────────────────────────────────────────────────────────────
main_menu() {
  while true; do
    print_banner

    # WebScanner API + UI status
    local api_status ui_status
    if curl -sf http://localhost:8000/api/health >/dev/null 2>&1; then
      api_status="${GREEN}● running${RESET}"
    else
      api_status="${DIM}○ offline${RESET}"
    fi
    if curl -sf http://localhost:3000 >/dev/null 2>&1; then
      ui_status="${GREEN}● running${RESET}"
    else
      ui_status="${DIM}○ offline${RESET}"
    fi
    echo -e "  API ${api_status}   UI ${ui_status}"

    # Docker status (quick — no timeout)
    local docker_status kubectl_status
    if command -v docker &>/dev/null; then
      if docker info &>/dev/null 2>&1; then
        docker_status="${GREEN}● running${RESET}"
      else
        docker_status="${YELLOW}● stopped${RESET}"
      fi
    else
      docker_status="${RED}● not installed${RESET}"
    fi
    # kubectl status (quick client check only)
    if command -v kubectl &>/dev/null; then
      if kubectl cluster-info --request-timeout=2s &>/dev/null 2>&1; then
        kubectl_status="${GREEN}● connected${RESET}"
      else
        kubectl_status="${YELLOW}● no cluster${RESET}"
      fi
    else
      kubectl_status="${RED}● not installed${RESET}"
    fi
    echo -e "  Docker ${docker_status}   kubectl ${kubectl_status}"
    echo

    sep
    echo -e "  ${BOLD}Services${RESET}"
    echo -e "  ${CYAN}[1]${RESET}  Start           — launch API + UI"
    echo -e "  ${CYAN}[2]${RESET}  Stop            — stop API + UI"
    echo -e "  ${CYAN}[3]${RESET}  Status          — full status report"
    echo
    echo -e "  ${BOLD}WiFi${RESET}"
    echo -e "  ${CYAN}[4]${RESET}  WPA Audit       — dictionary attack on captured handshake"
    echo -e "  ${CYAN}[5]${RESET}  WiFi Attack     — online brute force against a live SSID"
    echo
    echo -e "  ${BOLD}Infrastructure${RESET}"
    echo -e "  ${CYAN}[6]${RESET}  Docker Scan     — Dockerfile / compose / container checks  ${docker_status}"
    echo -e "  ${CYAN}[7]${RESET}  K8s Scan        — manifest / live cluster checks           ${kubectl_status}"
    echo
    echo -e "  ${CYAN}[8]${RESET}  Download wordlists"
    echo -e "  ${CYAN}[9]${RESET}  Install Tools   — brew install security tools"
    echo -e "  ${CYAN}[0]${RESET}  Exit"
    sep
    echo
    read -rp "  Choice [1]: " choice
    choice="${choice:-1}"
    echo

    case "$choice" in
      1) start_services ;;
      2) stop_services ;;
      3) show_status ;;
      4) run_wpa_audit ;;
      5) run_wifi_attack ;;
      6) run_docker_scan ;;
      7) run_k8s_scan ;;
      8) download_wordlists ;;
      9) run_install_tools ;;
      0) echo -e "  ${DIM}Bye.${RESET}\n"; exit 0 ;;
      *) warn "Unknown option '${choice}'. Try again."; sleep 1 ;;
    esac
  done
}

# ── Entry point ───────────────────────────────────────────────────────────────
# Direct shortcuts: ./start.sh start | stop | status | wpa-audit | wordlists
case "${1:-}" in
  start)        check_deps && start_services ;;
  stop)         stop_services ;;
  status)       show_status ;;
  wpa-audit)    run_wpa_audit ;;
  wifi-attack)  run_wifi_attack ;;
  docker-scan)  run_docker_scan ;;
  k8s-scan)     run_k8s_scan ;;
  wordlists)    download_wordlists ;;
  install-tools) run_install_tools ;;
  *)            main_menu ;;
esac
