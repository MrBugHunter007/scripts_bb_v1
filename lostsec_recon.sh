#!/usr/bin/env bash
# =============================================================================
#  lostsec_recon.sh — Exact workflow from:
#  "A Practical Workflow for Fuzzing and Scanning in Bug Bounty" by LostSec
# =============================================================================

set -euo pipefail

# ─── Colours ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
BOLD='\033[1m'
RESET='\033[0m'

info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*" >&2; }
step()    { echo -e "\n${BOLD}${BLUE}━━━ $* ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"; }

# ─── Banner ───────────────────────────────────────────────────────────────────
banner() {
  echo -e "${CYAN}${BOLD}"
  cat <<'EOF'
  ██╗      ██████╗ ███████╗████████╗███████╗███████╗ ██████╗
  ██║     ██╔═══██╗██╔════╝╚══██╔══╝██╔════╝██╔════╝██╔════╝
  ██║     ██║   ██║███████╗   ██║   ███████╗█████╗  ██║
  ██║     ██║   ██║╚════██║   ██║   ╚════██║██╔══╝  ██║
  ███████╗╚██████╔╝███████║   ██║   ███████║███████╗╚██████╗
  ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚══════╝ ╚═════╝
EOF
  echo -e "${RESET}${BLUE}${BOLD}  Recon Workflow by LostSec  —  Bug Bounty Edition${RESET}"
  echo -e "${CYAN}  ──────────────────────────────────────────────────${RESET}\n"
}

# ─── Input ────────────────────────────────────────────────────────────────────
if [[ $# -ne 1 || -z "${1:-}" ]]; then
  error "Domain required."
  echo -e "  Usage:   $0 <domain>"
  echo -e "  Example: $0 redbull.com"
  exit 1
fi

DOMAIN="$1"
WORKDIR="results/${DOMAIN}"
WORDLIST="/root/lostsec/payloads/backup_files_only.txt"

export PATH="$PATH:$HOME/go/bin:/usr/local/go/bin"

# ─── Tool Check & Auto-Install ────────────────────────────────────────────────
check_tools() {
  step "Tool Check & Auto-Install"

  # Go
  if ! command -v go &>/dev/null; then
    warn "Go not found — installing Go 1.22 …"
    local ARCH; ARCH=$(uname -m)
    [[ "$ARCH" == "x86_64" ]] && ARCH="amd64" || ARCH="arm64"
    wget -q "https://go.dev/dl/go1.22.3.linux-${ARCH}.tar.gz" -O /tmp/go.tar.gz
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    export PATH="$PATH:/usr/local/go/bin"
    success "Go installed."
  fi

  declare -A TOOLS=(
    [chaos]="go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest"
    [httpx]="go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [naabu]="go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [nuclei]="go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [ffuf]="go install -v github.com/ffuf/ffuf/v2@latest"
  )

  for tool in chaos httpx naabu nuclei ffuf; do
    if command -v "$tool" &>/dev/null; then
      echo -e "  ${GREEN}[OK]${RESET}         $tool"
    else
      echo -ne "  ${YELLOW}[INSTALLING]${RESET} $tool … "
      if eval "${TOOLS[$tool]}" &>/dev/null 2>&1 && command -v "$tool" &>/dev/null; then
        echo -e "${GREEN}done${RESET}"
      else
        echo -e "${RED}FAILED — install manually${RESET}"
      fi
    fi
  done

  # nmap (apt)
  if command -v nmap &>/dev/null; then
    echo -e "  ${GREEN}[OK]${RESET}         nmap"
  else
    echo -ne "  ${YELLOW}[INSTALLING]${RESET} nmap … "
    sudo apt-get install -y -qq nmap &>/dev/null && echo -e "${GREEN}done${RESET}" || echo -e "${RED}FAILED${RESET}"
  fi

  # python3 (apt)
  if command -v python3 &>/dev/null; then
    echo -e "  ${GREEN}[OK]${RESET}         python3"
  else
    echo -ne "  ${YELLOW}[INSTALLING]${RESET} python3 … "
    sudo apt-get install -y -qq python3 &>/dev/null && echo -e "${GREEN}done${RESET}" || echo -e "${RED}FAILED${RESET}"
  fi

  echo ""
}

# ─── Setup ────────────────────────────────────────────────────────────────────
setup() {
  mkdir -p "$WORKDIR"
  cd "$WORKDIR"

  # ── Download naabutonmap.py if missing
  if [[ ! -f "naabutonmap.py" ]]; then
    info "Downloading naabutonmap.py from coffinxp/scripts …"
    wget -q "https://raw.githubusercontent.com/coffinxp/scripts/main/naabutonmap.py" \
         -O naabutonmap.py && success "naabutonmap.py downloaded." \
      || warn "Could not download naabutonmap.py — Phase 4 may fail."
  fi

  # ── Download nmap-parse-output if missing
  if [[ ! -f "nmap-parse-output" ]]; then
    info "Downloading nmap-parse-output from ernw …"
    wget -q "https://raw.githubusercontent.com/ernw/nmap-parse-output/master/nmap-parse-output" \
         -O nmap-parse-output \
      && chmod +x nmap-parse-output \
      && success "nmap-parse-output downloaded." \
      || warn "Could not download nmap-parse-output — HTML report step may fail."
  fi

  # ── Download wordlist if missing
  if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist not found at ${WORDLIST}"
    info "Downloading backup_files_only.txt from coffinxp/payloads …"
    mkdir -p "$(dirname "$WORDLIST")"
    wget -q "https://raw.githubusercontent.com/coffinxp/payloads/main/backup_files_only.txt" \
         -O "$WORDLIST" \
      && success "Wordlist saved to ${WORDLIST}" \
      || warn "Could not download wordlist — ffuf step may fail."
  fi
}

# ─── Phase 1: Subdomain Discovery with Chaos ─────────────────────────────────
phase1_chaos() {
  step "Phase 1 — Subdomain Discovery with Chaos"
  info "Running: chaos -d ${DOMAIN} -o ${DOMAIN}.txt"

  chaos -d "$DOMAIN" -o "${DOMAIN}.txt" 2>/dev/null || {
    warn "chaos failed — check your CHAOS_KEY env variable."
    touch "${DOMAIN}.txt"
  }

  local count; count=$(wc -l < "${DOMAIN}.txt" 2>/dev/null || echo 0)
  success "Subdomains found: ${count} → ${DOMAIN}.txt"
}

# ─── Phase 2: Alive Hosts & IP Deduplication ─────────────────────────────────
phase2_httpx() {
  step "Phase 2 — Alive Hosts & IP Deduplication"

  if [[ ! -s "${DOMAIN}.txt" ]]; then
    warn "${DOMAIN}.txt is empty — skipping Phase 2."
    touch ip.txt
    return
  fi

  # ── Step 1: Use -title flag to spot CDN/WAF vs real origin ──
  info "Checking titles to detect CDN/WAF (Cloudflare, Akamai, Fastly) ..."
  info "Running: httpx -l ${DOMAIN}.txt -ip -title -silent > httpx_title.txt"
  httpx -l "${DOMAIN}.txt" -ip -title -silent > httpx_title.txt 2>/dev/null || true

  warn "NOTE: IPs showing generic CDN/WAF titles are edge servers — NOT real origins."
  warn "      Review httpx_title.txt to verify which IPs are worth targeting."

  # ── Step 2: Extract all unique IPs (exact sed from article) ──
  info "Running: httpx -l ${DOMAIN}.txt -ip -silent | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' | sort -u > ip.txt"
  httpx -l "${DOMAIN}.txt" -ip -silent \
    | sed -nE 's/.*\[([0-9.]+)\].*/\1/p' \
    | sort -u > ip_all.txt

  # ── Step 3: Filter known Cloudflare / Akamai / Fastly CIDR prefixes ──
  info "Filtering out CDN IPs (Cloudflare / Akamai / Fastly) ..."
  local CDN_PREFIXES=(
    "103.21.244" "103.22.200" "103.31.4" "104.16" "104.17" "104.18" "104.19"
    "104.20" "104.21" "104.22" "104.24" "104.25" "104.26" "104.27"
    "108.162.192" "131.0.72" "141.101.64" "141.101.65" "162.158"
    "172.64" "172.65" "172.66" "172.67" "172.68" "172.69" "172.70" "172.71"
    "188.114.96" "188.114.97" "188.114.98" "188.114.99"
    "190.93.240" "190.93.241" "190.93.242" "190.93.243"
    "197.234.240" "198.41.128" "198.41.129" "198.41.130" "198.41.131" "198.41.132"
    "151.101" "199.27.72" "199.27.73" "199.27.74" "199.27.75"
    "23.235.32" "23.235.33" "23.235.34" "23.235.35" "23.235.36"
    "23.32" "23.33" "23.34" "23.35" "23.36" "23.37" "23.38" "23.39"
    "2.16" "2.17" "2.18" "2.19" "2.20" "2.21" "2.22" "2.23"
    "92.122" "92.123" "95.100" "95.101"
  )

  cp ip_all.txt ip.txt
  for prefix in "${CDN_PREFIXES[@]}"; do
    sed -i "/^${prefix}\./d" ip.txt 2>/dev/null || true
  done

  local total; total=$(wc -l < ip_all.txt)
  local clean; clean=$(wc -l < ip.txt)
  local removed=$(( total - clean ))

  success "Total IPs: ${total} | CDN removed: ${removed} | Origin IPs kept: ${clean} → ip.txt"
  info "Title scan saved → httpx_title.txt  (review for manual CDN verification)"
}

# ─── Phase 3: Port Scanning with Naabu ───────────────────────────────────────
phase3_naabu() {
  step "Phase 3 — Port Scanning with Naabu"

  if [[ ! -s "ip.txt" ]]; then
    warn "ip.txt is empty — skipping Phase 3."
    touch naabu.txt
    return
  fi

  info "Running: naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt"

  # ── Exact command from article ──
  naabu -l ip.txt -top-ports 100 -rate 1500 -verify -silent -o naabu.txt 2>/dev/null || touch naabu.txt

  local count; count=$(wc -l < naabu.txt)
  success "Open ports found: ${count} → naabu.txt"
}

# ─── Phase 4: Service Detection & Nmap Parsing ───────────────────────────────
phase4_nmap() {
  step "Phase 4 — Service Detection & Nmap Parsing"

  if [[ ! -s "naabu.txt" ]]; then
    warn "naabu.txt is empty — skipping Phase 4."
    return
  fi

  # ── naabutonmap.py ──
  if [[ -f "naabutonmap.py" ]]; then
    info "Running: python3 naabutonmap.py -i naabu.txt"
    python3 naabutonmap.py -i naabu.txt 2>/dev/null || warn "naabutonmap.py encountered errors."
  else
    warn "naabutonmap.py not found — skipping Nmap scan."
  fi

  # ── nmap-parse-output: find latest XML and convert to HTML ──
  if [[ -f "nmap-parse-output" ]]; then
    local xml_file
    xml_file=$(find nmap-out -name "*.xml" 2>/dev/null | sort | tail -n 1 || true)

    if [[ -n "$xml_file" ]]; then
      info "Running: nmap-parse-output ${xml_file} html > scan.html"
      nmap-parse-output "$xml_file" html > scan.html 2>/dev/null \
        && success "HTML report generated → scan.html" \
        || warn "nmap-parse-output failed."
    else
      warn "No Nmap XML output found — skipping HTML report."
    fi
  else
    warn "nmap-parse-output not found — skipping HTML report."
  fi
}

# ─── Phase 5: Nuclei Vulnerability Scanning ──────────────────────────────────
phase5_nuclei() {
  step "Phase 5 — Automated Vulnerability Scanning with Nuclei"

  info "Updating nuclei templates …"
  nuclei -update-templates -silent 2>/dev/null || true

  # ── Scan live IPs for known CVEs (exact command from article) ──
  if [[ -s "ip.txt" ]]; then
    info "Running: cat ip.txt | nuclei -tags cve -bs 200"
    cat ip.txt | nuclei -tags cve -bs 200 \
      -o nuclei_ips.txt 2>/dev/null || true
    local c1; c1=$(wc -l < nuclei_ips.txt 2>/dev/null || echo 0)
    success "Nuclei (IPs) findings: ${c1} → nuclei_ips.txt"
  else
    warn "ip.txt is empty — skipping nuclei IP scan."
  fi

  # ── Scan all discovered ports / naabu output (exact command from article) ──
  if [[ -s "naabu.txt" ]]; then
    info "Running: cat naabu.txt | nuclei -tags cve -bs 200"
    cat naabu.txt | nuclei -tags cve -bs 200 \
      -o nuclei_ports.txt 2>/dev/null || true
    local c2; c2=$(wc -l < nuclei_ports.txt 2>/dev/null || echo 0)
    success "Nuclei (ports) findings: ${c2} → nuclei_ports.txt"
  else
    warn "naabu.txt is empty — skipping nuclei port scan."
  fi
}

# ─── Phase 6: Content Discovery & Fuzzing with FFUF ─────────────────────────
phase6_ffuf() {
  step "Phase 6 — Content Discovery & Fuzzing with FFUF"

  if [[ ! -f "$WORDLIST" ]]; then
    warn "Wordlist not found: ${WORDLIST} — skipping ffuf."
    return
  fi

  # ── Fuzz using ip.txt (exact command from article) ──
  if [[ -s "ip.txt" ]]; then
    info "Running: ffuf -w ip.txt:SUB -w ${WORDLIST}:FILE -u https://SUB/FILE …"
    ffuf \
      -w "ip.txt:SUB" \
      -w "${WORDLIST}:FILE" \
      -u "https://SUB/FILE" \
      -mc 200 \
      -rate 50 \
      -fs 0 \
      -c \
      -o ffuf_ips.txt \
      -of csv \
      2>/dev/null || warn "ffuf (ip.txt) encountered errors."
    success "ffuf (IPs) results → ffuf_ips.txt"
  else
    warn "ip.txt is empty — skipping ffuf IP fuzz."
  fi

  # ── Fuzz using naabu.txt (exact command from article) ──
  if [[ -s "naabu.txt" ]]; then
    info "Running: ffuf -w naabu.txt:SUB -w ${WORDLIST}:FILE -u https://SUB/FILE …"
    ffuf \
      -w "naabu.txt:SUB" \
      -w "${WORDLIST}:FILE" \
      -u "https://SUB/FILE" \
      -mc 200 \
      -rate 50 \
      -fs 0 \
      -c \
      -o ffuf_ports.txt \
      -of csv \
      2>/dev/null || warn "ffuf (naabu.txt) encountered errors."
    success "ffuf (ports) results → ffuf_ports.txt"
  else
    warn "naabu.txt is empty — skipping ffuf port fuzz."
  fi
}

# ─── Summary ──────────────────────────────────────────────────────────────────
summary() {
  echo -e "\n${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${GREEN}${BOLD}  SUMMARY — ${DOMAIN}${RESET}"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  declare -A LABELS=(
    ["${DOMAIN}.txt"]="Subdomains (chaos)"
    ["ip.txt"]="Unique IPs (httpx)"
    ["naabu.txt"]="Open ports (naabu)"
    ["nuclei_ips.txt"]="Nuclei hits on IPs"
    ["nuclei_ports.txt"]="Nuclei hits on ports"
    ["ffuf_ips.txt"]="FFUF hits (IPs)"
    ["ffuf_ports.txt"]="FFUF hits (ports)"
    ["scan.html"]="Nmap HTML report"
  )

  for f in "${DOMAIN}.txt" ip.txt naabu.txt nuclei_ips.txt nuclei_ports.txt ffuf_ips.txt ffuf_ports.txt scan.html; do
    if [[ -f "$f" ]]; then
      if [[ "$f" == *.html ]]; then
        printf "  ${GREEN}%-30s${RESET} %s\n" "${LABELS[$f]}:" "generated"
      else
        local c; c=$(wc -l < "$f" 2>/dev/null || echo 0)
        printf "  ${GREEN}%-30s${RESET} %s\n" "${LABELS[$f]:-$f}:" "$c lines"
      fi
    fi
  done

  echo -e "\n  ${BOLD}Output:${RESET} ${WORKDIR}/"
  echo -e "${CYAN}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}\n"
}

# ─── Main ─────────────────────────────────────────────────────────────────────
main() {
  banner
  info "Target: ${BOLD}${DOMAIN}${RESET}"
  echo ""

  check_tools
  setup

  phase1_chaos
  phase2_httpx
  phase3_naabu
  phase4_nmap
  phase5_nuclei
  phase6_ffuf

  summary
  success "Done. Happy hunting!"
}

main "$@"

