#!/usr/bin/env bash
# =============================================================================
#  LostScanner - Automated Bug Bounty Recon & Vulnerability Scanner
#  Author  : Based on coffinxp's 5-Minute Workflow methodology
#  Article : https://infosecwriteups.com/my-5-minute-workflow-to-find-bugs-on-any-website
#  Version : 1.0.0
#  Usage   : ./lostscanner.sh -d domain.com [OPTIONS]
#            ./lostscanner.sh -l domains.txt [OPTIONS]
# =============================================================================
# DISCLAIMER: For authorized security testing only. Always obtain written
# permission before scanning any target. Use responsibly.
# =============================================================================

set -euo pipefail
IFS=$'\n\t'

# ---------------------------------------------------------------------------
# COLOUR PALETTE
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# ---------------------------------------------------------------------------
# LOGGING HELPERS
# ---------------------------------------------------------------------------
info()    { echo -e "${CYAN}[*]${RESET} $*"; }
success() { echo -e "${GREEN}[✔]${RESET} $*"; }
warn()    { echo -e "${YELLOW}[!]${RESET} $*"; }
error()   { echo -e "${RED}[✘]${RESET} $*" >&2; }
banner()  { echo -e "${MAGENTA}${BOLD}$*${RESET}"; }
step()    { echo -e "\n${BLUE}${BOLD}[➤] $*${RESET}"; }
dim()     { echo -e "${DIM}$*${RESET}"; }

# ---------------------------------------------------------------------------
# BANNER
# ---------------------------------------------------------------------------
print_banner() {
cat << 'EOF'
 _              _   ____                                 
| |    ___  ___| |_/ ___|  ___ __ _ _ __  _ __   ___ _ __
| |   / _ \/ __| __\___ \ / __/ _` | '_ \| '_ \ / _ \ '__|
| |__| (_) \__ \ |_ ___) | (_| (_| | | | | | | |  __/ |   
|_____\___/|___/\__|____/ \___\__,_|_| |_|_| |_|\___|_|   
EOF
    echo -e "${CYAN}    Automated Bug Bounty Recon | Inspired by coffinxp's Workflow${RESET}"
    echo -e "${DIM}    https://infosecwriteups.com/my-5-minute-workflow-to-find-bugs-on-any-website${RESET}"
    echo -e "${DIM}    ─────────────────────────────────────────────────────────────────────${RESET}\n"
}

# ---------------------------------------------------------------------------
# GLOBAL DEFAULTS
# ---------------------------------------------------------------------------
DOMAIN=""
DOMAIN_LIST=""
OUTPUT_BASE="recon"
SCRIPTS_DIR="$(pwd)/scripts"      # coffinxp's cloned scripts repo path
NUCLEI_TAGS=""                     # optional: -t cve,xss etc.
IP_LIST=""                         # optional: Shodan IP file for mass scan
THREADS=50
BATCH_SIZE=50
WAYBACK_SUBDOMAIN="-s"             # include subdomains by default
WAYBACK_STATUS="-sc 200,301,302,403"
SKIP_NUCLEI=false
SKIP_WAYBACK=false
SKIP_ALIENVAULT=false
SKIP_VIRUSTOTAL=false
SKIP_GF=false
VERBOSE=false
MAX_PARALLEL=3                     # max parallel domain workers

# ---------------------------------------------------------------------------
# CDN / WAF SIGNATURES  (used to skip scanning CDN edge nodes)
# ---------------------------------------------------------------------------
CDN_SIGNATURES=(
    "cloudflare"
    "akamai"
    "fastly"
    "cloudfront"
    "sucuri"
    "incapsula"
    "imperva"
    "stackpath"
    "maxcdn"
    "keycdn"
    "cdn77"
    "bunnycdn"
    "edgecast"
    "limelight"
    "level3"
    "verizon"
)

# ---------------------------------------------------------------------------
# USAGE
# ---------------------------------------------------------------------------
usage() {
    cat << EOF
${BOLD}USAGE:${RESET}
  $(basename "$0") -d <domain>        Single domain scan
  $(basename "$0") -l <file>          Multi-domain scan from file
  $(basename "$0") --shodan <ip-file> Shodan IP list → direct Nuclei scan

${BOLD}OPTIONS:${RESET}
  -d  <domain>      Target domain (e.g. example.com)
  -l  <file>        File containing one domain per line
  -o  <dir>         Output base directory (default: ./recon)
  -t  <tags>        Nuclei tags/CVEs (e.g. cve,xss,lfi) [optional]
  --shodan <file>   IP list from Shodan for mass CVE scanning
  --scripts <dir>   Path to coffinxp/scripts repo (default: ./scripts)
  --threads <n>     Nuclei thread count (default: 50)
  --skip-nuclei     Skip Nuclei scanning phase
  --skip-wayback    Skip Waybackurls phase
  --skip-alien      Skip AlienVault phase
  --skip-vt         Skip VirusTotal phase
  --skip-gf         Skip GF pattern filtering
  -v                Verbose output
  -h                Show this help

${BOLD}EXAMPLES:${RESET}
  $(basename "$0") -d example.com
  $(basename "$0") -d example.com -t cve,xss -o /tmp/recon
  $(basename "$0") -l targets.txt --threads 100
  $(basename "$0") --shodan shodan_ips.txt -t grafana
  $(basename "$0") -d example.com --skip-nuclei -v

${BOLD}REQUIREMENTS:${RESET}
  nuclei, httpx, gf, uro, waybackurls
  coffinxp/scripts: alienvault.sh, wayback.sh, virustotal.sh
EOF
    exit 0
}

# ---------------------------------------------------------------------------
# ARGUMENT PARSING
# ---------------------------------------------------------------------------
parse_args() {
    [[ $# -eq 0 ]] && usage

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -d)         DOMAIN="$2";          shift 2 ;;
            -l)         DOMAIN_LIST="$2";     shift 2 ;;
            -o)         OUTPUT_BASE="$2";     shift 2 ;;
            -t)         NUCLEI_TAGS="$2";     shift 2 ;;
            --shodan)   IP_LIST="$2";         shift 2 ;;
            --scripts)  SCRIPTS_DIR="$2";     shift 2 ;;
            --threads)  THREADS="$2";         BATCH_SIZE="$2"; shift 2 ;;
            --skip-nuclei)  SKIP_NUCLEI=true;    shift ;;
            --skip-wayback) SKIP_WAYBACK=true;   shift ;;
            --skip-alien)   SKIP_ALIENVAULT=true; shift ;;
            --skip-vt)      SKIP_VIRUSTOTAL=true; shift ;;
            --skip-gf)      SKIP_GF=true;        shift ;;
            -v)         VERBOSE=true;         shift ;;
            -h|--help)  usage ;;
            *)          error "Unknown option: $1"; usage ;;
        esac
    done

    # Validate: must have at least one target input
    if [[ -z "$DOMAIN" && -z "$DOMAIN_LIST" && -z "$IP_LIST" ]]; then
        error "No target specified. Use -d, -l, or --shodan"
        usage
    fi
}

# ---------------------------------------------------------------------------
# DEPENDENCY CHECKER
# ---------------------------------------------------------------------------
check_dependencies() {
    step "Checking dependencies"

    local required_tools=("nuclei" "httpx" "gf" "uro" "waybackurls")
    local missing=()

    for tool in "${required_tools[@]}"; do
        if command -v "$tool" &>/dev/null; then
            success "$tool found: $(command -v "$tool")"
        else
            missing+=("$tool")
            error "$tool NOT found"
        fi
    done

    # Check coffinxp scripts
    local scripts=("alienvault.sh" "wayback.sh" "virustotal.sh")
    for script in "${scripts[@]}"; do
        local path="$SCRIPTS_DIR/$script"
        if [[ -f "$path" ]]; then
            chmod +x "$path" 2>/dev/null || true
            success "Script found: $path"
        else
            warn "Script missing: $path (phase will be skipped)"
        fi
    done

    # Check optional Python script for URLScan
    if [[ -f "$SCRIPTS_DIR/urlscan.py" ]]; then
        success "urlscan.py found"
    else
        warn "urlscan.py not found in $SCRIPTS_DIR (phase will be skipped)"
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
        error "Missing required tools: ${missing[*]}"
        error "Install via: go install / apt / snap depending on tool"
        exit 1
    fi

    success "All required dependencies satisfied"
}

# ---------------------------------------------------------------------------
# OUTPUT DIRECTORY SETUP
# ---------------------------------------------------------------------------
setup_output_dir() {
    local domain="$1"
    # Sanitise domain for use as a directory name
    local safe_domain
    safe_domain=$(echo "$domain" | tr '/' '_' | tr ':' '_')
    local outdir="$OUTPUT_BASE/$safe_domain"
    mkdir -p "$outdir"
    echo "$outdir"
}

# ---------------------------------------------------------------------------
# PHASE 1 — URL GATHERING
# ---------------------------------------------------------------------------

## 1a. AlienVault OTX
run_alienvault() {
    local domain="$1"
    local outdir="$2"
    local outfile="$outdir/alienvault_urls.txt"

    [[ "$SKIP_ALIENVAULT" == true ]] && return
    [[ ! -f "$SCRIPTS_DIR/alienvault.sh" ]] && warn "alienvault.sh missing, skipping" && return

    info "AlienVault OTX → $domain"
    if "$SCRIPTS_DIR/alienvault.sh" "$domain" > "$outfile" 2>/dev/null; then
        local count
        count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
        success "AlienVault: $count URLs collected"
    else
        warn "AlienVault returned non-zero (may be partial results)"
    fi
}

## 1b. Waybackurls via wayback.sh
run_wayback() {
    local domain="$1"
    local outdir="$2"
    local outfile="$outdir/wayback_urls.txt"

    [[ "$SKIP_WAYBACK" == true ]] && return

    # Prefer coffinxp's wrapper; fall back to raw waybackurls
    if [[ -f "$SCRIPTS_DIR/wayback.sh" ]]; then
        info "Wayback (coffinxp wrapper) → $domain $WAYBACK_SUBDOMAIN $WAYBACK_STATUS"
        "$SCRIPTS_DIR/wayback.sh" "$domain" $WAYBACK_SUBDOMAIN $WAYBACK_STATUS \
            > "$outfile" 2>/dev/null || warn "wayback.sh returned non-zero"
    else
        info "Wayback (raw waybackurls) → $domain"
        echo "$domain" | waybackurls > "$outfile" 2>/dev/null || true
    fi

    local count
    count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    success "Waybackurls: $count URLs collected"
}

## 1c. VirusTotal
run_virustotal() {
    local domain="$1"
    local outdir="$2"
    local outfile="$outdir/virustotal_urls.txt"

    [[ "$SKIP_VIRUSTOTAL" == true ]] && return
    [[ ! -f "$SCRIPTS_DIR/virustotal.sh" ]] && warn "virustotal.sh missing, skipping" && return

    info "VirusTotal → $domain"
    if "$SCRIPTS_DIR/virustotal.sh" "$domain" > "$outfile" 2>/dev/null; then
        local count
        count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
        success "VirusTotal: $count URLs collected"
    else
        warn "VirusTotal returned non-zero (API key quota or missing keys?)"
    fi
}

## 1d. URLScan.io (Python script — optional)
run_urlscan() {
    local domain="$1"
    local outdir="$2"
    local outfile="$outdir/urlscan_urls.txt"

    [[ ! -f "$SCRIPTS_DIR/urlscan.py" ]] && return

    info "URLScan.io → $domain"
    python3 "$SCRIPTS_DIR/urlscan.py" -d "$domain" --mode urls \
        > "$outfile" 2>/dev/null || warn "urlscan.py returned non-zero"

    local count
    count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
    success "URLScan.io: $count URLs collected"
}

# ---------------------------------------------------------------------------
# PHASE 2 — MERGE & DEDUPLICATE
# ---------------------------------------------------------------------------
merge_and_clean() {
    local outdir="$1"
    local all_file="$outdir/all_urls.txt"
    local clean_file="$outdir/clean_urls.txt"

    step "Merging and deduplicating URLs"

    # Concatenate all source files that exist and have content
    : > "$all_file"
    for src in alienvault_urls wayback_urls virustotal_urls urlscan_urls; do
        local f="$outdir/${src}.txt"
        if [[ -f "$f" && -s "$f" ]]; then
            cat "$f" >> "$all_file"
            dim "  + $(wc -l < "$f") lines from $src"
        fi
    done

    local raw_count
    raw_count=$(wc -l < "$all_file" 2>/dev/null || echo 0)
    info "Total raw URLs: $raw_count"

    if [[ "$raw_count" -eq 0 ]]; then
        warn "No URLs gathered — check your scripts, API keys, and network."
        touch "$clean_file"
        return
    fi

    # uro: advanced URL deduplication & normalisation
    sort -u "$all_file" | uro > "$clean_file" 2>/dev/null || sort -u "$all_file" > "$clean_file"

    local clean_count
    clean_count=$(wc -l < "$clean_file" 2>/dev/null || echo 0)
    success "Unique/clean URLs after uro: $clean_count (removed $((raw_count - clean_count)) duplicates)"
}

# ---------------------------------------------------------------------------
# PHASE 3 — GF PATTERN FILTERING
# ---------------------------------------------------------------------------
run_gf_filters() {
    local outdir="$1"
    local clean_file="$outdir/clean_urls.txt"

    [[ "$SKIP_GF" == true ]] && return
    [[ ! -s "$clean_file" ]] && warn "clean_urls.txt is empty; skipping GF phase" && return

    step "GF pattern filtering"

    # Patterns aligned to coffinxp's workflow
    local patterns=("xss" "sqli" "idor" "ssrf" "redirect" "rce" "lfi" "ssti" "open-redirect")

    for pattern in "${patterns[@]}"; do
        local outfile="$outdir/${pattern}.txt"
        if gf "$pattern" < "$clean_file" > "$outfile" 2>/dev/null; then
            local count
            count=$(wc -l < "$outfile" 2>/dev/null || echo 0)
            if [[ "$count" -gt 0 ]]; then
                success "gf $pattern → $count potential targets → ${pattern}.txt"
            else
                dim "  gf $pattern → 0 matches"
                rm -f "$outfile"   # remove empty files
            fi
        else
            warn "gf pattern '$pattern' not available (install from coffinxp/GFpattren)"
        fi
    done
}

# ---------------------------------------------------------------------------
# PHASE 4 — CDN / WAF DETECTION  (skip CDN-fronted IPs from nuclei)
# ---------------------------------------------------------------------------
is_cdn() {
    # Returns 0 (true) if the host appears to be a CDN/WAF edge node
    local title_tech="$1"
    local lower
    lower=$(echo "$title_tech" | tr '[:upper:]' '[:lower:]')
    for sig in "${CDN_SIGNATURES[@]}"; do
        if echo "$lower" | grep -q "$sig"; then
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# PHASE 5 — LIVE HOST DETECTION WITH HTTPX
# ---------------------------------------------------------------------------
run_httpx() {
    local outdir="$1"
    local clean_file="$outdir/clean_urls.txt"
    local live_file="$outdir/live_hosts.txt"
    local live_raw="$outdir/live_hosts_raw.txt"
    local cdn_file="$outdir/cdn_hosts.txt"

    [[ ! -s "$clean_file" ]] && warn "clean_urls.txt empty; skipping httpx" && return

    step "Live host detection with httpx"

    # Run httpx with title + tech detect + status codes
    httpx \
        -l "$clean_file" \
        -title \
        -tech-detect \
        -status-code \
        -silent \
        -threads "$THREADS" \
        -o "$live_raw" \
        2>/dev/null || true

    if [[ ! -s "$live_raw" ]]; then
        warn "httpx produced no live results"
        touch "$live_file"
        return
    fi

    # Separate CDN hosts from scannable hosts
    : > "$live_file"
    : > "$cdn_file"

    while IFS= read -r line; do
        if is_cdn "$line"; then
            echo "$line" >> "$cdn_file"
        else
            # Extract just the URL (first field) for nuclei
            echo "$line" | awk '{print $1}' >> "$live_file"
        fi
    done < "$live_raw"

    local live_count cdn_count
    live_count=$(wc -l < "$live_file" 2>/dev/null || echo 0)
    cdn_count=$(wc -l < "$cdn_file" 2>/dev/null || echo 0)

    success "Live hosts (scannable): $live_count → live_hosts.txt"
    [[ "$cdn_count" -gt 0 ]] && warn "CDN/WAF hosts detected & skipped: $cdn_count → cdn_hosts.txt"
}

# ---------------------------------------------------------------------------
# PHASE 6 — NUCLEI SCANNING
# ---------------------------------------------------------------------------
run_nuclei() {
    local outdir="$1"
    local live_file="$outdir/live_hosts.txt"
    local results_file="$outdir/nuclei_results.txt"

    [[ "$SKIP_NUCLEI" == true ]] && info "Nuclei skipped (--skip-nuclei)" && return
    [[ ! -s "$live_file" ]] && warn "live_hosts.txt empty; skipping nuclei" && return

    step "Nuclei vulnerability scanning"

    local nuclei_cmd=(
        nuclei
        -l "$live_file"
        -c "$THREADS"
        -bs "$BATCH_SIZE"
        -o "$results_file"
        -es info          # exclude informational (noise reduction)
        -silent
    )

    # Append tag filter if provided
    if [[ -n "$NUCLEI_TAGS" ]]; then
        nuclei_cmd+=(-tags "$NUCLEI_TAGS")
        info "Nuclei tags filter: $NUCLEI_TAGS"
    else
        # Default: run critical + high + medium severity
        nuclei_cmd+=(-severity critical,high,medium)
        info "Nuclei severity filter: critical,high,medium"
    fi

    [[ "$VERBOSE" == true ]] && nuclei_cmd+=(-v)

    info "Running: ${nuclei_cmd[*]}"
    "${nuclei_cmd[@]}" 2>/dev/null || warn "Nuclei returned non-zero exit (may be partial results)"

    if [[ -s "$results_file" ]]; then
        local hit_count
        hit_count=$(wc -l < "$results_file")
        success "Nuclei: $hit_count findings → nuclei_results.txt"
    else
        info "Nuclei: no findings for this target"
    fi
}

# ---------------------------------------------------------------------------
# SHODAN MODE — Mass IP Scanning (Method 1 from article)
# ---------------------------------------------------------------------------
run_shodan_mode() {
    local ip_file="$1"
    local outdir="$OUTPUT_BASE/shodan_scan"
    local results_file="$outdir/nuclei_shodan_results.txt"

    mkdir -p "$outdir"

    if [[ ! -f "$ip_file" ]]; then
        error "IP list file not found: $ip_file"
        exit 1
    fi

    local ip_count
    ip_count=$(wc -l < "$ip_file")

    step "Shodan Mode — Mass IP Scanning"
    info "IP list: $ip_file ($ip_count IPs)"
    info "Output: $outdir"

    # Optional: run httpx first to detect live IPs + CDN
    local live_ips="$outdir/live_ips.txt"
    info "Detecting live IPs with httpx..."
    httpx \
        -l "$ip_file" \
        -title \
        -tech-detect \
        -status-code \
        -silent \
        -threads "$THREADS" \
        2>/dev/null | while IFS= read -r line; do
            if ! is_cdn "$line"; then
                echo "$line" | awk '{print $1}'
            else
                warn "CDN detected, skipping: $(echo "$line" | awk '{print $1}')"
            fi
        done > "$live_ips"

    local live_count
    live_count=$(wc -l < "$live_ips" 2>/dev/null || echo 0)
    success "Live non-CDN IPs: $live_count"

    # Run Nuclei directly on IPs (as described in article)
    local nuclei_cmd=(
        nuclei
        -l "$live_ips"
        -c "$THREADS"
        -bs "$BATCH_SIZE"
        -o "$results_file"
        -es info
        -silent
    )

    if [[ -n "$NUCLEI_TAGS" ]]; then
        nuclei_cmd+=(-tags "$NUCLEI_TAGS")
        info "Nuclei tags: $NUCLEI_TAGS"
    fi

    [[ "$VERBOSE" == true ]] && nuclei_cmd+=(-v)

    info "Running Nuclei on $live_count IPs..."
    "${nuclei_cmd[@]}" 2>/dev/null || warn "Nuclei non-zero exit"

    if [[ -s "$results_file" ]]; then
        local hits
        hits=$(wc -l < "$results_file")
        success "Shodan scan complete: $hits findings → $results_file"
    else
        info "No findings from Shodan scan"
    fi

    print_summary_shodan "$outdir" "$ip_count" "$live_count"
}

# ---------------------------------------------------------------------------
# FULL SINGLE-DOMAIN SCAN PIPELINE
# ---------------------------------------------------------------------------
scan_domain() {
    local domain="$1"
    local outdir
    outdir=$(setup_output_dir "$domain")

    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    banner " TARGET : $domain"
    banner " OUTPUT : $outdir"
    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

    local start_time
    start_time=$(date +%s)

    # — Phase 1: URL Gathering (parallel where possible) —
    step "Phase 1 — URL Aggregation"

    # Run source scripts in parallel; capture PIDs for wait
    run_alienvault   "$domain" "$outdir" &
    local pid_alien=$!

    run_wayback      "$domain" "$outdir" &
    local pid_wayback=$!

    run_virustotal   "$domain" "$outdir" &
    local pid_vt=$!

    run_urlscan      "$domain" "$outdir" &
    local pid_urlscan=$!

    # Wait for all background jobs before proceeding
    wait "$pid_alien"   2>/dev/null || true
    wait "$pid_wayback" 2>/dev/null || true
    wait "$pid_vt"      2>/dev/null || true
    wait "$pid_urlscan" 2>/dev/null || true

    # — Phase 2: Merge & Clean —
    step "Phase 2 — Merge & Deduplicate"
    merge_and_clean "$outdir"

    # — Phase 3: GF Filtering —
    step "Phase 3 — GF Pattern Filtering"
    run_gf_filters "$outdir"

    # — Phase 4 & 5: httpx Live Detection —
    step "Phase 4 — Live Host Detection (httpx)"
    run_httpx "$outdir"

    # — Phase 6: Nuclei —
    step "Phase 5 — Nuclei Scanning"
    run_nuclei "$outdir"

    local end_time elapsed
    end_time=$(date +%s)
    elapsed=$((end_time - start_time))

    print_summary "$domain" "$outdir" "$elapsed"
}

# ---------------------------------------------------------------------------
# SUMMARY PRINTERS
# ---------------------------------------------------------------------------
print_summary() {
    local domain="$1"
    local outdir="$2"
    local elapsed="$3"

    echo ""
    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    banner " SCAN COMPLETE — $domain"
    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "${BOLD}  Output Directory:${RESET} $outdir"
    echo -e "${BOLD}  Elapsed:${RESET} ${elapsed}s"
    echo ""

    # File summary table
    local files=(
        "all_urls.txt:Raw URLs (merged)"
        "clean_urls.txt:Deduplicated URLs (uro)"
        "live_hosts.txt:Live + non-CDN hosts"
        "cdn_hosts.txt:CDN/WAF hosts (skipped)"
        "nuclei_results.txt:Nuclei findings"
        "xss.txt:XSS candidates"
        "sqli.txt:SQLi candidates"
        "idor.txt:IDOR candidates"
        "ssrf.txt:SSRF candidates"
        "redirect.txt:Open redirect candidates"
        "lfi.txt:LFI candidates"
        "rce.txt:RCE candidates"
        "ssti.txt:SSTI candidates"
    )

    printf "  %-30s %10s  %s\n" "FILE" "LINES" "DESCRIPTION"
    printf "  %-30s %10s  %s\n" "────────────────────────────" "──────────" "───────────────────────"

    for entry in "${files[@]}"; do
        local fname desc fpath count_str
        fname="${entry%%:*}"
        desc="${entry##*:}"
        fpath="$outdir/$fname"
        if [[ -f "$fpath" && -s "$fpath" ]]; then
            count_str=$(wc -l < "$fpath")
            printf "  ${GREEN}%-30s${RESET} %10s  ${DIM}%s${RESET}\n" "$fname" "$count_str" "$desc"
        else
            printf "  ${DIM}%-30s %10s  %s${RESET}\n" "$fname" "—" "$desc"
        fi
    done

    echo ""
    # Highlight nuclei findings if any
    if [[ -f "$outdir/nuclei_results.txt" && -s "$outdir/nuclei_results.txt" ]]; then
        local hits
        hits=$(wc -l < "$outdir/nuclei_results.txt")
        echo -e "  ${RED}${BOLD}⚠  $hits Nuclei finding(s) detected! Review: $outdir/nuclei_results.txt${RESET}"
    fi
    echo ""
}

print_summary_shodan() {
    local outdir="$1"
    local total="$2"
    local live="$3"

    echo ""
    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    banner " SHODAN SCAN COMPLETE"
    banner "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo -e "  IPs in list   : $total"
    echo -e "  Live (non-CDN): $live"
    if [[ -f "$outdir/nuclei_shodan_results.txt" && -s "$outdir/nuclei_shodan_results.txt" ]]; then
        local hits
        hits=$(wc -l < "$outdir/nuclei_shodan_results.txt")
        echo -e "  ${RED}${BOLD}Findings: $hits → $outdir/nuclei_shodan_results.txt${RESET}"
    else
        echo -e "  Findings: 0"
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# MULTI-DOMAIN WORKER
# ---------------------------------------------------------------------------
scan_domain_list() {
    local list_file="$1"

    if [[ ! -f "$list_file" ]]; then
        error "Domain list file not found: $list_file"
        exit 1
    fi

    local domains=()
    while IFS= read -r line; do
        # Strip whitespace and skip blanks/comments
        line=$(echo "$line" | tr -d '[:space:]')
        [[ -z "$line" || "$line" == \#* ]] && continue
        domains+=("$line")
    done < "$list_file"

    local total=${#domains[@]}
    info "Loaded $total domains from $list_file"
    info "Parallel workers: $MAX_PARALLEL"

    local pids=()
    local running=0

    for domain in "${domains[@]}"; do
        # Throttle parallel workers
        if [[ "$running" -ge "$MAX_PARALLEL" ]]; then
            wait "${pids[0]}"
            pids=("${pids[@]:1}")
            running=$((running - 1))
        fi

        scan_domain "$domain" &
        pids+=($!)
        running=$((running + 1))
    done

    # Wait for remaining workers
    for pid in "${pids[@]}"; do
        wait "$pid" 2>/dev/null || true
    done

    success "All $total domains scanned."
}

# ---------------------------------------------------------------------------
# MAIN ENTRY POINT
# ---------------------------------------------------------------------------
main() {
    print_banner
    parse_args "$@"
    check_dependencies

    # Ensure output base exists
    mkdir -p "$OUTPUT_BASE"

    # ── Shodan mass-IP mode (Method 1 from article) ──
    if [[ -n "$IP_LIST" ]]; then
        run_shodan_mode "$IP_LIST"
        exit 0
    fi

    # ── Multi-domain mode ──
    if [[ -n "$DOMAIN_LIST" ]]; then
        scan_domain_list "$DOMAIN_LIST"
        exit 0
    fi

    # ── Single-domain mode ──
    if [[ -n "$DOMAIN" ]]; then
        scan_domain "$DOMAIN"
        exit 0
    fi
}

main "$@"

