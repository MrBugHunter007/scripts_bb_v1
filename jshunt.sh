#!/usr/bin/env bash

# ============================================================
#  JS-HUNT SECRET SCANNER v3.1 — Stable Enterprise Edition
# ============================================================

set -euo pipefail

# ── Colors ───────────────────────────────────────────────────
R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'
C='\033[0;36m'; M='\033[0;35m'
W='\033[1;37m'; DIM='\033[2m'; NC='\033[0m'

# ── Defaults ──────────────────────────────────────────────────
THREADS=10
RATE=10
TIMEOUT=10
DOMAIN=""
LIST=""
OUTPUT_BASE="out"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
START_TIME=$(date +%s)

# ── Logging (stderr only) ────────────────────────────────────
log() { printf "  %b[%s]%b %b%s%b\n" "$2" "$1" "$NC" "$DIM" "$3" "$NC" >&2; }
ok()    { log "OK"  "$G" "$1"; }
info()  { log "*"   "$C" "$1"; }
warn()  { log "!"   "$Y" "$1"; }
error() { log "ERR" "$R" "$1"; }

# ── Cleanup Trap ─────────────────────────────────────────────
TMP_FILES=()
cleanup() { for f in "${TMP_FILES[@]}"; do [[ -f "$f" ]] && rm -f "$f"; done; }
trap cleanup EXIT

# ── False Positive Filter ────────────────────────────────────
is_false_positive() {
  local val="$1"
  [[ ${#val} -lt 10 ]] && return 0
  echo "$val" | grep -qiE '(test|example|dummy|sample|changeme|12345678|abcdefgh|null|undefined|localhost|placeholder|YOUR_|INSERT_|REPLACE_)' && return 0
  echo "$val" | grep -qP '^(.)\1{7,}$' && return 0
  return 1
}

# ── Secret Regex ─────────────────────────────────────────────
SECRET_REGEX='(?i)(api[_-]?key|secret|token|password|access[_-]?key)[^"\047]{0,20}["\047:=> ]{1,3}([0-9a-zA-Z_\-]{10,})'

# ── Dependency Check ─────────────────────────────────────────
check_deps() {
  local tools=(subfinder httpx katana gau waybackurls subjs gf curl)
  for t in "${tools[@]}"; do
    command -v "$t" >/dev/null 2>&1 || warn "$t not found (some features may be skipped)"
  done
}

# ── Step 1: Subdomains ───────────────────────────────────────
step_subdomains() {
  local domain="$1"
  local outdir="$2"
  local subfile="${outdir}/subdomains.txt"

  [[ -f "$subfile" ]] && { info "Subdomains already exist — skipping"; return; }

  echo "$domain" > "$subfile"

  if command -v subfinder >/dev/null 2>&1; then
    info "Running subfinder..."
    subfinder -d "$domain" -silent >> "$subfile" 2>/dev/null || true
    sort -u "$subfile" -o "$subfile"
  fi

  ok "Subdomains: $(wc -l < "$subfile")"
}

# ── Step 2: Live Hosts ───────────────────────────────────────
step_live_hosts() {
  local outdir="$1"
  local subfile="$2"
  local livefile="${outdir}/live_hosts.txt"

  [[ -f "$livefile" ]] && { info "Live hosts already exist — skipping"; return; }

  if command -v httpx >/dev/null 2>&1; then
    info "Probing with httpx..."
    httpx -l "$subfile" -silent -threads "$THREADS" -rate-limit "$RATE" -timeout "$TIMEOUT" -o "$livefile" 2>/dev/null || true
  else
    while read -r sub; do
      curl -Is --max-time "$TIMEOUT" "https://$sub" 2>/dev/null | grep -q "200" && echo "https://$sub" >> "$livefile"
    done < "$subfile"
  fi

  [[ ! -f "$livefile" ]] && touch "$livefile"
  ok "Live Hosts: $(wc -l < "$livefile")"
}

# ── Step 3: Collect JS ───────────────────────────────────────
step_collect_js() {
  local outdir="$1"
  local livefile="$2"
  local domain="$3"
  local jsfile="${outdir}/js_files.txt"

  [[ -f "$jsfile" ]] && { info "JS file list already exists — skipping"; return; }

  touch "$jsfile"

  if command -v katana >/dev/null 2>&1; then
    katana -list "$livefile" -silent -jc -d 2 2>/dev/null | grep -i '\.js' >> "$jsfile" || true
  fi

  if command -v gau >/dev/null 2>&1; then
    echo "$domain" | gau --threads "$THREADS" 2>/dev/null | grep -i '\.js' >> "$jsfile" || true
  fi

  sort -u "$jsfile" -o "$jsfile"
  ok "JS Files: $(wc -l < "$jsfile")"
}

# ── Secret Scanner ───────────────────────────────────────────
scan_one_js() {
  local url="$1"
  local outdir="$2"
  local tmp
  tmp=$(mktemp)
  TMP_FILES+=("$tmp")

  curl -sL --max-time "$TIMEOUT" "$url" -o "$tmp" 2>/dev/null || return
  [[ ! -s "$tmp" ]] && return

  grep -oP "$SECRET_REGEX" "$tmp" 2>/dev/null | while read -r line; do
    val=$(echo "$line" | grep -oP '[0-9a-zA-Z_\-]{10,}')
    [[ -z "$val" ]] && continue
    is_false_positive "$val" && continue
    echo "$url ||| $val" >> "${outdir}/_raw_secrets.txt"
  done
}

# ── Step 4: Secret Scan ──────────────────────────────────────
step_scan_secrets() {
  local outdir="$1"
  local jsfile="$2"
  local raw="${outdir}/_raw_secrets.txt"

  [[ -f "$raw" ]] && rm -f "$raw"
  touch "$raw"

  info "Scanning JS files in parallel..."
  export -f scan_one_js is_false_positive
  export SECRET_REGEX TIMEOUT

  cat "$jsfile" | xargs -P "$THREADS" -I {} bash -c 'scan_one_js "$@"' _ {} "$outdir"

  sort -u "$raw" -o "$raw"

  ok "Secrets Found: $(wc -l < "$raw")"
}

# ── Report ────────────────────────────────────────────────────
step_report() {
  local domain="$1"
  local outdir="$2"
  local report="${outdir}/REPORT.md"

  {
    echo "# JS-HUNT REPORT"
    echo "Target: $domain"
    echo "Date: $(date)"
    echo
    echo "## Secrets"
    echo
    [[ -s "${outdir}/_raw_secrets.txt" ]] && cat "${outdir}/_raw_secrets.txt" || echo "No secrets found."
  } > "$report"

  ok "Report generated"
}

# ── Domain Pipeline ───────────────────────────────────────────
scan_domain() {
  local domain="$1"
  domain="${domain//http:\/\//}"
  domain="${domain//https:\/\//}"
  domain="${domain%%/*}"

  local outdir="${OUTPUT_BASE}/${domain}/${TIMESTAMP}"
  mkdir -p "$outdir"

  ok "Target: $domain"
  ok "Output: $outdir"

  local subfile="${outdir}/subdomains.txt"
  local livefile="${outdir}/live_hosts.txt"
  local jsfile="${outdir}/js_files.txt"

  step_subdomains "$domain" "$outdir"
  step_live_hosts "$outdir" "$subfile"
  step_collect_js "$outdir" "$livefile" "$domain"

  [[ -s "$jsfile" ]] && step_scan_secrets "$outdir" "$jsfile"
  step_report "$domain" "$outdir"
}

# ── Arguments ─────────────────────────────────────────────────
while [[ $# -gt 0 ]]; do
  case "$1" in
    -d) DOMAIN="$2"; shift 2 ;;
    -l) LIST="$2"; shift 2 ;;
    -t) THREADS="$2"; shift 2 ;;
    -r) RATE="$2"; shift 2 ;;
    *) shift ;;
  esac
done

check_deps
mkdir -p "$OUTPUT_BASE"

if [[ -n "$DOMAIN" ]]; then
  scan_domain "$DOMAIN"
elif [[ -n "$LIST" ]]; then
  while read -r d; do [[ -z "$d" ]] && continue; scan_domain "$d"; done < "$LIST"
else
  echo "Usage: $0 -d domain.com OR -l domains.txt"
fi
