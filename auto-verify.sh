#!/usr/bin/env bash
# Luphahla Host Scan - Unified Scanner (Liveness + Zero-Rating simultaneously)
# Checks TLS, HTTP headers, and speed in one pass.
# Usage: ./auto-verify.sh

set -o pipefail

# ---------- Portable wrappers ----------
if command -v timeout >/dev/null 2>&1; then
  _timeout() { timeout "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
  _timeout() { gtimeout "$@"; }
else
  _timeout() {
    local secs="$1"; shift
    ( "$@" ) &
    local pid=$!
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) &
    wait "$pid" 2>/dev/null
    return $?
  }
fi

# ---------- Defaults ----------
USE_COLOR=true
TIMEOUT=5
PARALLEL=30
BATCH_SIZE=5000
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
SCORED_FILE="${HOME}/sni_hosts_scored.txt"   # New: saves scores!
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --batch)         BATCH_SIZE="$2"; shift ;;
    --help|-h)
      echo "Luphahla Unified Scanner"
      echo "  Scans for live hosts AND zero-rating in the same pass."
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; WHITE=''; MAGENTA=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''; BRIGHT_MAGENTA=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; WHITE='\033[37m'; MAGENTA='\033[35m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'; BRIGHT_MAGENTA='\033[95m'
fi

# ---------- Setup temp dirs ----------
mkdir -p "$TDIR" || { echo -e "${RED}Error: Could not create $TDIR${RESET}" >&2; exit 1; }
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
LIVE_FILE="$TDIR/live.txt"
SCORED_RAW="$TDIR/scored_raw.txt"
: > "$LIVE_FILE"
: > "$SCORED_RAW"

# ---------- Banner ----------
[ -t 1 ] && clear
echo -e "${BRIGHT_RED}${BOLD}"
echo "  ██╗     ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗  "
echo "  ██║     ██║   ██║██╔══██╗██║  ██║██╔══██╗██║  ██║██║     ██╔══██╗ "
echo "  ██║     ██║   ██║██████╔╝███████║███████║███████║██║     ███████║ "
echo "  ██║     ██║   ██║██╔═══╝ ██╔══██║██╔══██║██╔══██║██║     ██╔══██║ "
echo "  ███████╗╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║███████╗██║  ██║ "
echo "  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ "
echo -e "${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}   U N I F I E D   L I V E   +   Z E R O   S C A N   🔄🚀${RESET}"
echo -e "${CYAN}          Luphahla Host Scan - Batch + Zero-Rated${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Batch Size:${RESET} ${BRIGHT_WHITE}$BATCH_SIZE${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}  ${YELLOW}Parallel:${RESET} ${BRIGHT_WHITE}$PARALLEL${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo ""

# ---------- Network Check ----------
ONLINE=false
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  ONLINE=true
  echo -e "  ${GREEN}✓ Network: ONLINE${RESET}"
else
  echo -e "  ${RED}✗ Network: OFFLINE${RESET}"
fi

# ============================================================
#  DISCOVERY ENGINE (Grabs ALL IPs & Domains)
# ============================================================
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Grabbing targets ──${RESET}"

if [ "$ONLINE" = true ]; then
  echo -e "  ${CYAN}●${RESET} Detecting your ISP..."
  CURRENT_ASN=$(curl -s -m 5 "https://ipinfo.io/org" | grep -oE 'AS[0-9]+' | head -1)
  if [ -z "$CURRENT_ASN" ]; then
    CURRENT_ASN=$(curl -s -m 5 "https://api.hackertarget.com/aslookup/8.8.8.8" | grep -oE 'AS[0-9]+' | head -1)
  fi

  if [ -n "$CURRENT_ASN" ]; then
    echo -e "  ${GREEN}✓${RESET} Detected ASN: ${BRIGHT_WHITE}$CURRENT_ASN${RESET}"
    echo -e "  ${CYAN}●${RESET} Fetching ALL IP ranges..."
    RANGES=$(curl -s -m 15 "https://ipinfo.io/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+')
    if [ -z "$RANGES" ]; then
      RANGES=$(curl -s -m 15 "https://api.hackertarget.com/aslookup/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+')
    fi
    if [ -n "$RANGES" ]; then
      echo "$RANGES" | while read -r cidr; do
        local mask="${cidr#*/}"; local base="${cidr%/*}"
        if [ "$mask" -eq 24 ]; then
          local prefix="${base%.*}"
          for i in $(seq 1 254); do echo "${prefix}.${i}"; done
        elif [ "$mask" -eq 16 ]; then
          local prefix="${base%.*.*}"
          for i in $(seq 0 255); do for j in $(seq 1 254); do echo "${prefix}.${i}.${j}"; done; done
        elif [ "$mask" -eq 8 ]; then
          echo -e "  ${BRIGHT_YELLOW}⚠ /8 range (16M IPs) - will be huge!${RESET}"
          local prefix="${base%.*.*.*}"
          for i in $(seq 0 255); do for j in $(seq 0 255); do for k in $(seq 1 254); do echo "${prefix}.${i}.${j}.${k}"; done; done; done
        else
          local prefix="${base%.*}"; for i in $(seq 1 254); do echo "${prefix}.${i}"; done
        fi
      done > "$TDIR/isp_ips.txt"
      COUNT=$(wc -l < "$TDIR/isp_ips.txt")
      echo -e "  ${GREEN}✓${RESET} Generated ${BRIGHT_WHITE}$COUNT${RESET} IPs."
    fi
  fi

  echo -e "  ${CYAN}●${RESET} Fetching domains from SSL logs..."
  for domain in "co.zw" "google.com" "facebook.com" "microsoft.com" "amazon.com"; do
    curl -s -m 15 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' >> "$TDIR/ct_hosts.txt"
  done
  sort -u "$TDIR/ct_hosts.txt" -o "$TDIR/ct_hosts.txt"
  CT_COUNT=$(wc -l < "$TDIR/ct_hosts.txt")
  echo -e "  ${GREEN}✓${RESET} Found ${BRIGHT_WHITE}$CT_COUNT${RESET} subdomains."
else
  echo -e "  ${YELLOW}⚠ Offline mode. Using cache.${RESET}"
fi

# ============================================================
#  MERGE ALL SOURCES
# ============================================================
: > "$FRESH_FILE"
[ -f "$TDIR/isp_ips.txt" ] && cat "$TDIR/isp_ips.txt" >> "$FRESH_FILE"
[ -f "$TDIR/ct_hosts.txt" ] && cat "$TDIR/ct_hosts.txt" >> "$FRESH_FILE"
[ -f "$OUTPUT_FILE" ] && cat "$OUTPUT_FILE" >> "$FRESH_FILE"
[ -f "$CACHE_FILE" ] && cat "$CACHE_FILE" >> "$FRESH_FILE"
if [ ! -s "$FRESH_FILE" ]; then
  echo -e "  ${YELLOW}⚠ Emergency fallback.${RESET}"
  cat > "$FRESH_FILE" << 'EOF'
google.com
youtube.com
facebook.com
whatsapp.com
instagram.com
microsoft.com
amazon.com
EOF
fi
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
echo -e "  ${GREEN}✓${RESET} Total targets: ${BRIGHT_CYAN}$TOTAL${RESET}"
echo ""

# ============================================================
#  UNIFIED INSPECTION FUNCTION (TLS + HTTP + Speed)
# ============================================================
inspect_host() {
  local host="$1"
  local port="$2"
  local score=0
  local speed="N/A"
  local zero_label="Unknown"
  local server_header=""

  # 1. TLS Handshake (Liveness)
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1 || return 1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1 || return 1
  fi
  score=$((score + 30))

  # 2. HTTP Headers (Zero-Rating Detection)
  if command -v curl >/dev/null; then
    local headers
    headers=$(curl -s -I -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    server_header=$(echo "$headers" | grep -i "^Server:" | head -1)
    
    if echo "$server_header" | grep -qi "gws\|google\|youtube"; then
      zero_label="Google (Free)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "facebook\|meta\|whatsapp\|instagram"; then
      zero_label="Meta (Free)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "cloudflare"; then
      zero_label="Cloudflare (Often Free)"
      score=$((score + 35))
    elif echo "$server_header" | grep -qi "microsoft\|iis"; then
      zero_label="Microsoft (Sometimes Free)"
      score=$((score + 25))
    elif echo "$server_header" | grep -qi "amazon\|aws\|cloudfront"; then
      zero_label="Amazon (Often Free)"
      score=$((score + 25))
    else
      zero_label="Unknown"
      score=$((score + 5))
    fi

    # 3. Speed Test
    local speed_result
    speed_result=$(curl -s -o /dev/null -w "%{speed_download}" -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    if [[ "$speed_result" =~ ^[0-9]+ ]] && [ "$speed_result" -gt 0 ]; then
      speed_kb=$(echo "$speed_result / 1024" | bc 2>/dev/null)
      if [ -n "$speed_kb" ]; then
        if [ "$speed_kb" -gt 100 ]; then
          score=$((score + 25)); speed="⚡ ${speed_kb} KB/s"
        elif [ "$speed_kb" -gt 10 ]; then
          score=$((score + 10)); speed="🐢 ${speed_kb} KB/s"
        else
          speed="⛔ ${speed_kb} KB/s"
        fi
      fi
    else
      speed="⛔ No Data"
    fi
  else
    score=$((score - 10))
    speed="Install curl for full detection"
  fi

  # Output: SCORE|HOST|ZERO_LABEL|SPEED
  echo "${score}|${host}|${zero_label}|${speed}"
}
export -f inspect_host _timeout
export TIMEOUT

# ---------- Scan a single batch (unified) ----------
scan_batch() {
  local batch_file="$1"
  local port="$2"
  local tmp_scored="$TDIR/scored_${port}_$$.txt"
  : > "$tmp_scored"

  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$batch_file" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        inspect_host "$1" '"$port"'
      ' _ {} >> "$tmp_scored" 2>/dev/null &
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Unified scan (live+zero) port $port..."
      sleep 0.1
    done
    wait "$pid"
    printf "\r  ${GREEN}✓${RESET} Port $port unified scan complete.                    \n"
  else
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      inspect_host "$host" "$port" >> "$tmp_scored"
    done < "$batch_file"
  fi

  # Merge scored results into the global scored file
  cat "$tmp_scored" >> "$SCORED_RAW"
}

# ============================================================
#  INTERACTIVE BATCH PROCESSING ENGINE
# ============================================================
BATCH_NUM=1
START_LINE=1

if [ "$TOTAL" -le "$BATCH_SIZE" ]; then
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Unified scan (single batch) ──${RESET}"
  scan_batch "$FRESH_FILE" "443"
  # Optional: also check 8080? 443 is usually enough for zero-rating, skip 8080 to save time.
else
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Interactive Batching (${BATCH_SIZE} per batch) ──${RESET}"
  
  while [ $START_LINE -le "$TOTAL" ]; do
    END_LINE=$((START_LINE + BATCH_SIZE - 1))
    [ $END_LINE -gt "$TOTAL" ] && END_LINE="$TOTAL"
    
    BATCH_FILE="$TDIR/batch_${BATCH_NUM}.txt"
    sed -n "${START_LINE},${END_LINE}p" "$FRESH_FILE" > "$BATCH_FILE"
    BATCH_COUNT=$((END_LINE - START_LINE + 1))
    
    echo ""
    echo -e "${BRIGHT_CYAN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ║         BATCH #${BATCH_NUM} (${BATCH_COUNT} hosts)           ║${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
    
    scan_batch "$BATCH_FILE" "443"
    
    # Count current live (scored) hosts
    CURRENT_LIVE=$(grep -cve '^[[:space:]]*$' "$SCORED_RAW" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}✓${RESET} Live+Scored hosts so far: ${BRIGHT_WHITE}$CURRENT_LIVE${RESET}"
    
    # Show top 5 scored results from this batch
    if [ -f "$SCORED_RAW" ] && [ "$CURRENT_LIVE" -gt 0 ]; then
      echo -e "  ${BRIGHT_CYAN}Top scored from this batch:${RESET}"
      tail -n "$BATCH_COUNT" "$SCORED_RAW" 2>/dev/null | sort -t'|' -k1 -nr | head -5 | while IFS='|' read -r score host zero speed; do
        if [ "$score" -gt 70 ]; then label="${BRIGHT_GREEN}[HIGH]${RESET}"; elif [ "$score" -gt 40 ]; then label="${BRIGHT_YELLOW}[MEDIUM]${RESET}"; else label="${BRIGHT_RED}[LOW]${RESET}"; fi
        printf "    %-8s ${CYAN}%-25s${RESET} ${DIM}%-20s %s${RESET}\n" "$label" "$host" "$zero" "$speed"
      done
    fi

    if [ $END_LINE -ge "$TOTAL" ]; then
      echo -e "  ${GREEN}✓ All batches processed!${RESET}"
      break
    fi
    
    REMAINING=$((TOTAL - END_LINE))
    echo ""
    echo -e "${BRIGHT_YELLOW}${BOLD}  ─── Next batch: ${REMAINING} hosts remaining ───${RESET}"
    echo "  [1] Continue to next batch"
    echo "  [2] Stop and Save results (Exit gracefully)"
    echo "  [0] Exit immediately (kill script)"
    echo ""
    read -p "  Choose [1/2/0]: " CHOICE
    
    case "$CHOICE" in
      0) echo -e "  ${RED}Exiting. Results NOT saved.${RESET}"; exit 0 ;;
      2) echo -e "  ${GREEN}Stopping. Saving results.${RESET}"; break ;;
      1|*) echo -e "  ${CYAN}Continuing...${RESET}"; START_LINE=$((END_LINE + 1)); BATCH_NUM=$((BATCH_NUM + 1)) ;;
    esac
  done
fi

# ============================================================
#  FINALIZE, SORT, AND SAVE RESULTS
# ============================================================
# Extract live hosts (for compatibility) - only those with a score > 30 (actual TLS success)
sort -u "$SCORED_RAW" -o "$SCORED_RAW"
grep -vE '^[[:space:]]*$' "$SCORED_RAW" > "$SCORED_RAW.tmp"
mv "$SCORED_RAW.tmp" "$SCORED_RAW"

LIVECOUNT=$(wc -l < "$SCORED_RAW")

# Generate plain host list from scored data
cut -d'|' -f2 "$SCORED_RAW" > "$LIVE_FILE"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║    F I N A L   R E S U L T S          ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Total Candidates: ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Live + Scored:     ${BRIGHT_GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:          ${BRIGHT_YELLOW}${DURATION}s${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  cp "$LIVE_FILE" "$CACHE_FILE"
  cp "$SCORED_RAW" "$SCORED_FILE"
  
  echo -e "  ${GREEN}✓${RESET} Plain list saved to ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
  echo -e "  ${GREEN}✓${RESET} Scored list saved to ${BRIGHT_WHITE}$SCORED_FILE${RESET}"
  
  echo ""
  echo -e "${BRIGHT_CYAN}${BOLD}  ── Scored Hosts (Highest First) ──${RESET}"
  sort -t'|' -k1 -nr "$SCORED_RAW" | while IFS='|' read -r score host zero speed; do
    if [ "$score" -gt 70 ]; then label="${BRIGHT_GREEN}[HIGH]${RESET}"; elif [ "$score" -gt 40 ]; then label="${BRIGHT_YELLOW}[MEDIUM]${RESET}"; else label="${BRIGHT_RED}[LOW]${RESET}"; fi
    printf "  %-8s ${CYAN}%-30s${RESET} ${DIM}%-20s %s${RESET}\n" "$label" "$host" "$zero" "$speed"
  done
else
  echo -e "  ${YELLOW}No live hosts found.${RESET}"
fi

echo ""
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ║   UNIFIED SCAN COMPLETE (${BATCH_NUM} batches)   ║${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
exit 0
