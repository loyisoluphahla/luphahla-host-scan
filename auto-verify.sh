#!/usr/bin/env bash
# Luphahla Host Scan - AGGRESSIVE MODE (Unauthorized techniques)
# WARNING: This uses SYN scans, DNS zone transfers, and HTTP TRACE.
# USE ONLY ON YOUR OWN NETWORK OR WITH PERMISSION.

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
TIMEOUT=3
PARALLEL=10
BATCH_SIZE=1000
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
AGGRESSIVE_OUTPUT="${HOME}/sni_aggressive_results.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)
AGGRESSIVE_MODE=false

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --batch)         BATCH_SIZE="$2"; shift ;;
    --aggressive)    AGGRESSIVE_MODE=true ;;   # <-- NEW DANGEROUS FLAG
    --help|-h)
      echo "Luphahla Host Scan - AGGRESSIVE MODE"
      echo "  --aggressive  : SYN scans, DNS AXFR, HTTP TRACE, port 80 probing."
      echo "  --timeout 3   : Faster aggressive scans."
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
AGGRESSIVE_RAW="$TDIR/aggressive_raw.txt"
: > "$AGGRESSIVE_RAW"

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
echo -e "${BRIGHT_RED}${BOLD}   A G G R E S S I V E   M O D E   (Unauthorized)   ⚡💀${RESET}"
echo -e "${RED}   ⚠ WARNING: SYN scans, DNS AXFR, HTTP TRACE.${RESET}"
echo -e "${RED}   ⚠ DO NOT USE ON NETWORKS YOU DO NOT OWN.${RESET}"
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
#  DISCOVERY ENGINE - Aggressive Mode also uses broader ranges
# ============================================================
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Grabbing targets (Aggressive) ──${RESET}"

if [ "$ONLINE" = true ]; then
  # 1. Detect ISP ASN (same as before)
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
        # Aggressive: also expand /16 and /8 fully!
        if [ "$mask" -eq 24 ]; then
          local prefix="${base%.*}"
          for i in $(seq 1 254); do echo "${prefix}.${i}"; done
        elif [ "$mask" -eq 16 ]; then
          local prefix="${base%.*.*}"
          for i in $(seq 0 255); do for j in $(seq 1 254); do echo "${prefix}.${i}.${j}"; done; done
        elif [ "$mask" -eq 8 ]; then
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

  # Aggressive: Also grab random public IPs (WARNING: ILLEGAL ZONE!)
  echo -e "  ${BRIGHT_RED}⚠${RESET} Aggressive: Adding random public IPs (RISKY!)"
  echo "8.8.8.8" >> "$TDIR/isp_ips.txt"
  echo "1.1.1.1" >> "$TDIR/isp_ips.txt"
  # Do not add 10.x or 192.168.x (those are private, safe)

  # Aggressive: Fetch even more subdomains
  echo -e "  ${CYAN}●${RESET} Fetching ALL domains (aggressive)..."
  for domain in "co.zw" "google.com" "facebook.com" "microsoft.com" "amazon.com" "cloudflare.com" "netflix.com" "twitter.com"; do
    curl -s -m 15 "https://crt.sh/?q=%25.${domain}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' >> "$TDIR/ct_hosts.txt"
  done
  sort -u "$TDIR/ct_hosts.txt" -o "$TDIR/ct_hosts.txt"
  CT_COUNT=$(wc -l < "$TDIR/ct_hosts.txt")
  echo -e "  ${GREEN}✓${RESET} Found ${BRIGHT_WHITE}$CT_COUNT${RESET} subdomains."

else
  echo -e "  ${YELLOW}⚠ Offline. Using cache.${RESET}"
fi

# ============================================================
#  MERGE
# ============================================================
: > "$FRESH_FILE"
[ -f "$TDIR/isp_ips.txt" ] && cat "$TDIR/isp_ips.txt" >> "$FRESH_FILE"
[ -f "$TDIR/ct_hosts.txt" ] && cat "$TDIR/ct_hosts.txt" >> "$FRESH_FILE"
[ -f "$OUTPUT_FILE" ] && cat "$OUTPUT_FILE" >> "$FRESH_FILE"
if [ ! -s "$FRESH_FILE" ]; then
  echo -e "  ${YELLOW}⚠ Emergency fallback.${RESET}"
  cat > "$FRESH_FILE" << 'EOF'
google.com
youtube.com
facebook.com
EOF
fi
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
echo -e "  ${GREEN}✓${RESET} Total targets: ${BRIGHT_CYAN}$TOTAL${RESET}"
echo ""

# ============================================================
#  AGGRESSIVE INSPECTION FUNCTION
# ============================================================
aggressive_inspect() {
  local host="$1"
  local result=""

  # 1. ICMP Timestamp (often filtered)
  if command -v hping3 >/dev/null; then
    if _timeout 2 hping3 -c 1 -C 13 "$host" >/dev/null 2>&1; then
      result="ICMP_TS_ALLOWED"
    fi
  fi

  # 2. SYN Scan on common ports (using nc or nmap)
  local open_ports=""
  for port in 22 80 443 465 993 995 8080 8443; do
    if command -v nc >/dev/null; then
      if _timeout 2 nc -zv "$host" "$port" 2>/dev/null | grep -q open; then
        open_ports="${open_ports}${port},"
      fi
    elif command -v nmap >/dev/null; then
      if nmap -p "$port" --open "$host" 2>/dev/null | grep -q "/$port/"; then
        open_ports="${open_ports}${port},"
      fi
    fi
  done
  [ -n "$open_ports" ] && open_ports="${open_ports%,}"

  # 3. DNS Zone Transfer (AXFR) – classic unauthorized recon
  local axfr_result=""
  if command -v dig >/dev/null; then
    axfr_result=$(dig axfr "$host" @8.8.8.8 2>/dev/null | head -5 | tr '\n' ' ')
    if [[ "$axfr_result" == *"IN"* ]]; then
      axfr_result="AXFR_POSSIBLE (${axfr_result})"
    else
      axfr_result="AXFR_FAILED"
    fi
  fi

  # 4. HTTP TRACE / OPTIONS (fingerprinting)
  local http_trace=""
  if command -v curl >/dev/null; then
    local trace_result
    trace_result=$(curl -s -X TRACE -m "$TIMEOUT" -k "https://${host}:443" 2>/dev/null | head -1)
    if [ -n "$trace_result" ]; then
      http_trace="TRACE_ALLOWED"
    else
      http_trace="TRACE_BLOCKED"
    fi
  fi

  # 5. Port 80 HTTP (to check for hijacking)
  local http80=""
  if _timeout "$TIMEOUT" curl -s -I -k "http://${host}:80" >/dev/null 2>&1; then
    http80="HTTP_80_OPEN"
  else
    http80="HTTP_80_CLOSED"
  fi

  # Build output line
  echo "HOST|${host}|OPEN_PORTS|${open_ports}|AXFR|${axfr_result}|TRACE|${http_trace}|HTTP80|${http80}|ICMP|${result}"
}
export -f aggressive_inspect _timeout
export TIMEOUT

# ---------- Scan Batch ----------
scan_batch_aggressive() {
  local batch_file="$1"
  local tmp_raw="$TDIR/aggressive_batch.txt"
  : > "$tmp_raw"

  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$batch_file" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        aggressive_inspect "$1"
      ' _ {} > "$tmp_raw" 2>/dev/null &
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  ${BRIGHT_RED}${spin:i++%${#spin}:1}${RESET} Aggressive scanning (SYN/AXFR/TRACE)..."
      sleep 0.1
    done
    wait "$pid"
    printf "\r  ${GREEN}✓${RESET} Aggressive scan complete.                    \n"
  else
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      aggressive_inspect "$host" >> "$tmp_raw"
    done < "$batch_file"
  fi

  cat "$tmp_raw" >> "$AGGRESSIVE_RAW"
}

# ============================================================
#  BATCH ENGINE
# ============================================================
BATCH_NUM=1
START_LINE=1

if [ "$TOTAL" -le "$BATCH_SIZE" ]; then
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Aggressive scan (single batch) ──${RESET}"
  scan_batch_aggressive "$FRESH_FILE"
else
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Aggressive batching (${BATCH_SIZE} per batch) ──${RESET}"
  while [ $START_LINE -le "$TOTAL" ]; do
    END_LINE=$((START_LINE + BATCH_SIZE - 1))
    [ $END_LINE -gt "$TOTAL" ] && END_LINE="$TOTAL"
    
    BATCH_FILE="$TDIR/batch_${BATCH_NUM}.txt"
    sed -n "${START_LINE},${END_LINE}p" "$FRESH_FILE" > "$BATCH_FILE"
    BATCH_COUNT=$((END_LINE - START_LINE + 1))
    
    echo ""
    echo -e "${BRIGHT_RED}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_RED}${BOLD}  ║   AGGRESSIVE BATCH #${BATCH_NUM} (${BATCH_COUNT} hosts)   ║${RESET}"
    echo -e "${BRIGHT_RED}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
    
    scan_batch_aggressive "$BATCH_FILE"
    CURRENT=$(wc -l < "$AGGRESSIVE_RAW")
    echo -e "  ${GREEN}✓${RESET} Processed: ${BRIGHT_WHITE}$CURRENT${RESET}"

    if [ $END_LINE -ge "$TOTAL" ]; then break; fi
    
    REMAINING=$((TOTAL - END_LINE))
    echo ""
    echo -e "${BRIGHT_YELLOW}${BOLD}  ─── Next batch: ${REMAINING} hosts ───${RESET}"
    echo "  [1] Continue (dangerous)"
    echo "  [2] Stop & Save"
    echo "  [0] Exit"
    read -p "  Choose [1/2/0]: " CHOICE
    case "$CHOICE" in
      0) echo "Exiting."; exit 0 ;;
      2) echo "Saving."; break ;;
      1|*) START_LINE=$((END_LINE + 1)); BATCH_NUM=$((BATCH_NUM + 1)) ;;
    esac
  done
fi

# ============================================================
#  FINAL RESULTS
# ============================================================
sort -u "$AGGRESSIVE_RAW" -o "$AGGRESSIVE_RAW"
cp "$AGGRESSIVE_RAW" "$AGGRESSIVE_OUTPUT"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BRIGHT_RED}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ║    A G G R E S S I V E   R E S U L T S  ║${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates: ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:   ${BRIGHT_YELLOW}${DURATION}s${RESET}"
echo ""

echo -e "${BRIGHT_RED}${BOLD}  ── Hosts with Open Ports (SYN scan) ──${RESET}"
grep "OPEN_PORTS|" "$AGGRESSIVE_OUTPUT" | while IFS='|' read -r trash host trash ports trash; do
  if [ -n "$ports" ]; then
    echo -e "  ${BRIGHT_RED}🔓${RESET} ${CYAN}$host${RESET} ${DIM}→ open: $ports${RESET}"
  fi
done

echo ""
echo -e "${BRIGHT_YELLOW}${BOLD}  ── DNS Zone Transfer (AXFR) Possible ──${RESET}"
grep "AXFR_POSSIBLE" "$AGGRESSIVE_OUTPUT" | while IFS='|' read -r trash host; do
  echo -e "  ${BRIGHT_YELLOW}📂${RESET} ${CYAN}$host${RESET} ${DIM}(zone transfer leak)${RESET}"
done

echo ""
echo -e "${BRIGHT_CYAN}${BOLD}  ── HTTP TRACE Allowed ──${RESET}"
grep "TRACE_ALLOWED" "$AGGRESSIVE_OUTPUT" | while IFS='|' read -r trash host; do
  echo -e "  ${BRIGHT_CYAN}🕵️${RESET} ${CYAN}$host${RESET} ${DIM}(TRACE method enabled)${RESET}"
done

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ── HTTP Port 80 Open ──${RESET}"
grep "HTTP_80_OPEN" "$AGGRESSIVE_OUTPUT" | while IFS='|' read -r trash host; do
  echo -e "  ${BRIGHT_GREEN}🌐${RESET} ${CYAN}$host${RESET} ${DIM}(HTTP on 80)${RESET}"
done

echo ""
echo -e "  ${GREEN}✓${RESET} Full log saved to ${BRIGHT_WHITE}$AGGRESSIVE_OUTPUT${RESET}"
echo ""
echo -e "${BRIGHT_RED}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ║      AGGRESSIVE SCAN COMPLETE         ║${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ║  ⚠ THESE TECHNIQUES ARE UNATHORIZED   ║${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
exit 0