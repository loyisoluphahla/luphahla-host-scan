
#!/usr/bin/env bash
# Luphahla Host Scan - WIDE MODE (Multi-Port + SYN Scan)
# Scans ports: 80, 443, 465, 587, 993, 995, 8080, 8443, 3128, 1080
# WARNING: SYN scans are detectable. Use at your own risk.

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
PARALLEL=20
BATCH_SIZE=500
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
WIDE_OUTPUT="${HOME}/sni_wide_results.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)
WIDE_MODE=false

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --batch)         BATCH_SIZE="$2"; shift ;;
    --wide)          WIDE_MODE=true ;;   # <-- NEW FLAG (Multi-Port + SYN)
    --help|-h)
      echo "Luphahla Host Scan - WIDE MODE"
      echo "  --wide        : Scan 10 ports (80,443,465,587,993,995,8080,8443,3128,1080)"
      echo "  --timeout 3   : Faster scans."
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
WIDE_RAW="$TDIR/wide_raw.txt"
: > "$WIDE_RAW"

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
echo -e "${BRIGHT_YELLOW}${BOLD}      W I D E   M O D E   (Multi-Port + SYN Scan)   🌊${RESET}"
echo -e "${RED}   ⚠ SYN scans 10 ports. Detectable by ISP firewalls.${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Ports:${RESET} 80,443,465,587,993,995,8080,8443,3128,1080"
echo -e "  ${YELLOW}Batch:${RESET} ${BRIGHT_WHITE}$BATCH_SIZE${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
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
#  DISCOVERY ENGINE (Same as before to fetch targets)
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
#  WIDE INSPECTION FUNCTION (SYN + Multi-Port Probe)
# ============================================================
wide_inspect() {
  local host="$1"
  local ports="80 443 465 587 993 995 8080 8443 3128 1080"
  local found=""

  for port in $ports; do
    # 1. SYN Scan using nc (-zv)
    if command -v nc >/dev/null; then
      if _timeout 2 nc -zv "$host" "$port" 2>/dev/null | grep -q open; then
        found="${found}${port},"
        
        # 2. If it's a TLS port, do a handshake
        if [[ "$port" =~ ^(443|465|587|993|995|8443)$ ]]; then
          local server_header=""
          local tls_result=""
          if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
            tls_result=$(echo | _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof 2>/dev/null | grep -i "^Server:" | head -1)
          else
            tls_result=$(echo | _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof 2>/dev/null | grep -i "^Server:" | head -1)
          fi
          
          if [[ "$tls_result" =~ (gws|google) ]]; then
            server_header="Google (FREE)"
          elif [[ "$tls_result" =~ (cloudflare) ]]; then
            server_header="Cloudflare (FREE)"
          elif [[ "$tls_result" =~ (facebook|meta) ]]; then
            server_header="Meta (FREE)"
          else
            server_header="TLS/Unknown"
          fi
          echo "PORT|${host}|${port}|TLS|${server_header}"
        fi

        # 3. If it's an HTTP port (80, 8080), try curl HEAD
        if [[ "$port" =~ ^(80|8080)$ ]]; then
          if command -v curl >/dev/null; then
            local http_header
            http_header=$(curl -s -I -m "$TIMEOUT" "http://${host}:${port}" 2>/dev/null | grep -i "^Server:" | head -1)
            if [ -n "$http_header" ]; then
              echo "PORT|${host}|${port}|HTTP|${http_header}"
            else
              echo "PORT|${host}|${port}|HTTP_OPEN|NoServer"
            fi
          fi
        fi

        # 4. Proxy ports (3128, 1080) - just note they're open
        if [[ "$port" =~ ^(3128|1080)$ ]]; then
          echo "PORT|${host}|${port}|PROXY_OPEN|"
        fi
      fi
    fi
  done
}
export -f wide_inspect _timeout
export TIMEOUT

# ---------- Scan Batch ----------
scan_batch_wide() {
  local batch_file="$1"
  local tmp_raw="$TDIR/wide_batch.txt"
  : > "$tmp_raw"

  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$batch_file" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        wide_inspect "$1"
      ' _ {} > "$tmp_raw" 2>/dev/null &
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  ${BRIGHT_YELLOW}${spin:i++%${#spin}:1}${RESET} Wide scanning (10 ports)..."
      sleep 0.1
    done
    wait "$pid"
    printf "\r  ${GREEN}✓${RESET} Wide scan complete.                    \n"
  else
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      wide_inspect "$host" >> "$tmp_raw"
    done < "$batch_file"
  fi

  cat "$tmp_raw" >> "$WIDE_RAW"
}

# ============================================================
#  BATCH ENGINE
# ============================================================
BATCH_NUM=1
START_LINE=1

if [ "$TOTAL" -le "$BATCH_SIZE" ]; then
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Wide scan (single batch) ──${RESET}"
  scan_batch_wide "$FRESH_FILE"
else
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Wide batching (${BATCH_SIZE} per batch) ──${RESET}"
  while [ $START_LINE -le "$TOTAL" ]; do
    END_LINE=$((START_LINE + BATCH_SIZE - 1))
    [ $END_LINE -gt "$TOTAL" ] && END_LINE="$TOTAL"
    
    BATCH_FILE="$TDIR/batch_${BATCH_NUM}.txt"
    sed -n "${START_LINE},${END_LINE}p" "$FRESH_FILE" > "$BATCH_FILE"
    BATCH_COUNT=$((END_LINE - START_LINE + 1))
    
    echo ""
    echo -e "${BRIGHT_YELLOW}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_YELLOW}${BOLD}  ║     WIDE BATCH #${BATCH_NUM} (${BATCH_COUNT} hosts)     ║${RESET}"
    echo -e "${BRIGHT_YELLOW}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
    
    scan_batch_wide "$BATCH_FILE"
    CURRENT=$(wc -l < "$WIDE_RAW")
    echo -e "  ${GREEN}✓${RESET} Processed: ${BRIGHT_WHITE}$CURRENT${RESET}"

    if [ $END_LINE -ge "$TOTAL" ]; then break; fi
    
    REMAINING=$((TOTAL - END_LINE))
    echo ""
    echo -e "${BRIGHT_YELLOW}${BOLD}  ─── Next batch: ${REMAINING} hosts ───${RESET}"
    echo "  [1] Continue"
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
sort -u "$WIDE_RAW" -o "$WIDE_RAW"
cp "$WIDE_RAW" "$WIDE_OUTPUT"

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║       W I D E   R E S U L T S         ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates: ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:   ${BRIGHT_YELLOW}${DURATION}s${RESET}"
echo ""

# ---------- Display Wide Results ----------
echo -e "${BRIGHT_GREEN}${BOLD}  ── FREE / ZERO-RATED (TLS/HTTP) ──${RESET}"
grep "FREE" "$WIDE_OUTPUT" | while IFS='|' read -r trash host port proto header; do
  echo -e "  ${BRIGHT_GREEN}✅${RESET} ${CYAN}$host${RESET}:${BRIGHT_WHITE}$port${RESET} ${DIM}$header${RESET}"
done

echo ""
echo -e "${BRIGHT_YELLOW}${BOLD}  ── OPEN PORTS (SYN Found) ──${RESET}"
grep "PORT|" "$WIDE_OUTPUT" | grep -v "FREE" | while IFS='|' read -r trash host port proto header; do
  echo -e "  ${BRIGHT_YELLOW}🔓${RESET} ${CYAN}$host${RESET}:${BRIGHT_WHITE}$port${RESET} ${DIM}$proto${RESET}"
done

echo ""
echo -e "${BRIGHT_RED}${BOLD}  ── PROXY PORTS (3128,1080) ──${RESET}"
grep "PROXY_OPEN" "$WIDE_OUTPUT" | while IFS='|' read -r trash host port; do
  echo -e "  ${BRIGHT_RED}🔀${RESET} ${CYAN}$host${RESET}:${BRIGHT_WHITE}$port${RESET} ${DIM}(Proxy)${RESET}"
done

echo ""
echo -e "  ${GREEN}✓${RESET} Full log saved to ${BRIGHT_WHITE}$WIDE_OUTPUT${RESET}"
echo ""
echo -e "${BRIGHT_RED}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ║   WIDE SCAN COMPLETE (10 ports)      ║${RESET}"
echo -e "${BRIGHT_RED}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
exit 0
