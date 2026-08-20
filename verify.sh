#!/usr/bin/env bash
# Luphahla Host Scan - Method Scanner
# Finds live hosts AND tells you which HTTP methods they support.
# Usage: cat hosts.txt | ./verify.sh --method-scan

set -o pipefail

# ---------- Portable timeout ----------
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
PARALLEL=20
OUTPUT_FILE=""
METHOD_SCAN=false
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
LIVE_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-live.XXXXXX")
METHODS_FILE="${HOME}/sni_methods_results.txt"

# ---------- List of HTTP methods from HA Tunnel Plus ----------
ALL_METHODS=(
  "HEAD" "GET" "POST" "OPTIONS" "TRACE" "DELETE" "CONNECT"
  "PUT" "MOVE" "PATCH" "PROPFIND" "PROPPATCH"
  "ACL" "BASELINE-CONTROL" "BDELETE" "BIND" "BMOVE" "BPROPFIND"
  "CHECKIN" "CHECKOUT" "LABEL" "LINK" "LOCK" "MERGE"
  "MKACTIVITY" "MKCALENDAR" "MKCOL" "MKREDIRECTREF" "MKWORKSPACE"
  "NOTIFY" "ORDERPATCH" "POLL" "PRI" "REBIND" "SEARCH"
  "SUBSCRIBE" "UNBIND" "UNCHECKOUT" "UNLINK" "UNLOCK"
  "UNSUBSCRIBE" "UPDATE" "UPDATEREDIRECTREF" "VERSION-CONTROL"
)

trap 'rm -f "$INPUT_FILE" "$LIVE_FILE"' EXIT INT TERM

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --method-scan)   METHOD_SCAN=true ;;
    -o)              OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      echo "Luphahla Method Scanner"
      echo "  --method-scan  : Probe hosts with ALL HTTP methods (HA Tunnel compatible)."
      echo "  --timeout 3    : Faster scans."
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; WHITE=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; WHITE='\033[37m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'
fi

# ---------- Read stdin ----------
cat > "$INPUT_FILE"
TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | wc -l)
if [ "$TOTAL" -eq 0 ]; then
  echo -e "${RED}No valid hosts.${RESET}" >&2
  exit 3
fi

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
echo -e "${BRIGHT_BLUE}${BOLD}       M E T H O D   S C A N N E R   🔍${RESET}"
echo -e "${CYAN}        Luphahla - Find which HTTP methods work${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Candidates:${RESET} ${BRIGHT_WHITE}$TOTAL${RESET}  ${YELLOW}Methods:${RESET} ${BRIGHT_WHITE}${#ALL_METHODS[@]}${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo ""

# ---------- TLS check ----------
check_tls() {
  local host="$1"
  local port="$2"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  fi
}
export -f check_tls _timeout
export TIMEOUT

# ---------- Probe Methods ----------
probe_methods() {
  local host="$1"
  local port="$2"
  local allowed=()
  local status

  for method in "${ALL_METHODS[@]}"; do
    # For SSL ports
    if [[ "$port" =~ ^(443|8443|465|993|995)$ ]]; then
      status=$(curl -s -k -o /dev/null -w "%{http_code}" -X "$method" "https://${host}:${port}" 2>/dev/null)
    else
      status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "http://${host}:${port}" 2>/dev/null)
    fi
    
    # 200, 301, 302, 401, 405 means the server understands the method
    if [[ "$status" =~ ^(200|301|302|401|405)$ ]]; then
      allowed+=("$method")
    fi
  done

  # If only HEAD, GET, POST work, but PROPFIND doesn't, we still report it.
  if [ ${#allowed[@]} -gt 0 ]; then
    echo "${host}|${port}|${allowed[*]}"
  fi
}
export -f probe_methods _timeout
export -f ALL_METHODS

# ---------- Main Scan ----------
echo -e "${BLUE}${BOLD}[*] Scanning live hosts and methods...${RESET}"
: > "$LIVE_FILE"
COUNT=0

if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
  grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | while read -r host; do
    COUNT=$((COUNT + 1))
    printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$COUNT"
    
    # First check TLS (live host)
    if check_tls "$host" 443; then
      echo "$host" >> "$LIVE_FILE"
      
      # If --method-scan, probe methods
      if [ "$METHOD_SCAN" = true ]; then
        probe_methods "$host" "443" >> "$METHODS_FILE"
      fi
    fi
  done
else
  while IFS= read -r host; do
    [[ "$host" =~ ^[[:space:]]*# ]] && continue
    [ -z "$host" ] && continue
    COUNT=$((COUNT + 1))
    printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$COUNT"
    
    if check_tls "$host" 443; then
      echo "$host" >> "$LIVE_FILE"
      if [ "$METHOD_SCAN" = true ]; then
        probe_methods "$host" "443" >> "$METHODS_FILE"
      fi
    fi
  done < "$INPUT_FILE"
fi

echo "" # newline

# ---------- Results ----------
sort -u "$LIVE_FILE" -o "$LIVE_FILE"
LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║         S C A N   R E S U L T S       ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Live Hosts: ${BRIGHT_GREEN}$LIVECOUNT${RESET}"

if [ "$METHOD_SCAN" = true ] && [ -s "$METHODS_FILE" ]; then
  echo ""
  echo -e "${BRIGHT_CYAN}${BOLD}  ── Method Scan Results (Top 10) ──${RESET}"
  head -10 "$METHODS_FILE" | while IFS='|' read -r host port methods; do
    # Show first 5 methods only for brevity
    first_methods=$(echo "$methods" | cut -d' ' -f1-5)
    echo -e "  ${GREEN}✓${RESET} ${CYAN}$host${RESET}:${BRIGHT_WHITE}$port${RESET} → ${DIM}$first_methods${RESET}"
  done
  [ $(wc -l < "$METHODS_FILE") -gt 10 ] && echo -e "  ${DIM}... and more in $METHODS_FILE${RESET}"
  
  echo ""
  echo -e "  ${GREEN}✓${RESET} Full method list saved to: ${BRIGHT_WHITE}$METHODS_FILE${RESET}"
  echo -e "  ${YELLOW}💡${RESET} Open this file to see exactly which HTTP methods work on each host."
  echo -e "  ${YELLOW}💡${RESET} Then select that method in HA Tunnel Plus -> METHOD dropdown."
else
  echo -e "  ${YELLOW}No method data. Run with --method-scan to probe HTTP verbs.${RESET}"
fi

if [ "$LIVECOUNT" -gt 0 ] && [ -n "$OUTPUT_FILE" ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  echo -e "  ${GREEN}✓${RESET} Saved hosts to $OUTPUT_FILE"
fi

echo ""
exit 0