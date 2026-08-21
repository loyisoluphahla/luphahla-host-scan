#!/usr/bin/env bash
# Luphahla Host Scan - 4 METHODS ONLY (GET, HEAD, CONNECT, POST)
# Safe for Termux - no OOM Killer.

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
TIMEOUT=4
PARALLEL=1                     # SEQUENTIAL - SAFEST
METHOD_SCAN=true               # Enabled, but only 4 methods
OUTPUT_FILE=""
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
RESULTS_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-results.XXXXXX")
trap 'rm -f "$INPUT_FILE" "$RESULTS_FILE"' EXIT INT TERM

# ---------- ONLY 4 METHODS ----------
METHODS=("GET" "HEAD" "CONNECT" "POST")

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --no-method)     METHOD_SCAN=false ;;
    -o)              OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      echo "Luphahla 4-Method Scanner (Safe for Termux)"
      echo "  Methods: GET, HEAD, CONNECT, POST"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
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

# ---------- Read stdin (clean input) ----------
# Remove blank lines and comments
grep -vE '^[[:space:]]*(#|$)' > "$INPUT_FILE"
TOTAL=$(wc -l < "$INPUT_FILE")
if [ "$TOTAL" -eq 0 ]; then
  echo -e "${RED}No hosts provided.${RESET}" >&2
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
echo -e "${BRIGHT_BLUE}${BOLD}       4 - M E T H O D   S C A N N E R   📱${RESET}"
echo -e "${CYAN}       GET • HEAD • CONNECT • POST${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Hosts:${RESET} ${BRIGHT_WHITE}$TOTAL${RESET}  ${YELLOW}Methods:${RESET} ${BRIGHT_WHITE}4${RESET}  ${YELLOW}Parallel:${RESET} ${BRIGHT_WHITE}$PARALLEL${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
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

# ---------- Probe only 4 methods ----------
probe_methods() {
  local host="$1"
  local port="$2"
  local allowed=()
  local status

  for method in "GET" "HEAD" "CONNECT" "POST"; do
    if [[ "$port" =~ ^(443|8443)$ ]]; then
      status=$(curl -s -k -o /dev/null -w "%{http_code}" -X "$method" "https://${host}:${port}" 2>/dev/null)
    else
      status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "http://${host}:${port}" 2>/dev/null)
    fi
    # 200, 301, 302, 401, 405 means the server accepts the method
    if [[ "$status" =~ ^(200|301|302|401|405)$ ]]; then
      allowed+=("$method")
    fi
  done

  # Return space-separated list
  echo "${allowed[*]}"
}
export -f probe_methods

# ---------- Scan ----------
echo -e "${BLUE}${BOLD}[*] Scanning (sequential, 4 methods)...${RESET}"
COUNT=0
: > "$RESULTS_FILE"

while IFS= read -r host; do
  [[ "$host" =~ ^[[:space:]]*# ]] && continue
  [ -z "$host" ] && continue
  COUNT=$((COUNT + 1))
  printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$COUNT"

  if check_tls "$host" 443; then
    # Server header
    server=$(curl -s -I -m "$TIMEOUT" -k "https://${host}:443" 2>/dev/null | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 25)
    [ -z "$server" ] && server="Unknown"

    # Speed test
    speed_bytes=$(curl -s -o /dev/null -w "%{speed_download}" -m "$TIMEOUT" -k "https://${host}:443" 2>/dev/null)
    speed_label="N/A"
    if [[ "$speed_bytes" =~ ^[0-9]+ ]] && [ "$speed_bytes" -gt 0 ]; then
      speed_kb=$(echo "$speed_bytes / 1024" | bc 2>/dev/null)
      if [ -n "$speed_kb" ]; then
        if [ "$speed_kb" -gt 100 ]; then speed_label="⚡ ${speed_kb} KB/s"; else speed_label="🐢 ${speed_kb} KB/s"; fi
      fi
    fi

    # Methods
    methods_string=""
    best_method=""
    if [ "$METHOD_SCAN" = true ]; then
      methods_string=$(probe_methods "$host" "443")
      # Pick the best: CONNECT > POST > HEAD > GET (CONNECT is rarest and often unthrottled)
      if echo "$methods_string" | grep -q "\bCONNECT\b"; then
        best_method="CONNECT"
      elif echo "$methods_string" | grep -q "\bPOST\b"; then
        best_method="POST"
      elif echo "$methods_string" | grep -q "\bHEAD\b"; then
        best_method="HEAD"
      elif echo "$methods_string" | grep -q "\bGET\b"; then
        best_method="GET"
      else
        best_method="None"
      fi
    fi

    echo "${host}|443|✓|${server}|${methods_string}|${speed_label}|${best_method}" >> "$RESULTS_FILE"
  fi
done < "$INPUT_FILE"

echo "" # newline

# ============================================================
#  DISPLAY TABLE
# ============================================================
LIVECOUNT=$(wc -l < "$RESULTS_FILE")
if [ "$LIVECOUNT" -eq 0 ]; then
  echo -e "${YELLOW}No live hosts found.${RESET}"
  exit 0
fi

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║                             L I V E   H O S T S   T A B L E                                          ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

printf "  ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-20s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-10s${RESET} | ${BRIGHT_CYAN}%-15s${RESET} | ${BRIGHT_CYAN}%-8s${RESET} | ${BRIGHT_CYAN}%-12s${RESET}\n" " # " "Host" "Port" "TLS" "Server" "Methods" "Speed" "Best"
printf "  %3s | %-20s | %4s | %3s | %-10s | %-15s | %-8s | %-12s\n" "---" "--------------------" "----" "---" "----------" "---------------" "--------" "------------"

LINE_NUM=1
while IFS='|' read -r host port tls server methods speed best; do
  host=$(echo "$host" | xargs)
  server=$(echo "$server" | xargs | cut -c1-10)
  speed=$(echo "$speed" | xargs)
  methods=$(echo "$methods" | xargs)
  best=$(echo "$best" | xargs)

  if [ "$best" != "None" ] && [ -n "$best" ]; then
    best_colored="${BRIGHT_GREEN}${BOLD}${best}${RESET}"
  else
    best_colored="${DIM}None${RESET}"
  fi

  printf "  ${YELLOW}%3d${RESET} | ${CYAN}%-20s${RESET} | ${BRIGHT_WHITE}%4s${RESET} | ${GREEN}%3s${RESET} | ${WHITE}%-10s${RESET} | ${DIM}%-15s${RESET} | ${BRIGHT_YELLOW}%-8s${RESET} | %-12s\n" "$LINE_NUM" "$host" "$port" "$tls" "$server" "$methods" "$speed" "$best_colored"
  LINE_NUM=$((LINE_NUM + 1))
done < "$RESULTS_FILE"

echo ""
echo -e "  ${GREEN}✓${RESET} Total live hosts: ${BRIGHT_WHITE}$LIVECOUNT${RESET}"

if [ -n "$OUTPUT_FILE" ]; then
  cp "$RESULTS_FILE" "$OUTPUT_FILE"
  echo -e "  ${GREEN}✓${RESET} Saved to: ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
fi

echo ""
exit 0
