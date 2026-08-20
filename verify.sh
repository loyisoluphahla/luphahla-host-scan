#!/usr/bin/env bash
# Luphahla Host Scan - TERMUX OPTIMIZED (No Signal 9)
# Uses low parallelism and only 10 HTTP methods to prevent OOM kills.

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

# ---------- Defaults (LOW for Termux) ----------
USE_COLOR=true
TIMEOUT=4               # Lower timeout
PARALLEL=3              # ONLY 3 parallel jobs (Safe for Android)
METHOD_SCAN=true        # Keep method scan, but only use 10 methods
OUTPUT_FILE=""
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
RESULTS_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-results.XXXXXX")
trap 'rm -f "$INPUT_FILE" "$RESULTS_FILE"' EXIT INT TERM

# ---------- ONLY 10 USEFUL METHODS (Saves memory) ----------
USEFUL_METHODS=(
  "HEAD" "GET" "POST" "OPTIONS" "TRACE"
  "PROPFIND" "LOCK" "UNLOCK" "MKCOL" "MOVE"
)

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --no-method)     METHOD_SCAN=false ;;
    -o)              OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      echo "Luphahla Termux Scanner (Safe Mode)"
      echo "  --parallel 3   : Run safely on Android"
      echo "  --timeout 4    : Fast timeouts"
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
echo -e "${BRIGHT_BLUE}${BOLD}      T E R M U X   S A F E   S C A N N E R   📱${RESET}"
echo -e "${CYAN}       Optimized to prevent Signal 9 (OOM Killer)${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Hosts:${RESET} ${BRIGHT_WHITE}$TOTAL${RESET}  ${YELLOW}Parallel:${RESET} ${BRIGHT_WHITE}$PARALLEL${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
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

# ---------- Probe only 10 methods ----------
probe_methods() {
  local host="$1"
  local port="$2"
  local allowed=()
  local status
  for method in "${USEFUL_METHODS[@]}"; do
    if [[ "$port" =~ ^(443|8443)$ ]]; then
      status=$(curl -s -k -o /dev/null -w "%{http_code}" -X "$method" "https://${host}:${port}" 2>/dev/null)
    else
      status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "http://${host}:${port}" 2>/dev/null)
    fi
    if [[ "$status" =~ ^(200|301|302|401|405)$ ]]; then
      allowed+=("$method")
    fi
  done
  echo "${allowed[*]}"
}
export -f probe_methods _timeout

# ---------- Scan ----------
echo -e "${BLUE}${BOLD}[*] Scanning (low memory mode)...${RESET}"
COUNT=0
: > "$RESULTS_FILE"

# Use while loop with xargs but low parallel count
grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | while read -r host; do
  COUNT=$((COUNT + 1))
  printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$COUNT"
  
  if check_tls "$host" 443; then
    # Get server
    server=$(curl -s -I -m "$TIMEOUT" -k "https://${host}:443" 2>/dev/null | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 25)
    [ -z "$server" ] && server="Unknown"
    
    # Speed
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
      # Pick best obscure method
      for m in PROPFIND LOCK UNLOCK MKCOL MOVE; do
        if echo "$methods_string" | grep -q "\b$m\b"; then
          best_method="$m"
          break
        fi
      done
      [ -z "$best_method" ] && best_method=$(echo "$methods_string" | cut -d' ' -f1)
      [ -z "$best_method" ] && best_method="None"
    fi
    
    echo "${host}|443|✓|${server}|${methods_string}|${speed_label}|${best_method}" >> "$RESULTS_FILE"
  fi
done

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
echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║                    L I V E   H O S T S   T A B L E                 ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

printf "  ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-20s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-8s${RESET} | ${BRIGHT_CYAN}%-20s${RESET} | ${BRIGHT_CYAN}%-7s${RESET} | ${BRIGHT_CYAN}%-12s${RESET}\n" " # " "Host" "Port" "TLS" "Server" "Methods (allowed)" "Speed" "Best Method"
printf "  %3s | %-20s | %4s | %3s | %-8s | %-20s | %-7s | %-12s\n" "---" "--------------------" "----" "---" "--------" "--------------------" "-------" "------------"

LINE_NUM=1
while IFS='|' read -r host port tls server methods speed best; do
  host=$(echo "$host" | xargs)
  server=$(echo "$server" | xargs)
  speed=$(echo "$speed" | xargs)
  methods=$(echo "$methods" | xargs)
  best=$(echo "$best" | xargs)
  
  if [ "$best" != "None" ] && [ -n "$best" ]; then
    best_colored="${BRIGHT_GREEN}${BOLD}${best}${RESET}"
  else
    best_colored="${DIM}None${RESET}"
  fi
  
  printf "  ${YELLOW}%3d${RESET} | ${CYAN}%-20s${RESET} | ${BRIGHT_WHITE}%4s${RESET} | ${GREEN}%3s${RESET} | ${WHITE}%-8s${RESET} | ${DIM}%-20s${RESET} | ${BRIGHT_YELLOW}%-7s${RESET} | %-12s\n" "$LINE_NUM" "$host" "$port" "$tls" "$server" "$methods" "$speed" "$best_colored"
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