#!/usr/bin/env bash
# Luphahla Host Scan - verify.sh
# Usage: cat hosts.txt | ./verify.sh [options]
# Options:
#   --no-color        disable ANSI colors
#   --timeout N       timeout in seconds per host (default 5)
#   --parallel N      number of parallel jobs (default 10)
#   -o FILE           write live hosts to FILE
#   --help            show this help

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
PARALLEL=10
OUTPUT_FILE=""
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
LIVE_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-live.XXXXXX")
trap 'rm -f "$INPUT_FILE" "$LIVE_FILE"' EXIT INT TERM

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)    USE_COLOR=false ;;
    --timeout)     TIMEOUT="$2"; shift ;;
    --parallel)    PARALLEL="$2"; shift ;;
    -o)            OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# //'
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
  RESET=''; BOLD=''; DIM=''; UNDERLINE=''
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''; BRIGHT_MAGENTA=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; UNDERLINE='\033[4m'
  RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; MAGENTA='\033[35m'; WHITE='\033[37m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'; BRIGHT_MAGENTA='\033[95m'
fi

# ---------- Progress bar function ----------
progress_bar() {
  local current=$1
  local total=$2
  local prefix="$3"
  local percent=$((current * 100 / total))
  local filled=$((percent / 2))
  local empty=$((50 - filled))
  
  printf "\r${BLUE}${BOLD}${prefix}${RESET} ${CYAN}["
  for ((i=0; i<filled; i++)); do printf "${GREEN}█${RESET}"; done
  for ((i=0; i<empty; i++)); do printf "${DIM}░${RESET}"; done
  printf "${CYAN}] ${BRIGHT_CYAN}%3d%%${RESET} ${WHITE}(%d/%d)${RESET}" "$percent" "$current" "$total"
}

# ---------- Read stdin into temp file ----------
cat > "$INPUT_FILE"
TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | wc -l)
if [ "$TOTAL" -eq 0 ]; then
  echo -e "${YELLOW}No valid hosts supplied.${RESET}" >&2
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
echo -e "${BRIGHT_BLUE}${BOLD}                  H O S T   S C A N${RESET}"
echo -e "${CYAN}               Luphahla Host Scan - Verification${RESET}"
echo -e "${DIM}           ───────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Candidates:${RESET} ${BRIGHT_CYAN}$TOTAL${RESET}    ${YELLOW}Timeout:${RESET} ${BRIGHT_CYAN}${TIMEOUT}s${RESET}"
echo -e "${DIM}           ───────────────────────────────────────${RESET}"
echo ""

# ---------- TLS check function ----------
check_tls() {
  local host="$1"
  local port="${2:-443}"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  fi
}
export -f check_tls _timeout
export TIMEOUT

# ---------- Parallel verification ----------
echo -e "${BRIGHT_BLUE}${BOLD}  ── Scanning Port 443 ──${RESET}"
: > "$LIVE_FILE"
COUNT=0

if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
  # We capture output in temp files to show progress
  TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/verify-progress.XXXXXX")
  trap 'rm -rf "$TMP_DIR"' EXIT INT TERM
  
  grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | while read -r host; do
    COUNT=$((COUNT + 1))
    progress_bar "$COUNT" "$TOTAL" "Scanning"
    if check_tls "$host"; then
      echo "$host" >> "$LIVE_FILE"
    fi
  done
else
  # Sequential fallback
  while IFS= read -r host; do
    [[ "$host" =~ ^[[:space:]]*# ]] && continue
    [ -z "$host" ] && continue
    COUNT=$((COUNT + 1))
    progress_bar "$COUNT" "$TOTAL" "Scanning"
    if check_tls "$host"; then
      echo "$host" >> "$LIVE_FILE"
    fi
  done < "$INPUT_FILE"
fi

echo "" # newline after progress bar

# ---------- Results ----------
sort -u "$LIVE_FILE" -o "$LIVE_FILE"
LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║            S C A N   R E S U L T S         ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════════╝${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  echo -e "${BRIGHT_CYAN}${BOLD}  ── Live Hosts (${LIVECOUNT} found) ──${RESET}"
  nl -w2 -s'. ' "$LIVE_FILE" | sed 's/^/  /' | while read -r line; do
    echo -e "  ${GREEN}✓${RESET} ${WHITE}$line${RESET}"
  done
else
  echo -e "  ${YELLOW}${BOLD}⚠${RESET} ${YELLOW}No hosts passed TLS verification.${RESET}"
fi

echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ╔════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}  ║            S U M M A R Y                  ║${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}  ╚════════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates:  ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Live:         ${BRIGHT_GREEN}$LIVECOUNT${RESET}"
echo ""

# ---------- Save output if requested ----------
if [ -n "$OUTPUT_FILE" ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  echo -e "  ${GREEN}✓${RESET} ${GREEN}Saved to${RESET} ${BRIGHT_CYAN}$OUTPUT_FILE${RESET}"
  echo ""
fi

exit 0
