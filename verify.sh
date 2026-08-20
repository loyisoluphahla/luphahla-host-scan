#!/data/data/com.termux/files/usr/bin/bash
# Luphahla Host Scan
# verify.sh — check any host list file or pipe

set -o pipefail

RESET='\033[0m'
BOLD='\033[1m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
WHITE='\033[37m'
BRIGHT_RED='\033[91m'
BRIGHT_BLUE='\033[94m'
BRIGHT_CYAN='\033[96m'
DIM='\033[2m'

USE_COLOR=true
TIMEOUT=5

while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)
      USE_COLOR=false
      ;;
    --timeout)
      if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ]; then
        echo "Error: --timeout requires a positive number."
        exit 2
      fi
      TIMEOUT="$2"
      shift
      ;;
    --help|-h)
      echo "Luphahla Host Scan - Verification"
      echo ""
      echo "Usage:"
      echo "  cat ~/sni_hosts_latest.txt | ./verify.sh"
      echo "  ./verify.sh < ~/sni_hosts_latest.txt"
      echo "  ./verify.sh --no-color < hosts.txt"
      echo "  ./verify.sh --timeout 10 < hosts.txt"
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1"
      exit 2
      ;;
  esac
  shift
done

if [ "$USE_COLOR" = false ]; then
  RESET=''
  BOLD=''
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  CYAN=''
  WHITE=''
  BRIGHT_RED=''
  BRIGHT_BLUE=''
  BRIGHT_CYAN=''
  DIM=''
fi

# ---- Dependencies ----
MISSING=()

for cmd in openssl timeout sort grep wc mktemp; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING+=("$cmd")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  echo -e "${RED}${BOLD}[!] Missing dependencies:${RESET}"
  printf '  %s\n' "${MISSING[@]}"
  exit 1
fi

# ---- Buffer stdin ----
INPUT_FILE=$(mktemp "${TMPDIR:-/data/data/com.termux/files/usr/tmp}/luphahla-verify.XXXXXX") || {
  echo -e "${RED}Error: Could not create temporary input file.${RESET}"
  exit 1
}

cleanup() {
  rm -f "$INPUT_FILE"
}
trap cleanup EXIT INT TERM

cat > "$INPUT_FILE"

TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | wc -l)

if [ "$TOTAL" -eq 0 ]; then
  echo -e "${YELLOW}[!] No valid hosts were supplied.${RESET}"
  exit 3
fi

clear

echo -e "${BRIGHT_RED}${BOLD}"
echo "██╗     ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗"
echo "██║     ██║   ██║██╔══██╗██║  ██║██╔══██╗██║  ██║██║     ██╔══██╗"
echo "██║     ██║   ██║██████╔╝███████║███████║███████║██║     ███████║"
echo "██║     ██║   ██║██╔═══╝ ██╔══██║██╔══██║██╔══██║██║     ██╔══██║"
echo "███████╗╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║███████╗██║  ██║"
echo "╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}                 H O S T   S C A N${RESET}"
echo -e "${CYAN}                 Verification Mode${RESET}"
echo -e "${DIM}              Luphahla Host Scan${RESET}"
echo ""

echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}Candidates:${RESET} $TOTAL"
echo -e "  ${CYAN}Timeout:${RESET}    ${TIMEOUT}s"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

START_TIME=$(date +%s)

LIVE_FILE=$(mktemp "${TMPDIR:-/data/data/com.termux/files/usr/tmp}/luphahla-live.XXXXXX") || {
  echo -e "${RED}Error: Could not create temporary result file.${RESET}"
  exit 1
}

cleanup_verify() {
  rm -f "$INPUT_FILE" "$LIVE_FILE"
}
trap cleanup_verify EXIT INT TERM

check_tls() {
  local host="$1"

  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    timeout "$TIMEOUT" openssl s_client \
      -connect "$host:443" \
      -verify_return_error \
      -verify_ip "$host" \
      -verify_quiet \
      -brief \
      -no_ign_eof \
      </dev/null >/dev/null 2>&1
  else
    timeout "$TIMEOUT" openssl s_client \
      -connect "$host:443" \
      -servername "$host" \
      -verify_return_error \
      -verify_hostname "$host" \
      -verify_quiet \
      -brief \
      -no_ign_eof \
      </dev/null >/dev/null 2>&1
  fi
}

COUNT=0

while IFS= read -r host; do
  [[ "$host" =~ ^[[:space:]]*# ]] && continue
  [ -z "$host" ] && continue

  COUNT=$((COUNT + 1))

  echo -ne "\r${CYAN}[*]${RESET} ${WHITE}$COUNT/$TOTAL${RESET} — ${CYAN}$host${RESET}...   "

  if check_tls "$host"; then
    echo ""
    echo -e "  ${GREEN}${BOLD}✓${RESET} ${GREEN}$host:443${RESET}"
    printf '%s\n' "$host" >> "$LIVE_FILE"
  fi
done < "$INPUT_FILE"

sort -u "$LIVE_FILE" -o "$LIVE_FILE"

LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_RED}${BOLD}                    RESULTS${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  cat "$LIVE_FILE"
else
  echo -e "${YELLOW}No hosts passed TLS verification.${RESET}"
fi

echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}Candidates:${RESET} $TOTAL"
echo -e "  ${CYAN}Checked:${RESET}    $COUNT"
echo -e "  ${CYAN}Live:${RESET}       ${GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}Duration:${RESET}   ${DURATION}s"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

if [ "$LIVECOUNT" -gt 0 ]; then
  exit 0
else
  exit 3
fi
