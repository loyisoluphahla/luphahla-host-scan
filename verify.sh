#!/usr/bin/env bash
# Luphahla Host Scan - Tunnel-Ready Endpoint Scanner
# Usage:
#   cat hosts.txt | ./verify.sh --tunnel-scan
#   ./verify.sh --tunnel-scan --timeout 3 < mylist.txt

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
PARALLEL=15
OUTPUT_FILE=""
TUNNEL_MODE=false
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
LIVE_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-live.XXXXXX")
SCORED_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-scored.XXXXXX")
trap 'rm -f "$INPUT_FILE" "$LIVE_FILE" "$SCORED_FILE"' EXIT INT TERM

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)       USE_COLOR=false ;;
    --timeout)        TIMEOUT="$2"; shift ;;
    --parallel)       PARALLEL="$2"; shift ;;
    --tunnel-scan)    TUNNEL_MODE=true ;;
    -o)               OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      echo "Luphahla Tunnel-Ready Scanner"
      echo "  --tunnel-scan    : Activate deep inspection (speed + zero-rating)"
      echo "  --timeout 3      : Faster checks for tunneling"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; GREEN=''; RED=''; CYAN=''; YELLOW=''; BLUE=''; BRIGHT_GREEN=''; BRIGHT_CYAN=''; BRIGHT_YELLOW=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; GREEN='\033[32m'; RED='\033[31m'; CYAN='\033[36m'; YELLOW='\033[33m'; BLUE='\033[34m'
  BRIGHT_GREEN='\033[92m'; BRIGHT_CYAN='\033[96m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_RED='\033[91m'
fi

# ---------- Read stdin ----------
cat > "$INPUT_FILE"
TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | wc -l)
if [ "$TOTAL" -eq 0 ]; then echo -e "${RED}No hosts.${RESET}" >&2; exit 3; fi

# ---------- Banner ----------
[ -t 1 ] && clear
echo -e "${BRIGHT_GREEN}${BOLD}"
echo "  ██╗     ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗  "
echo "  ██║     ██║   ██║██╔══██╗██║  ██║██╔══██╗██║  ██║██║     ██╔══██╗ "
echo "  ██║     ██║   ██║██████╔╝███████║███████║███████║██║     ███████║ "
echo "  ██║     ██║   ██║██╔═══╝ ██╔══██║██╔══██║██╔══██║██║     ██╔══██║ "
echo "  ███████╗╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║███████╗██║  ██║ "
echo "  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ "
echo -e "${RESET}"
echo -e "${BLUE}${BOLD}       T U N N E L - R E A D Y   S C A N N E R${RESET}"
if [ "$TUNNEL_MODE" = true ]; then
  echo -e "${BRIGHT_YELLOW}${BOLD}  ⚡ DEEP INSPECTION ACTIVE (Speed + Zero-Rating)${RESET}"
else
  echo -e "${CYAN}  Standard TLS Check (use --tunnel-scan for deep inspection)${RESET}"
fi
echo -e "${DIM}  Targets: $TOTAL  |  Timeout: ${TIMEOUT}s${RESET}"
echo ""

# ---------- The Deep Inspection Function ----------
deep_inspect() {
  local host="$1"
  local port="${2:-443}"
  local score=0
  local speed=""
  local zero_rated="No"
  local server_header=""

  # 1. Check TLS (basic)
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1 || return 1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1 || return 1
  fi
  score=$((score + 30))  # TLS handshake success

  # 2. Check HTTP headers (for zero-rating detection)
  if command -v curl >/dev/null; then
    local headers
    headers=$(curl -s -I -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    server_header=$(echo "$headers" | grep -i "^Server:" | head -1)
    
    # Detect famous zero-rated CDNs/Companies
    if echo "$server_header" | grep -qi "gws\|google"; then
      zero_rated="Google (Often Free)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "cloudflare"; then
      zero_rated="Cloudflare (Often Free)"
      score=$((score + 35))
    elif echo "$server_header" | grep -qi "facebook\|meta"; then
      zero_rated="Meta/WhatsApp (Often Free)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "microsoft\|iis"; then
      zero_rated="Microsoft (Sometimes Free)"
      score=$((score + 25))
    else
      zero_rated="Unknown (Check manually)"
      score=$((score + 5))
    fi

    # 3. Check Speed (Download a small file)
    local speed_result
    speed_result=$(curl -s -o /dev/null -w "%{speed_download}" -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    if [[ "$speed_result" =~ ^[0-9]+ ]]; then
      speed_kb=$(echo "$speed_result / 1024" | bc 2>/dev/null)
      if [ "$speed_kb" -gt 100 ]; then
        score=$((score + 25))  # Fast
        speed="⚡ ${speed_kb} KB/s"
      elif [ "$speed_kb" -gt 10 ]; then
        score=$((score + 10))
        speed="🐢 ${speed_kb} KB/s"
      else
        speed="⛔ Throttled"
      fi
    else
      speed="⛔ No Data"
    fi
  else
    score=$((score - 10))  # No curl installed, can't fully test
    speed="Install curl for speed tests"
  fi

  # Output: SCORE|HOST|PORT|ZERO|SPEED|SERVER
  echo "${score}|${host}|${port}|${zero_rated}|${speed}|${server_header}"
}
export -f deep_inspect _timeout
export TIMEOUT

# ---------- Run the scan ----------
if [ "$TUNNEL_MODE" = true ]; then
  echo -e "${BLUE}${BOLD}[*] Running Deep Inspection...${RESET}"
  echo ""

  # If xargs is available, parallelize the deep inspection
  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        deep_inspect "$1" 443
      ' _ {} > "$SCORED_FILE" 2>/dev/null
  else
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      deep_inspect "$host" 443 >> "$SCORED_FILE"
    done < "$INPUT_FILE"
  fi

  # Sort by score (highest first) and display beautifully
  echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════╗${RESET}"
  echo -e "${BRIGHT_GREEN}${BOLD}  ║              T U N N E L   R A N K I N G S                  ║${RESET}"
  echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════╝${RESET}"

  sort -t'|' -k1 -nr "$SCORED_FILE" | head -20 | while IFS='|' read -r score host port zero speed server; do
    # Determine color based on score
    if [ "$score" -gt 70 ]; then
      label="${BRIGHT_GREEN}[HIGH]${RESET}"
    elif [ "$score" -gt 40 ]; then
      label="${BRIGHT_YELLOW}[MEDIUM]${RESET}"
    else
      label="${BRIGHT_RED}[LOW]${RESET}"
    fi

    printf "  %-8s %-25s %-25s %-15s %-20s\n" \
      "$label" \
      "${CYAN}$host${RESET}" \
      "${YELLOW}$zero${RESET}" \
      "${GREEN}$speed${RESET}" \
      "${DIM}$server${RESET}"
  done

  echo ""
  echo -e "${DIM}  [HIGH] = Fast + Zero-Rated (Best for Tunneling)${RESET}"
  echo -e "${DIM}  [MEDIUM] = Working but may be throttled.${RESET}"
  echo -e "${DIM}  [LOW] = Slow or unverified.${RESET}"
  echo ""
  echo -e "${BRIGHT_YELLOW}${BOLD}  ⚠️  Remember: Actual tunneling requires V2Ray/Xray or SSH.${RESET}"
  echo -e "${BRIGHT_YELLOW}${BOLD}      This scan just finds the best fronting host.${RESET}"

  # Save the high-scoring hosts to the output file for external tools
  sort -t'|' -k1 -nr "$SCORED_FILE" | head -10 | cut -d'|' -f2 > "$LIVE_FILE"
else
  # Standard Mode (original behavior - just TLS check)
  echo -e "${BLUE}${BOLD}[*] Standard TLS Check (Use --tunnel-scan for better insights)${RESET}"
  # ... (original verify logic)
  grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | while read -r host; do
    if check_tls_standard "$host"; then echo "$host" >> "$LIVE_FILE"; fi
  done
fi

# ---------- Save output ----------
if [ -n "$OUTPUT_FILE" ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  echo -e "  ${GREEN}Saved best candidates to $OUTPUT_FILE${RESET}"
fi

exit 0
