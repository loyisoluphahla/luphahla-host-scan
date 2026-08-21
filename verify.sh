#!/usr/bin/env bash
# Luphahla Host Scan - BugScanX Style with Expanded Zero‑Rated Detection (including Elon)
# FIXED: printf error, better table formatting

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
PARALLEL=5
OUTPUT_FILE=""
INPUT_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-input.XXXXXX")
RESULTS_FILE=$(mktemp "${TMPDIR:-/tmp}/verify-results.XXXXXX")
trap 'rm -f "$INPUT_FILE" "$RESULTS_FILE"' EXIT INT TERM

# ---------- Methods ----------
METHODS=("CONNECT" "POST" "HEAD" "GET")

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    -o)              OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      echo "Luphahla BugScanX Scanner (Expanded Detection + Elon)"
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

# ---------- Read stdin ----------
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
echo -e "${BRIGHT_BLUE}${BOLD}     E X P A N D E D   Z E R O - R A T E D   D E T E C T I O N   +   E L O N   🚀${RESET}"
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

# ---------- Expanded Zero‑Rating Detection ----------
detect_zero_rated() {
  local host="$1"
  local server="$2"
  local combined="$host $server"
  combined=$(echo "$combined" | tr '[:upper:]' '[:lower:]')

  patterns=(
    # Google / Alphabet
    "google" "youtube" "gmail" "android" "play" "chrome" "gstatic" "googleapis"
    # Meta
    "facebook" "meta" "whatsapp" "instagram" "fbcdn" "messenger" "threads"
    # Twitter / X
    "twitter" "x.com" "twimg" "t.co"
    # Elon Musk companies
    "tesla" "spacex" "starlink" "neuralink" "boringcompany" "xai"
    # Other social / messaging
    "snapchat" "telegram" "signal" "line" "wechat" "discord" "slack" "zoom" "reddit" "pinterest" "linkedin"
    "tumblr" "viber" "imo" "skype"
    # Streaming / Media
    "netflix" "spotify" "hulu" "vimeo" "dailymotion" "twitch" "soundcloud" "pandora" "tidal"
    # CDNs
    "cloudflare" "akamai" "fastly" "cloudfront" "varnish" "incapsula" "sucuri" "stackpath" "edgecast"
    # Cloud providers
    "amazon" "aws" "azure" "google cloud" "oracle cloud" "ibm cloud" "digitalocean" "vultr" "linode"
    # Major tech
    "apple" "icloud" "microsoft" "office" "live" "outlook" "bing" "yahoo" "aol" "msn"
    # African ISPs
    "econet" "netone" "mtn" "vodacom" "orange" "airtel" "safaricom" "liquid" "telkom" "zol"
    # Other big names
    "github" "stackoverflow" "wordpress" "blogger" "medium" "wix" "squarespace"
    "shopify" "etsy" "alibaba" "alipay" "tencent" "baidu" "weibo" "yandex"
    "naver" "kakao" "line"
  )

  for pattern in "${patterns[@]}"; do
    if [[ "$combined" == *"$pattern"* ]]; then
      echo "FREE"
      return 0
    fi
  done
  echo "UNKNOWN"
}

# ---------- Scan a host ----------
scan_host() {
  local host="$1"
  local port=443

  if ! check_tls "$host" "$port"; then
    return 1
  fi

  local best_method=""
  local best_code=""
  local best_server=""
  local best_ip=""
  local speed_kb=0
  local speed_label="N/A"
  local zero_label="UNKNOWN"

  for method in "${METHODS[@]}"; do
    local output
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}" -X "$method" "https://${host}:${port}" 2>/dev/null)
    local code=$(echo "$output" | cut -d'|' -f1)
    local ip=$(echo "$output" | cut -d'|' -f2)
    local speed_bytes=$(echo "$output" | cut -d'|' -f3)

    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      local server=$(curl -s -I -k -m "$TIMEOUT" -X "$method" "https://${host}:${port}" 2>/dev/null | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 25)
      [ -z "$server" ] && server="Unknown"

      if [[ "$speed_bytes" =~ ^[0-9]+ ]] && [ "$speed_bytes" -gt 0 ]; then
        speed_kb=$(echo "$speed_bytes / 1024" | bc 2>/dev/null)
        if [ -n "$speed_kb" ]; then
          if [ "$speed_kb" -gt 100 ]; then speed_label="⚡ ${speed_kb} KB/s"; else speed_label="🐢 ${speed_kb} KB/s"; fi
        else
          speed_label="N/A"
        fi
      else
        speed_label="⛔ No Data"
      fi

      if [ -z "$best_method" ]; then
        best_method="$method"
        best_code="$code"
        best_server="$server"
        best_ip="$ip"
        zero_label=$(detect_zero_rated "$host" "$server")
      fi
    fi
  done

  if [ -z "$best_method" ]; then
    return 1
  fi

  if [ "$zero_label" = "FREE" ]; then
    zero_label="✅ FREE"
  else
    zero_label="❓ Unknown"
  fi

  echo "${host}|${best_ip:-N/A}|${port}|${best_method}|${best_code}|${best_server:-Unknown}|${speed_label}|${zero_label}"
}
export -f scan_host check_tls _timeout detect_zero_rated
export TIMEOUT METHODS

# ---------- Run scan ----------
echo -e "${BLUE}${BOLD}[*] Scanning hosts (${PARALLEL} parallel)...${RESET}"
COUNT=0
: > "$RESULTS_FILE"

if [ "$PARALLEL" -gt 1 ] && command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
  grep -vE '^[[:space:]]*(#|$)' "$INPUT_FILE" | \
    xargs -P "$PARALLEL" -I {} bash -c '
      scan_host "$1"
    ' _ {} > "$RESULTS_FILE" 2>/dev/null &
  local pid=$!
  local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
  local i=0
  while kill -0 "$pid" 2>/dev/null; do
    printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Scanning..."
    sleep 0.1
  done
  wait "$pid"
  printf "\r  ${GREEN}✓${RESET} Scan complete.                    \n"
else
  while IFS= read -r host; do
    [[ "$host" =~ ^[[:space:]]*# ]] && continue
    [ -z "$host" ] && continue
    COUNT=$((COUNT + 1))
    printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$COUNT"
    scan_host "$host" >> "$RESULTS_FILE"
  done < "$INPUT_FILE"
  echo ""
fi

# ============================================================
#  DISPLAY TABLE (FIXED)
# ============================================================
LIVECOUNT=$(wc -l < "$RESULTS_FILE")
if [ "$LIVECOUNT" -eq 0 ]; then
  echo -e "${YELLOW}No live hosts found.${RESET}"
  exit 0
fi

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║                            L I V E   H O S T S   T A B L E                                                                                ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

printf "  ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-25s${RESET} | ${BRIGHT_CYAN}%-15s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%-8s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%-12s${RESET} | ${BRIGHT_CYAN}%-10s${RESET} | ${BRIGHT_CYAN}%-10s${RESET}\n" " # " "Host" "IP" "Port" "Method" "Code" "Server" "Speed" "Zero-Rated"
printf "  %3s | %-25s | %-15s | %4s | %-8s | %4s | %-12s | %-10s | %-10s\n" "---" "-------------------------" "---------------" "----" "--------" "----" "------------" "----------" "----------"

LINE_NUM=1
while IFS='|' read -r host ip port method code server speed zero; do
  host=$(echo "$host" | xargs)
  ip=$(echo "$ip" | xargs)
  server=$(echo "$server" | xargs | cut -c1-12)
  speed=$(echo "$speed" | xargs)
  zero=$(echo "$zero" | xargs)

  if [[ "$code" =~ ^(200|301|302)$ ]]; then
    code_colored="${GREEN}${code}${RESET}"
  elif [[ "$code" == "401" ]]; then
    code_colored="${YELLOW}${code}${RESET}"
  elif [[ "$code" == "405" ]]; then
    code_colored="${CYAN}${code}${RESET}"
  else
    code_colored="${RED}${code}${RESET}"
  fi

  if [[ "$zero" == *"FREE"* ]]; then
    zero_colored="${BRIGHT_GREEN}✅ FREE${RESET}"
  else
    zero_colored="${DIM}❓ Unknown${RESET}"
  fi

  # FIXED: Use %s for all string fields to avoid "invalid number" error
  printf "  ${YELLOW}%3d${RESET} | ${CYAN}%-25s${RESET} | ${WHITE}%-15s${RESET} | ${BRIGHT_WHITE}%4s${RESET} | ${BRIGHT_BLUE}%-8s${RESET} | ${code_colored}%4s${RESET} | ${DIM}%-12s${RESET} | %-10s | ${zero_colored}\n" "$LINE_NUM" "$host" "$ip" "$port" "$method" "$code" "$server" "$speed" "$zero"
  LINE_NUM=$((LINE_NUM + 1))
done < "$RESULTS_FILE"

echo ""
echo -e "  ${GREEN}✓${RESET} Total live hosts: ${BRIGHT_WHITE}$LIVECOUNT${RESET}"
echo -e "  ${GREEN}✓${RESET} ✅ FREE = matches known zero‑rated patterns (including Elon Musk's companies)."

if [ -n "$OUTPUT_FILE" ]; then
  cp "$RESULTS_FILE" "$OUTPUT_FILE"
  echo -e "  ${GREEN}✓${RESET} Saved to: ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
fi

echo ""
exit 0
