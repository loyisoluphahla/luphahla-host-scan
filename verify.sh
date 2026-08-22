#!/usr/bin/env bash
# Luphahla Scanner – Zero-Rated Host Checker (with Tunnel Test)
# Usage: cat hosts.txt | ./verify.sh [--timeout 4] [--min-speed 50] [--tunnel]

set -o pipefail

# ============================
# DEFAULTS
# ============================
TIMEOUT=4
MIN_SPEED=50
TUNNEL_MODE=false
METHODS=("GET" "HEAD" "POST" "CONNECT")
PORTS=(443 80)

# ============================
# PARSE ARGUMENTS
# ============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)   TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --tunnel)    TUNNEL_MODE=true ;;
    --help)
      echo "Usage: cat hosts.txt | $0 [--timeout 4] [--min-speed 50] [--tunnel]"
      echo "  --tunnel : test CONNECT and WebSocket support (✅/❌)"
      exit 0
      ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# ============================
# COLORS
# ============================
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'; W='\033[37m'; RD='\033[91m'

# ============================
# READ STDIN – SPLIT, TRIM, DEDUPLICATE
# ============================
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
cat /dev/stdin | tr ' ' '\n' | sed 's/^[[:space:]]*//;s/[[:space:]]*$//' | grep -vE '^[[:space:]]*(#|$)' | tr '[:upper:]' '[:lower:]' | sort -u > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
[[ $TOTAL -eq 0 ]] && { echo -e "${Y}No hosts.${R}" >&2; exit 3; }

# ============================
# ZERO‑RATED DETECTION (community patterns)
# ============================
is_free() {
  local h=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  for p in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow \
           econetwireless zigssh roshan etisalat mtnplay goodinternet learningpassport unicef msmehub latamairlines ooguy bundles orgonemoney topup apn vasapi selfcare ibills meet elevateyouth oldlock; do
    [[ "$h" == *"$p"* ]] && return 0
  done
  return 1
}

# ============================
# BANNER
# ============================
clear
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}         L U P H A H L A   Z E R O - R A T E D   H O S T S            ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
if [[ "$TUNNEL_MODE" == true ]]; then
  echo -e "  ${C}Mode:${R} TUNNEL (speed ≥ ${MIN_SPEED} KB/s, CONNECT & WS tested)"
else
  echo -e "  ${C}Mode:${R} STANDARD (speed ≥ ${MIN_SPEED} KB/s)"
fi
echo ""

# ============================
# TABLE HEADERS
# ============================
if [[ "$TUNNEL_MODE" == true ]]; then
  printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-8s  %-4s  %-4s${R}\n" "HOST" "METHOD" "IP" "SPEED" "STATUS" "C" "WS"
  printf "  %-26s  %-10s  %-15s  %-10s  %-8s  %-4s  %-4s\n" "--------------------------" "----------" "---------------" "----------" "--------" "---" "---"
else
  printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-8s${R}\n" "HOST" "METHOD" "IP" "SPEED" "STATUS"
  printf "  %-26s  %-10s  %-15s  %-10s  %-8s\n" "--------------------------" "----------" "---------------" "----------" "--------"
fi

# ============================
# SPINNER
# ============================
SPINNER=('|' '/' '-' '\')
SPIN_IDX=0
update_spinner() {
  printf "\r  ${C}%s${R} Scanning..." "${SPINNER[SPIN_IDX]}"
  ((SPIN_IDX++)); [[ $SPIN_IDX -ge ${#SPINNER[@]} ]] && SPIN_IDX=0
}

# ============================
# SCAN LOOP
# ============================
COUNT=0; FOUND=0
while IFS= read -r host; do
  ((COUNT++)); update_spinner

  if ! is_free "$host"; then continue; fi

  SUCCESS=false
  SPEED_KB=0
  METHOD_USED=""
  IP_USED="N/A"
  BEST_PORT=0

  # ---- Primary scan (GET first for speed) ----
  for port in "${PORTS[@]}"; do
    for method in "${METHODS[@]}"; do
      output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}" -X "$method" -m "$TIMEOUT" "$( [[ $port -eq 443 ]] && echo "https" || echo "http" )://$host:$port" 2>/dev/null)
      code=$(echo "$output" | cut -d'|' -f1)
      ip=$(echo "$output" | cut -d'|' -f2)
      speed_bytes=$(echo "$output" | cut -d'|' -f3)
      [[ -z "$ip" ]] && ip="N/A"

      if [[ -n "$code" && "$code" != "000" ]]; then
        SUCCESS=true
        METHOD_USED="$method"
        IP_USED="$ip"
        BEST_PORT="$port"
        [[ "$speed_bytes" =~ ^[0-9]+ ]] && SPEED_KB=$((speed_bytes / 1024))
        break 2
      fi
    done
  done

  # ---- CLASSIFY STATUS ----
  if [[ "$SUCCESS" == false ]]; then
    STATUS="BLOCKED"
    SPEED_DISPLAY="N/A"
    METHOD_USED="-"
    IP_USED="N/A"
    CONNECT_SUPPORT="❌"
    WS_SUPPORT="❌"
  else
    if (( SPEED_KB == 0 )); then
      SPEED_DISPLAY="0KB/s"
    elif (( SPEED_KB > 100 )); then
      SPEED_DISPLAY="⚡${SPEED_KB}KB/s"
    else
      SPEED_DISPLAY="🐢${SPEED_KB}KB/s"
    fi

    if (( SPEED_KB >= MIN_SPEED )); then
      STATUS="FREE"
    else
      STATUS="THROTTLED"
    fi

    # ---- TUNNEL MODE: test CONNECT and WebSocket ----
    if [[ "$TUNNEL_MODE" == true ]]; then
      # Test CONNECT method
      connect_code=$(curl -s -o /dev/null -w "%{http_code}" -X CONNECT -k -m "$TIMEOUT" "https://$host" 2>/dev/null)
      if [[ "$connect_code" =~ ^(200|301|302|405)$ ]]; then
        CONNECT_SUPPORT="✅"
      else
        CONNECT_SUPPORT="❌"
      fi

      # Test WebSocket upgrade
      if curl -s -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" -k -m "$TIMEOUT" "https://$host" 2>/dev/null | grep -q "101 Switching"; then
        WS_SUPPORT="✅"
      else
        WS_SUPPORT="❌"
      fi
    else
      CONNECT_SUPPORT=""
      WS_SUPPORT=""
    fi
  fi

  # ---- FILTER: only show fast hosts ----
  if [[ "$STATUS" != "FREE" ]]; then
    continue
  fi

  # ---- PRINT ROW ----
  printf "\r  %-70s\r" ""
  STATUS_COLOR="${G}${STATUS}${R}"

  if [[ "$TUNNEL_MODE" == true ]]; then
    # Color the emojis: green for ✅, red for ❌
    [[ "$CONNECT_SUPPORT" == "✅" ]] && CONNECT_COLOR="${G}${CONNECT_SUPPORT}${R}" || CONNECT_COLOR="${RD}${CONNECT_SUPPORT}${R}"
    [[ "$WS_SUPPORT" == "✅" ]] && WS_COLOR="${G}${WS_SUPPORT}${R}" || WS_COLOR="${RD}${WS_SUPPORT}${R}"
    printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${STATUS_COLOR}%-8s${R}  ${CONNECT_COLOR}%-4s${R}  ${WS_COLOR}%-4s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY" "$STATUS" "$CONNECT_SUPPORT" "$WS_SUPPORT"
  else
    printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${STATUS_COLOR}%-8s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY" "$STATUS"
  fi
  ((FOUND++))
done < "$INPUT"

printf "\r  %-70s\r" ""
echo ""
if [[ "$TUNNEL_MODE" == true ]]; then
  echo -e "${G}✓${R} Found: ${C}$FOUND${R} tunnel‑ready candidates (speed ≥ ${MIN_SPEED} KB/s)."
  echo -e "  ${C}Columns:${R} C = CONNECT support, WS = WebSocket support"
else
  echo -e "${G}✓${R} Found: ${C}$FOUND${R} zero-rated hosts (speed ≥ ${MIN_SPEED} KB/s)."
  echo -e "  ${C}Tip:${R} Use --tunnel to test CONNECT and WebSocket support."
fi
exit 0
