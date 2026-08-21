#!/usr/bin/env bash
# Luphahla Scanner – Zero-Rated Host Checker (Community Edition)
# Usage: cat hosts.txt | ./verify.sh [--timeout 4] [--min-speed 50]

set -o pipefail

# ============================
# DEFAULTS
# ============================
TIMEOUT=4
MIN_SPEED=50
METHODS=("CONNECT" "POST" "HEAD" "GET")
PORTS=(443 80)   # Check both HTTPS and HTTP

# ============================
# PARSE ARGUMENTS
# ============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)   TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --help)
      echo "Usage: cat hosts.txt | $0 [--timeout 4] [--min-speed 50]"
      echo "  Checks port 443 (HTTPS) and 80 (HTTP) for zero-rated hosts."
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
# ZERO‑RATED DETECTION (extended community patterns)
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
echo -e "  ${C}Mode:${R} STANDARD (speed ≥ ${MIN_SPEED} KB/s, ports 443 & 80)"
echo ""

# ============================
# TABLE HEADERS
# ============================
printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-10s${R}\n" "HOST" "METHOD" "IP" "SPEED" "STATUS"
printf "  %-26s  %-10s  %-15s  %-10s  %-10s\n" "--------------------------" "----------" "---------------" "----------" "----------"

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

  # Try each port
  for port in "${PORTS[@]}"; do
    for method in "${METHODS[@]}"; do
      output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}|%{time_total}" -X "$method" -m "$TIMEOUT" "$( [[ $port -eq 443 ]] && echo "https" || echo "http" )://$host:$port" 2>/dev/null)
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
        break 2   # exit both loops
      fi
    done
  done

  # --- CLASSIFY STATUS ---
  if [[ "$SUCCESS" == false ]]; then
    STATUS="BLOCKED"
    SPEED_DISPLAY="N/A"
    METHOD_USED="-"
    IP_USED="N/A"
  else
    if (( SPEED_KB == 0 )); then
      SPEED_DISPLAY="0KB/s"
    elif (( SPEED_KB > 100 )); then
      SPEED_DISPLAY="⚡${SPEED_KB}KB/s"
    else
      SPEED_DISPLAY="🐢${SPEED_KB}KB/s"
    fi

    if (( SPEED_KB >= MIN_SPEED )); then
      STATUS="FREE (fast)"
    else
      STATUS="THROTTLED"
    fi
  fi

  # --- FILTER: only show fast hosts ---
  if [[ "$STATUS" != "FREE (fast)" ]]; then
    continue
  fi

  # Print row
  printf "\r  %-70s\r" ""
  case "$STATUS" in
    "FREE (fast)") STATUS_COLOR="${G}${STATUS}${R}" ;;
    "THROTTLED")   STATUS_COLOR="${Y}${STATUS}${R}" ;;
    "BLOCKED")     STATUS_COLOR="${RD}${STATUS}${R}" ;;
    *)             STATUS_COLOR="${STATUS}" ;;
  esac
  printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${STATUS_COLOR}%-10s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY" "$STATUS"
  ((FOUND++))
done < "$INPUT"

printf "\r  %-70s\r" ""
echo ""
echo -e "${G}✓${R} Found: ${C}$FOUND${R} zero-rated hosts (speed ≥ ${MIN_SPEED} KB/s)."
echo -e "  ${C}Note:${R} Ports 443 (HTTPS) and 80 (HTTP) are checked."
exit 0
