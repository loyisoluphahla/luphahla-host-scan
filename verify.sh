#!/usr/bin/env bash
# Luphahla Scanner – Zero‑Rated Host Checker
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--min-speed 50] [--vpn] [--analyze]

set -o pipefail

# ============================
# DEFAULTS
# ============================
TIMEOUT=3
MIN_SPEED=50
VPN_MODE=false
ANALYZE_MODE=false
METHODS=("CONNECT" "POST" "HEAD" "GET")

# ============================
# PARSE ARGUMENTS
# ============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)   TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --vpn)       VPN_MODE=true ;;
    --analyze)   ANALYZE_MODE=true ;;
    --help)
      echo "Usage: cat hosts.txt | $0 [--timeout 3] [--min-speed 50] [--vpn] [--analyze]"
      echo "  --min-speed : minimum speed for 'fast' (default 50)"
      echo "  --vpn       : strict VPN filters (CONNECT, latency, server header)"
      echo "  --analyze   : show all zero‑rated hosts with status: FREE, THROTTLED, or BLOCKED"
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
# READ STDIN
# ============================
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
[[ $TOTAL -eq 0 ]] && { echo -e "${Y}No hosts.${R}" >&2; exit 3; }

# ============================
# ZERO‑RATED DETECTION
# ============================
is_free() {
  local h=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  for p in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow; do
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
if [[ "$ANALYZE_MODE" == true ]]; then
  echo -e "  ${C}Mode:${R} ANALYZE (shows FREE, THROTTLED, BLOCKED)"
elif [[ "$VPN_MODE" == true ]]; then
  echo -e "  ${C}Mode:${R} VPN-ELIGIBLE (strict)"
else
  echo -e "  ${C}Mode:${R} STANDARD (speed ≥ ${MIN_SPEED} KB/s)"
fi
echo ""

# ============================
# TABLE HEADERS (determined by mode)
# ============================
if [[ "$ANALYZE_MODE" == true ]]; then
  printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-10s${R}\n" "HOST" "METHOD" "IP" "SPEED" "STATUS"
  printf "  %-26s  %-10s  %-15s  %-10s  %-10s\n" "--------------------------" "----------" "---------------" "----------" "----------"
elif [[ "$VPN_MODE" == true ]]; then
  printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-10s  %-8s${R}\n" "HOST" "METHOD" "IP" "SPEED" "LATENCY" "STATUS"
  printf "  %-26s  %-10s  %-15s  %-10s  %-10s  %-8s\n" "--------------------------" "----------" "---------------" "----------" "----------" "--------"
else
  printf "  ${C}%-26s  %-10s  %-15s  %-10s${R}\n" "HOST" "METHOD" "IP" "SPEED"
  printf "  %-26s  %-10s  %-15s  %-10s\n" "--------------------------" "----------" "---------------" "----------"
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

  # Only zero‑rated hosts
  if ! is_free "$host"; then continue; fi

  # Try methods in order, but we only need one that gives any response
  # For analyze mode, we also need to detect BLOCKED (no response from any method)
  SUCCESS=false
  SPEED_KB=0
  LATENCY=999.0
  METHOD_USED=""
  IP_USED="N/A"

  for method in "${METHODS[@]}"; do
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}|%{time_total}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    code=$(echo "$output" | cut -d'|' -f1)
    ip=$(echo "$output" | cut -d'|' -f2)
    speed_bytes=$(echo "$output" | cut -d'|' -f3)
    latency=$(echo "$output" | cut -d'|' -f4)
    [[ -z "$ip" ]] && ip="N/A"
    [[ -z "$latency" ]] && latency="999.0"

    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      SUCCESS=true
      METHOD_USED="$method"
      IP_USED="$ip"
      LATENCY="$latency"
      [[ "$speed_bytes" =~ ^[0-9]+ ]] && SPEED_KB=$((speed_bytes / 1024))
      break  # stop at first working method
    fi
  done

  # --- CLASSIFY STATUS ---
  if [[ "$SUCCESS" == false ]]; then
    STATUS="BLOCKED"
    SPEED_DISPLAY="N/A"
    METHOD_USED="-"
    IP_USED="N/A"
    LATENCY_DISPLAY="N/A"
  else
    # Speed display
    if (( SPEED_KB > 100 )); then SPEED_DISPLAY="⚡${SPEED_KB}KB/s"; else SPEED_DISPLAY="🐢${SPEED_KB}KB/s"; fi
    LATENCY_DISPLAY=$(printf "%.2f" "$LATENCY")s

    # Determine status
    if (( SPEED_KB >= MIN_SPEED )); then
      STATUS="FREE (fast)"
    else
      STATUS="THROTTLED"
    fi
  fi

  # --- FILTERING ---
  # If NOT analyze mode, skip slow hosts
  if [[ "$ANALYZE_MODE" == false ]]; then
    if [[ "$STATUS" == "BLOCKED" || "$STATUS" == "THROTTLED" ]]; then
      continue
    fi
  fi

  # VPN mode: additional filters (only if not blocked and not analyze? VPN mode usually only cares about fast hosts)
  if [[ "$VPN_MODE" == true && "$STATUS" != "BLOCKED" ]]; then
    [[ "$METHOD_USED" != "CONNECT" ]] && continue
    (( $(echo "$LATENCY > 1.5" | bc -l) )) && continue
    server=$(curl -s -I -k -m 2 "https://$host" 2>/dev/null | grep -i "^Server:" | head -1)
    [[ -z "$server" || "$server" == *"Unknown"* ]] && continue
    VPN_STATUS="✅ PASS"
  else
    VPN_STATUS=""
  fi

  # Print row
  printf "\r  %-70s\r" ""

  if [[ "$ANALYZE_MODE" == true ]]; then
    # Color status
    case "$STATUS" in
      "FREE (fast)") STATUS_COLOR="${G}${STATUS}${R}" ;;
      "THROTTLED")   STATUS_COLOR="${Y}${STATUS}${R}" ;;
      "BLOCKED")     STATUS_COLOR="${RD}${STATUS}${R}" ;;
      *)             STATUS_COLOR="${STATUS}" ;;
    esac
    printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${STATUS_COLOR}%-10s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY" "$STATUS"
  elif [[ "$VPN_MODE" == true ]]; then
    if (( SPEED_KB >= MIN_SPEED )); then
      printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${W}%-10s${R}  ${G}%-8s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY" "$LATENCY_DISPLAY" "$VPN_STATUS"
    else
      continue  # skip slow hosts in VPN mode
    fi
  else
    # Standard mode: already filtered to fast hosts only
    printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}\n" "$host" "$METHOD_USED" "$IP_USED" "$SPEED_DISPLAY"
  fi

  ((FOUND++))
done < "$INPUT"

printf "\r  %-70s\r" ""
echo ""
if [[ "$ANALYZE_MODE" == true ]]; then
  echo -e "${G}✓${R} Analysis complete. Found ${C}$FOUND${R} zero‑rated hosts."
  echo -e "  ${G}FREE (fast)${R}   : speed ≥ ${MIN_SPEED} KB/s"
  echo -e "  ${Y}THROTTLED${R}    : speed < ${MIN_SPEED} KB/s (ISP slowing)"
  echo -e "  ${RD}BLOCKED${R}     : TLS handshake failed (ISP blocking)"
else
  echo -e "${G}✓${R} Found: ${C}$FOUND${R} hosts (speed ≥ ${MIN_SPEED} KB/s)"
fi
exit 0
