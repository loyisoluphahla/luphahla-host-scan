#!/usr/bin/env bash
# Luphahla Scanner – Zero‑Rated Host Checker
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--min-speed 50] [--vpn]

set -o pipefail

# ============================
# DEFAULTS (50 KB/s minimum)
# ============================
TIMEOUT=3
MIN_SPEED=50                # Default is now 50 KB/s
VPN_MODE=false
METHODS=("CONNECT" "POST" "HEAD" "GET")

# ============================
# PARSE ARGUMENTS
# ============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout)   TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --vpn)       VPN_MODE=true ;;
    --help)
      echo "Usage: cat hosts.txt | $0 [--timeout 3] [--min-speed 50] [--vpn]"
      echo "  --min-speed : minimum speed in KB/s (default 50)"
      echo "  --vpn       : enforce CONNECT method, latency ≤1.5s, valid Server header"
      exit 0
      ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# ============================
# COLORS
# ============================
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'; W='\033[37m'

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
[[ "$VPN_MODE" == true ]] && echo -e "  ${C}Mode:${R} VPN-ELIGIBLE (strict)" || echo -e "  ${C}Mode:${R} STANDARD (speed ≥ ${MIN_SPEED} KB/s)"
echo ""

# ============================
# TABLE HEADERS
# ============================
if [[ "$VPN_MODE" == true ]]; then
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

  for method in "${METHODS[@]}"; do
    # curl: get code, IP, speed, latency
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}|%{time_total}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    code=$(echo "$output" | cut -d'|' -f1)
    ip=$(echo "$output" | cut -d'|' -f2)
    speed_bytes=$(echo "$output" | cut -d'|' -f3)
    latency=$(echo "$output" | cut -d'|' -f4)
    [[ -z "$ip" ]] && ip="N/A"
    [[ -z "$latency" ]] && latency="999.0"

    # Valid HTTP response?
    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      speed_kb=0
      [[ "$speed_bytes" =~ ^[0-9]+ ]] && speed_kb=$((speed_bytes / 1024))

      # ---- Speed filter ----
      (( speed_kb < MIN_SPEED )) && continue

      # ---- VPN mode extra filters ----
      if [[ "$VPN_MODE" == true ]]; then
        # Must be CONNECT method
        [[ "$method" != "CONNECT" ]] && continue
        # Latency ≤ 1.5s
        (( $(echo "$latency > 1.5" | bc -l) )) && continue
        # Server header must exist and not be "Unknown"
        server=$(curl -s -I -k -m 2 "https://$host" 2>/dev/null | grep -i "^Server:" | head -1)
        [[ -z "$server" || "$server" == *"Unknown"* ]] && continue
        status="✅ PASS"
      else
        status=""
      fi

      # Speed display with emoji
      if (( speed_kb > 100 )); then speed_display="⚡${speed_kb}KB/s"; else speed_display="🐢${speed_kb}KB/s"; fi
      latency_display=$(printf "%.2f" "$latency")s

      # Clear spinner line
      printf "\r  %-70s\r" ""

      # Print table row
      if [[ "$VPN_MODE" == true ]]; then
        printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${W}%-10s${R}  ${G}%-8s${R}\n" "$host" "$method" "$ip" "$speed_display" "$latency_display" "$status"
      else
        printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}\n" "$host" "$method" "$ip" "$speed_display"
      fi
      ((FOUND++))
      break   # stop after first successful method
    fi
  done
done < "$INPUT"

printf "\r  %-70s\r" ""
echo ""
echo -e "${G}✓${R} Found: ${C}$FOUND${R} hosts (speed ≥ ${MIN_SPEED} KB/s)"
[[ "$VPN_MODE" == true ]] && echo -e "  ${C}VPN-ELIGIBLE criteria:${R} CONNECT method, latency ≤ 1.5s, valid Server header."
exit 0
