#!/usr/bin/env bash
# Luphahla Scanner – Zero‑Rated Host Checker
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--min-speed 10] [--vpn]

set -o pipefail

# Defaults
TIMEOUT=3
MIN_SPEED=10
VPN_MODE=false
METHODS=("CONNECT" "POST" "HEAD" "GET")

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --vpn) VPN_MODE=true ;;
    --help) echo "Usage: cat hosts.txt | $0 [--timeout 3] [--min-speed 10] [--vpn]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# If VPN mode, enforce stricter defaults (overrides user if lower)
if [[ "$VPN_MODE" == true ]]; then
  MIN_SPEED=50   # Minimum 50 KB/s for VPN
fi

# Colors
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'; W='\033[37m'
RD='\033[91m'

# Read stdin
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
[[ $TOTAL -eq 0 ]] && { echo -e "${Y}No hosts.${R}" >&2; exit 3; }

# Zero‑rated detection
is_free() {
  local h=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  for p in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow; do
    [[ "$h" == *"$p"* ]] && return 0
  done
  return 1
}

# Banner
clear
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}         L U P H A H L A   Z E R O - R A T E D   H O S T S            ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
[[ "$VPN_MODE" == true ]] && echo -e "  ${C}Mode:${R} VPN-ELIGIBLE (strict)" || echo -e "  ${C}Mode:${R} STANDARD (speed ≥ ${MIN_SPEED} KB/s)"
echo ""

# Headers
if [[ "$VPN_MODE" == true ]]; then
  printf "  ${C}%-26s  %-10s  %-15s  %-10s  %-10s  %-8s${R}\n" "HOST" "METHOD" "IP" "SPEED" "LATENCY" "STATUS"
  printf "  %-26s  %-10s  %-15s  %-10s  %-10s  %-8s\n" "--------------------------" "----------" "---------------" "----------" "----------" "--------"
else
  printf "  ${C}%-26s  %-10s  %-15s  %-10s${R}\n" "HOST" "METHOD" "IP" "SPEED"
  printf "  %-26s  %-10s  %-15s  %-10s\n" "--------------------------" "----------" "---------------" "----------"
fi

# Spinner
SPINNER=('|' '/' '-' '\')
SPIN_IDX=0
update_spinner() {
  printf "\r  ${C}%s${R} Scanning..." "${SPINNER[SPIN_IDX]}"
  ((SPIN_IDX++)); [[ $SPIN_IDX -ge ${#SPINNER[@]} ]] && SPIN_IDX=0
}

# Scan loop
COUNT=0; FOUND=0
while IFS= read -r host; do
  ((COUNT++)); update_spinner

  if ! is_free "$host"; then continue; fi

  for method in "${METHODS[@]}"; do
    # Capture code, IP, speed, latency
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}|%{time_total}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    code=$(echo "$output" | cut -d'|' -f1)
    ip=$(echo "$output" | cut -d'|' -f2)
    speed_bytes=$(echo "$output" | cut -d'|' -f3)
    latency=$(echo "$output" | cut -d'|' -f4)
    [[ -z "$ip" ]] && ip="N/A"
    [[ -z "$latency" ]] && latency="999.0"

    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      speed_kb=0
      [[ "$speed_bytes" =~ ^[0-9]+ ]] && speed_kb=$((speed_bytes / 1024))

      # VPN Mode: extra filters
      if [[ "$VPN_MODE" == true ]]; then
        # Must have CONNECT method (if method is CONNECT, priority given)
        if [[ "$method" != "CONNECT" ]]; then
          # Only allow CONNECT for VPN, skip others
          continue
        fi
        # Speed filter
        (( speed_kb < MIN_SPEED )) && continue
        # Latency filter
        (( $(echo "$latency > 1.5" | bc -l) )) && continue
        # Server header filter
        server=$(curl -s -I -k -m 2 "https://$host" 2>/dev/null | grep -i "^Server:" | head -1)
        [[ -z "$server" || "$server" == *"Unknown"* ]] && continue
        status="✅ PASS"
      else
        status=""
        (( speed_kb < MIN_SPEED )) && continue
      fi

      # Speed display
      if (( speed_kb > 100 )); then speed_display="⚡${speed_kb}KB/s"; else speed_display="🐢${speed_kb}KB/s"; fi
      latency_display=$(printf "%.2f" "$latency")s

      printf "\r  %-70s\r" ""
      if [[ "$VPN_MODE" == true ]]; then
        printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${W}%-10s${R}  ${G}%-8s${R}\n" "$host" "$method" "$ip" "$speed_display" "$latency_display" "$status"
      else
        printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}\n" "$host" "$method" "$ip" "$speed_display"
      fi
      ((FOUND++))
      break
    fi
  done
done < "$INPUT"

printf "\r  %-70s\r" ""
echo ""
echo -e "${G}✓${R} Found: ${C}$FOUND${R} hosts"
[[ "$VPN_MODE" == true ]] && echo -e "  ${C}VPN-ELIGIBLE criteria:${R} speed ≥ 50 KB/s, latency ≤ 1.5s, CONNECT method, valid Server header."
exit 0
