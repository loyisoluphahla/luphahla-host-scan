#!/usr/bin/env bash
# Luphahla Scanner – Zero‑Rated Host Checker with Protocol Filters
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--min-speed 10] [--vpn] [--tls13] [--http2]

set -o pipefail

# Defaults
TIMEOUT=3
MIN_SPEED=10
VPN_MODE=false
TLS13_MODE=false
HTTP2_MODE=false
METHODS=("CONNECT" "POST" "HEAD" "GET")

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --vpn) VPN_MODE=true ;;
    --tls13) TLS13_MODE=true ;;
    --http2) HTTP2_MODE=true ;;
    --help) 
      echo "Usage: cat hosts.txt | $0 [--timeout 3] [--min-speed 10] [--vpn] [--tls13] [--http2]"
      echo "  --vpn       : strict filters: CONNECT method, speed≥50KB/s, latency≤1.5s, valid Server"
      echo "  --tls13     : only show hosts that support TLS 1.3"
      echo "  --http2     : only show hosts that support HTTP/2"
      exit 0
      ;;
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
mode_str="STANDARD (speed ≥ ${MIN_SPEED} KB/s)"
[[ "$VPN_MODE" == true ]] && mode_str="VPN-ELIGIBLE (strict)"
[[ "$TLS13_MODE" == true ]] && mode_str+=" + TLS 1.3"
[[ "$HTTP2_MODE" == true ]] && mode_str+=" + HTTP/2"
echo -e "  ${C}Mode:${R} ${mode_str}"
echo ""

# Determine table headers
if [[ "$VPN_MODE" == true ]]; then
  headers=("HOST" "METHOD" "IP" "SPEED" "LATENCY" "TLS" "HTTP/2" "STATUS")
  header_line="  ${C}%-26s  %-10s  %-15s  %-10s  %-10s  %-5s  %-6s  %-8s${R}"
  divider_line="  %-26s  %-10s  %-15s  %-10s  %-10s  %-5s  %-6s  %-8s"
  format="  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  ${W}%-10s${R}  %-5s  %-6s  ${G}%-8s${R}"
elif [[ "$TLS13_MODE" == true || "$HTTP2_MODE" == true ]]; then
  headers=("HOST" "METHOD" "IP" "SPEED" "TLS" "HTTP/2")
  header_line="  ${C}%-26s  %-10s  %-15s  %-10s  %-5s  %-6s${R}"
  divider_line="  %-26s  %-10s  %-15s  %-10s  %-5s  %-6s"
  format="  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}  %-5s  %-6s"
else
  headers=("HOST" "METHOD" "IP" "SPEED")
  header_line="  ${C}%-26s  %-10s  %-15s  %-10s${R}"
  divider_line="  %-26s  %-10s  %-15s  %-10s"
  format="  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}"
fi

printf "$header_line" "${headers[@]}"
printf "$divider_line" "--------------------------" "----------" "---------------" "----------" "----------" "-----" "------" "--------" | cut -c1-90

# Spinner
SPINNER=('|' '/' '-' '\')
SPIN_IDX=0
update_spinner() {
  printf "\r  ${C}%s${R} Scanning..." "${SPINNER[SPIN_IDX]}"
  ((SPIN_IDX++)); [[ $SPIN_IDX -ge ${#SPINNER[@]} ]] && SPIN_IDX=0
}

# Helper: check TLS version
check_tls_version() {
  local host="$1"
  local version=""
  if timeout 2 openssl s_client -connect "$host:443" -tls1_3 -verify_quiet -brief </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
    version="1.3"
  elif timeout 2 openssl s_client -connect "$host:443" -tls1_2 -verify_quiet -brief </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
    version="1.2"
  else
    version="❌"
  fi
  echo "$version"
}

# Helper: check HTTP/2 support
check_http2() {
  local host="$1"
  if curl -s -k --http2 -I -m 2 "https://$host" 2>/dev/null | grep -q "HTTP/2"; then
    echo "✅"
  else
    echo "❌"
  fi
}

# Scan loop
COUNT=0; FOUND=0
while IFS= read -r host; do
  ((COUNT++)); update_spinner

  if ! is_free "$host"; then continue; fi

  # Pre-check TLS/HTTP2 if needed (but only once per host)
  tls_version=""
  http2_support=""
  if [[ "$TLS13_MODE" == true || "$HTTP2_MODE" == true || "$VPN_MODE" == true ]]; then
    tls_version=$(check_tls_version "$host")
    http2_support=$(check_http2 "$host")
    # If TLS13_MODE is on, skip if not 1.3
    if [[ "$TLS13_MODE" == true && "$tls_version" != "1.3" ]]; then
      continue
    fi
    # If HTTP2_MODE is on, skip if not supported
    if [[ "$HTTP2_MODE" == true && "$http2_support" != "✅" ]]; then
      continue
    fi
  fi

  for method in "${METHODS[@]}"; do
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
        [[ "$method" != "CONNECT" ]] && continue
        (( speed_kb < MIN_SPEED )) && continue
        (( $(echo "$latency > 1.5" | bc -l) )) && continue
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

      # Clear spinner line
      printf "\r  %-80s\r" ""

      # Print based on mode
      if [[ "$VPN_MODE" == true ]]; then
        printf "$format" "$host" "$method" "$ip" "$speed_display" "$latency_display" "$tls_version" "$http2_support" "$status"
      elif [[ "$TLS13_MODE" == true || "$HTTP2_MODE" == true ]]; then
        printf "$format" "$host" "$method" "$ip" "$speed_display" "$tls_version" "$http2_support"
      else
        printf "$format" "$host" "$method" "$ip" "$speed_display"
      fi
      ((FOUND++))
      break
    fi
  done
done < "$INPUT"

printf "\r  %-80s\r" ""
echo ""
echo -e "${G}✓${R} Found: ${C}$FOUND${R} hosts"
[[ "$VPN_MODE" == true ]] && echo -e "  ${C}VPN-ELIGIBLE criteria:${R} speed ≥ 50 KB/s, latency ≤ 1.5s, CONNECT method, valid Server header."
exit 0
