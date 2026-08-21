#!/usr/bin/env bash
# Luphahla Scanner – Speed Filtered Zero‑Rated Hosts
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--min-speed 10]

set -o pipefail

# Defaults
TIMEOUT=3
MIN_SPEED=10                  # KB/s (hosts slower than this are hidden)
METHODS=("CONNECT" "POST" "HEAD" "GET")

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --help) echo "Usage: cat hosts.txt | $0 [--timeout 3] [--min-speed 10]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# Colors
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'; W='\033[37m'

# Read stdin
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
if [[ $TOTAL -eq 0 ]]; then
  echo -e "${Y}No hosts provided.${R}" >&2
  exit 3
fi

# Zero‑rated detection (based on hostname)
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
echo -e "  ${C}Filter:${R} speed ≥ ${MIN_SPEED} KB/s"
echo ""

# Table headers
printf "  ${C}%-26s  %-10s  %-15s  %-10s${R}\n" "HOST" "METHOD" "IP" "SPEED"
printf "  %-26s  %-10s  %-15s  %-10s\n" "--------------------------" "----------" "---------------" "----------"

# Spinner chars
SPINNER=('|' '/' '-' '\')
SPIN_IDX=0

# Function to update spinner
update_spinner() {
  printf "\r  ${C}%s${R} Scanning..." "${SPINNER[SPIN_IDX]}"
  ((SPIN_IDX++))
  [[ $SPIN_IDX -ge ${#SPINNER[@]} ]] && SPIN_IDX=0
}

# Scan loop
COUNT=0
FOUND=0
while IFS= read -r host; do
  ((COUNT++))
  update_spinner

  # Skip if not zero‑rated
  if ! is_free "$host"; then
    continue
  fi

  # Test methods in order
  for method in "${METHODS[@]}"; do
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    code=$(echo "$output" | cut -d'|' -f1)
    ip=$(echo "$output" | cut -d'|' -f2)
    speed_bytes=$(echo "$output" | cut -d'|' -f3)
    [[ -z "$ip" ]] && ip="N/A"

    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      # Convert speed to KB/s
      speed_kb=0
      if [[ "$speed_bytes" =~ ^[0-9]+ ]] && (( speed_bytes > 0 )); then
        speed_kb=$((speed_bytes / 1024))
      fi

      # Only show if speed >= MIN_SPEED
      if (( speed_kb >= MIN_SPEED )); then
        # Speed label
        if (( speed_kb > 100 )); then
          speed_display="⚡${speed_kb}KB/s"
        else
          speed_display="🐢${speed_kb}KB/s"
        fi

        # Clear spinner line and print result
        printf "\r  %-60s\r" ""
        printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}  ${W}%-10s${R}\n" "$host" "$method" "$ip" "$speed_display"
        ((FOUND++))
        break
      fi
    fi
  done
done < "$INPUT"

# Final newline and summary
printf "\r  %-60s\r" ""
echo ""
echo -e "${G}✓${R} Zero‑rated hosts with speed ≥ ${MIN_SPEED} KB/s: ${C}$FOUND${R}"
