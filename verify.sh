#!/usr/bin/env bash
# Luphahla Scanner – Simple Table with Spinner
# Usage: cat hosts.txt | ./verify.sh [--timeout 3]

set -o pipefail

# Defaults
TIMEOUT=3
METHODS=("CONNECT" "POST" "HEAD" "GET")

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --help) echo "Usage: cat hosts.txt | $0 [--timeout 3]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# Colors
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'

# Read stdin
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
if [[ $TOTAL -eq 0 ]]; then
  echo -e "${Y}No hosts provided.${R}" >&2
  exit 3
fi

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
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}         L U P H A H L A   Z E R O - R A T E D   H O S T S        ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo ""

# Table headers
printf "  ${C}%-26s  %-10s  %-15s${R}\n" "HOST" "METHOD" "IP"
printf "  %-26s  %-10s  %-15s\n" "--------------------------" "----------" "---------------"

# Spinner chars
SPINNER=('|' '/' '-' '\')
SPIN_IDX=0

# Function to update spinner (prints over the same line)
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
    output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    code=$(echo "$output" | cut -d'|' -f1)
    ip=$(echo "$output" | cut -d'|' -f2)
    [[ -z "$ip" ]] && ip="N/A"
    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      # Clear the spinner line before printing the result
      printf "\r  %-50s\r" ""
      printf "  ${G}%-26s${R}  ${Y}%-10s${R}  ${C}%-15s${R}\n" "$host" "$method" "$ip"
      ((FOUND++))
      break
    fi
  done
done < "$INPUT"

# Final newline and summary
printf "\r  %-50s\r" ""
echo ""
echo -e "${G}✓${R} Total zero‑rated hosts found: ${C}$FOUND${R}"
