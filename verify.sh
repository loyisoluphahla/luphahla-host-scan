#!/usr/bin/env bash
# Luphahla Scanner – Simple Zero‑Rated Host Checker
# Usage: cat hosts.txt | ./verify.sh [--timeout 3] [--method HEAD]

set -o pipefail

# Defaults
TIMEOUT=3
METHODS=("CONNECT" "POST" "HEAD" "GET")   # Order of preference

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --help) echo "Usage: cat hosts.txt | $0 [--timeout 3]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# Read stdin (skip blanks/comments)
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
if [[ $TOTAL -eq 0 ]]; then
  echo "No hosts provided." >&2
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

echo "Scanning $TOTAL hosts for zero‑rated ones..."
COUNT=0
FOUND=0

while IFS= read -r host; do
  ((COUNT++))
  printf "\rProgress: %d/%d" "$COUNT" "$TOTAL"

  # Skip if not zero‑rated
  if ! is_free "$host"; then
    continue
  fi

  # Test methods in order
  for method in "${METHODS[@]}"; do
    code=$(curl -s -k -o /dev/null -w "%{http_code}" -X "$method" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    if [[ "$code" =~ ^(200|301|302|401|405)$ ]]; then
      echo "$host → $method (zero‑rated)"
      ((FOUND++))
      break
    fi
  done
done < "$INPUT"

echo ""  # newline after progress
echo "Done. Found $FOUND zero‑rated hosts."
