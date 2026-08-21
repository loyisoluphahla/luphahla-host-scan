#!/usr/bin/env bash
# Luphahla Scanner – Clean Table (BugScanX style)
# Usage: cat hosts.txt | ./verify.sh [--timeout 3]

set -o pipefail

# Defaults
TIMEOUT=3
USE_COLOR=true

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --no-color) USE_COLOR=false ;;
    --help) echo "Usage: cat hosts.txt | $0 [--timeout 3]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# Colors
if [[ "$USE_COLOR" == true ]]; then
  R='\033[0m'; B='\033[1m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; W='\033[37m'
  BG='\033[92m'; BC='\033[96m'; D='\033[2m'; RD='\033[31m'
else
  R=''; B=''; G=''; Y=''; C=''; W=''; BG=''; BC=''; D=''; RD=''
fi

# Read stdin (skip blanks/comments)
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
if [[ $TOTAL -eq 0 ]]; then
  echo -e "${Y}No hosts provided.${R}" >&2
  exit 3
fi

# Banner
clear
echo -e "${BG}${B}  ╔══════════════════════════════════════════════════════════════════╗${R}"
echo -e "${BG}${B}  ║              L U P H A H L A   S C A N N E R  (Clean)         ║${R}"
echo -e "${BG}${B}  ╚══════════════════════════════════════════════════════════════════╝${R}"
echo -e "  ${C}Hosts:${R} $TOTAL  |  ${C}Timeout:${R} ${TIMEOUT}s"
echo ""

# Zero-rated detection (based on hostname)
detect_free() {
  local h=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  for p in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow; do
    [[ "$h" == *"$p"* ]] && { echo "✅ FREE"; return 0; }
  done
  echo "❓ Unknown"
}

# Scan each host (sequential, no parallel)
echo -e "${C}Scanning...${R}"
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

COUNT=0
while IFS= read -r host; do
  ((COUNT++))
  printf "\r  ${C}Progress:${R} ${W}%d/$TOTAL${R}" "$COUNT"

  # Use curl -I to get status, IP, speed, and server header in one go
  tmp=$(mktemp)
  curl -s -k -I -w "%{http_code}|%{remote_ip}|%{speed_download}" -m "$TIMEOUT" "https://$host" > "$tmp" 2>/dev/null
  code=$(tail -n1 "$tmp" | cut -d'|' -f1)
  ip=$(tail -n1 "$tmp" | cut -d'|' -f2)
  speed_bytes=$(tail -n1 "$tmp" | cut -d'|' -f3)
  # Extract Server header from the headers (skip the last line)
  server=$(head -n -1 "$tmp" | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 20)
  rm -f "$tmp"

  # If no status code, host is dead
  [[ -z "$code" ]] && continue

  # Speed label
  if [[ "$speed_bytes" =~ ^[0-9]+ ]] && (( speed_bytes > 0 )); then
    speed_kb=$((speed_bytes / 1024))
    if (( speed_kb > 100 )); then speed_label="⚡ ${speed_kb} KB/s"; else speed_label="🐢 ${speed_kb} KB/s"; fi
  else
    speed_label="⛔ No Data"
  fi

  # Zero-rated label
  free_label=$(detect_free "$host")

  # Store result: host|ip|code|server|speed|free
  echo "$host|${ip:-N/A}|$code|${server:-Unknown}|$speed_label|$free_label" >> "$RESULTS"
done < "$INPUT"

echo ""  # newline after progress

# Count live
LIVE=$(wc -l < "$RESULTS")
if [[ $LIVE -eq 0 ]]; then
  echo -e "${Y}No live hosts found.${R}"
  exit 0
fi

# Display table
echo ""
echo -e "${BG}${B}  ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${R}"
echo -e "${BG}${B}  ║                            L I V E   H O S T S   T A B L E   (Zero‑Rated Checked)                            ║${R}"
echo -e "${BG}${B}  ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${R}"
echo ""

printf "  ${BC}%3s${R} | ${BC}%-25s${R} | ${BC}%-15s${R} | ${BC}%4s${R} | ${BC}%-12s${R} | ${BC}%-10s${R} | ${BC}%-10s${R}\n" " # " "Host" "IP" "Code" "Server" "Speed" "Zero-Rated"
printf "  %3s | %-25s | %-15s | %4s | %-12s | %-10s | %-10s\n" "---" "-------------------------" "---------------" "----" "------------" "----------" "----------"

LINE=1
while IFS='|' read -r host ip code server speed free; do
  # Color code
  if [[ "$code" =~ ^(200|301|302)$ ]]; then code_col="${G}${code}${R}"
  elif [[ "$code" == "401" ]]; then code_col="${Y}${code}${R}"
  elif [[ "$code" == "405" ]]; then code_col="${C}${code}${R}"
  else code_col="${RD}${code}${R}"
  fi

  # Color free
  [[ "$free" == "✅ FREE" ]] && free_col="${BG}✅ FREE${R}" || free_col="${D}❓ Unknown${R}"

  printf "  ${Y}%3d${R} | ${C}%-25s${R} | ${W}%-15s${R} | ${code_col}%4s${R} | ${D}%-12s${R} | %-10s | ${free_col}\n" \
    "$LINE" "$host" "$ip" "$code" "$server" "$speed" "$free"
  ((LINE++))
done < "$RESULTS"

echo ""
echo -e "  ${G}✓${R} Total live hosts: ${W}$LIVE${R}"
echo ""
