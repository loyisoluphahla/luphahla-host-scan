#!/usr/bin/env bash
# Luphahla Scanner – Final Working Version
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

# Read stdin
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
echo -e "${BG}${B}  ║              L U P H A H L A   S C A N N E R                   ║${R}"
echo -e "${BG}${B}  ╚══════════════════════════════════════════════════════════════════╝${R}"
echo -e "  ${C}Hosts:${R} $TOTAL  |  ${C}Timeout:${R} ${TIMEOUT}s"
echo ""

# Zero-rated detection
detect_free() {
  local h=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  for p in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow; do
    if [[ "$h" == *"$p"* ]]; then
      echo "FREE"
      return 0
    fi
  done
  echo "UNKNOWN"
}

# Scan
echo -e "${C}Scanning...${R}"
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

COUNT=0
while IFS= read -r host; do
  ((COUNT++))
  printf "\r  ${C}Progress:${R} ${W}%d/$TOTAL${R}" "$COUNT"

  tmp=$(mktemp)
  curl -s -k -I -w "%{http_code}|%{remote_ip}|%{speed_download}" -m "$TIMEOUT" "https://$host" > "$tmp" 2>/dev/null
  code=$(tail -n1 "$tmp" | cut -d'|' -f1)
  ip=$(tail -n1 "$tmp" | cut -d'|' -f2)
  speed_bytes=$(tail -n1 "$tmp" | cut -d'|' -f3)
  server=$(head -n -1 "$tmp" | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 18)
  rm -f "$tmp"

  [[ -z "$code" ]] && continue

  if [[ "$speed_bytes" =~ ^[0-9]+ ]] && (( speed_bytes > 0 )); then
    speed_kb=$((speed_bytes / 1024))
    if (( speed_kb > 100 )); then speed_label="⚡${speed_kb}KB/s"; else speed_label="🐢${speed_kb}KB/s"; fi
  else
    speed_label="NoData"
  fi

  free_label=$(detect_free "$host")
  echo "$host|${ip:-N/A}|$code|${server:-Unknown}|$speed_label|$free_label" >> "$RESULTS"
done < "$INPUT"

echo ""

LIVE=$(wc -l < "$RESULTS")
if [[ $LIVE -eq 0 ]]; then
  echo -e "${Y}No live hosts found.${R}"
  exit 0
fi

echo ""
echo -e "${BG}${B}  ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${R}"
echo -e "${BG}${B}  ║                            L I V E   H O S T S   T A B L E                                                   ║${R}"
echo -e "${BG}${B}  ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${R}"
echo ""

printf "  %3s | %-22s | %-14s | %4s | %-12s | %-10s | %-8s\n" " # " "Host" "IP" "Code" "Server" "Speed" "Zero"
printf "  %3s | %-22s | %-14s | %4s | %-12s | %-10s | %-8s\n" "---" "----------------------" "--------------" "----" "------------" "----------" "--------"

LINE=1
while IFS='|' read -r host ip code server speed free; do
  if [[ "$code" =~ ^(200|301|302)$ ]]; then code_c="${G}${code}${R}"
  elif [[ "$code" == "401" ]]; then code_c="${Y}${code}${R}"
  elif [[ "$code" == "405" ]]; then code_c="${C}${code}${R}"
  else code_c="${RD}${code}${R}"
  fi

  if [[ "$free" == "FREE" ]]; then free_c="${BG}✅FREE${R}"; else free_c="${D}❓UNKNOWN${R}"; fi
  host_display=$(echo "$host" | cut -c1-22)

  printf "  %3d | %-22s | %-14s | %4s | %-12s | %-10s | %-8s\n" \
    "$LINE" "$host_display" "$ip" "$code_c" "$server" "$speed" "$free_c"
  ((LINE++))
done < "$RESULTS"

echo ""
echo -e "  ${G}✓${R} Total live hosts: ${W}$LIVE${R}"
echo ""
