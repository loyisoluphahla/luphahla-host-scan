#!/usr/bin/env bash
# Luphahla Scanner - Simple & Reliable (No parallel, no xargs)
# Usage: cat hosts.txt | ./verify.sh [--timeout 3]

set -o pipefail

# ---------- Defaults ----------
TIMEOUT=3
USE_COLOR=true

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --timeout)  TIMEOUT="$2"; shift ;;
    --no-color) USE_COLOR=false ;;
    --help|-h)  echo "Usage: cat hosts.txt | ./verify.sh [--timeout 3]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; GREEN=''; YELLOW=''; CYAN=''; WHITE=''; BRIGHT_GREEN=''; BRIGHT_CYAN=''
else
  RESET='\033[0m'; BOLD='\033[1m'; GREEN='\033[32m'; YELLOW='\033[33m'; CYAN='\033[36m'; WHITE='\033[37m'
  BRIGHT_GREEN='\033[92m'; BRIGHT_CYAN='\033[96m'
fi

# ---------- Read stdin (skip blank lines and comments) ----------
INPUT=$(mktemp)
trap 'rm -f "$INPUT"' EXIT
grep -vE '^[[:space:]]*(#|$)' > "$INPUT"
TOTAL=$(wc -l < "$INPUT")
if [ "$TOTAL" -eq 0 ]; then
  echo -e "${YELLOW}No hosts provided.${RESET}" >&2
  exit 3
fi

# ---------- Banner ----------
clear
echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║              L U P H A H L A   S C A N N E R  (Simple)          ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}Hosts:${RESET} $TOTAL  |  ${CYAN}Timeout:${RESET} ${TIMEOUT}s"
echo ""

# ---------- Zero-rated detection (based on hostname) ----------
detect_free() {
  local host="$1"
  local lower=$(echo "$host" | tr '[:upper:]' '[:lower:]')
  for pattern in google youtube facebook meta whatsapp instagram twitter x.com tesla spacex starlink netflix spotify cloudflare amazon microsoft apple icloud live outlook office bing yahoo econet netone mtn vodacom orange airtel safaricom github stackoverflow; do
    [[ "$lower" == *"$pattern"* ]] && { echo "✅ FREE"; return 0; }
  done
  echo "❓ Unknown"
}

# ---------- Scan each host ----------
echo -e "${CYAN}Scanning...${RESET}"
LINE_NUM=1
RESULTS=$(mktemp)
trap 'rm -f "$RESULTS"' EXIT

while IFS= read -r host; do
  printf "\r  ${CYAN}Progress: ${WHITE}%d/$TOTAL${RESET}" "$LINE_NUM"

  # 1. TLS handshake
  if ! timeout "$TIMEOUT" openssl s_client -connect "$host:443" -servername "$host" -verify_quiet -brief </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
    LINE_NUM=$((LINE_NUM + 1))
    continue
  fi

  # 2. Get IP, HTTP code, Server header, Speed
  output=$(curl -s -k -o /dev/null -w "%{http_code}|%{remote_ip}|%{speed_download}" -m "$TIMEOUT" "https://$host" 2>/dev/null)
  code=$(echo "$output" | cut -d'|' -f1)
  ip=$(echo "$output" | cut -d'|' -f2)
  speed_bytes=$(echo "$output" | cut -d'|' -f3)

  # Server header
  server=$(curl -s -I -k -m "$TIMEOUT" "https://$host" 2>/dev/null | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 20)
  [ -z "$server" ] && server="Unknown"

  # Speed label
  if [[ "$speed_bytes" =~ ^[0-9]+ ]] && [ "$speed_bytes" -gt 0 ]; then
    speed_kb=$((speed_bytes / 1024))
    if [ "$speed_kb" -gt 100 ]; then speed_label="⚡ ${speed_kb} KB/s"; else speed_label="🐢 ${speed_kb} KB/s"; fi
  else
    speed_label="⛔ No Data"
  fi

  # Zero-rated detection
  free_label=$(detect_free "$host")

  # Save result
  echo "${LINE_NUM}|${host}|${ip:-N/A}|443|${code:-N/A}|${server}|${speed_label}|${free_label}" >> "$RESULTS"
  LINE_NUM=$((LINE_NUM + 1))
done < "$INPUT"

echo "" # newline after progress bar

# ---------- Display table ----------
LIVECOUNT=$(wc -l < "$RESULTS")
if [ "$LIVECOUNT" -eq 0 ]; then
  echo -e "${YELLOW}No live hosts found.${RESET}"
  exit 0
fi

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║                            L I V E   H O S T S   T A B L E   (Zero‑Rated Checked)                            ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚══════════════════════════════════════════════════════════════════════════════════════════════════════════════════════╝${RESET}"
echo ""

printf "  ${BRIGHT_CYAN}%3s${RESET} | ${BRIGHT_CYAN}%-25s${RESET} | ${BRIGHT_CYAN}%-15s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%4s${RESET} | ${BRIGHT_CYAN}%-12s${RESET} | ${BRIGHT_CYAN}%-10s${RESET} | ${BRIGHT_CYAN}%-10s${RESET}\n" " # " "Host" "IP" "Port" "Code" "Server" "Speed" "Zero-Rated"
printf "  %3s | %-25s | %-15s | %4s | %4s | %-12s | %-10s | %-10s\n" "---" "-------------------------" "---------------" "----" "----" "------------" "----------" "----------"

while IFS='|' read -r num host ip port code server speed free; do
  # Color code
  if [[ "$code" =~ ^(200|301|302)$ ]]; then
    code_colored="${GREEN}${code}${RESET}"
  elif [[ "$code" == "401" ]]; then
    code_colored="${YELLOW}${code}${RESET}"
  elif [[ "$code" == "405" ]]; then
    code_colored="${CYAN}${code}${RESET}"
  else
    code_colored="${RED}${code}${RESET}"
  fi

  if [[ "$free" == *"FREE"* ]]; then
    free_colored="${BRIGHT_GREEN}✅ FREE${RESET}"
  else
    free_colored="${DIM}❓ Unknown${RESET}"
  fi

  printf "  ${YELLOW}%3s${RESET} | ${CYAN}%-25s${RESET} | ${WHITE}%-15s${RESET} | ${BRIGHT_WHITE}%4s${RESET} | ${code_colored}%4s${RESET} | ${DIM}%-12s${RESET} | %-10s | ${free_colored}\n" "$num" "$host" "$ip" "$port" "$code" "$server" "$speed" "$free"
done < "$RESULTS"

echo ""
echo -e "  ${GREEN}✓${RESET} Total live hosts: ${BRIGHT_WHITE}$LIVECOUNT${RESET}"
echo ""
exit 0
