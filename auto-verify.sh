#!/usr/bin/env bash
# Luphahla Host Scan – Discovery Engine
# Usage: ./auto-verify.sh [--deep] [--timeout 4]

set -o pipefail

# Defaults
USE_COLOR=true
TIMEOUT=4
DEEP_MODE=false
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --deep) DEEP_MODE=true ;;
    --timeout) TIMEOUT="$2"; shift ;;
    --help) echo "Usage: $0 [--deep] [--timeout 4]"; exit 0 ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# Colors
if [[ "$USE_COLOR" == true ]]; then
  R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'
else
  R=''; G=''; Y=''; C=''; BG=''
fi

# Setup temp
mkdir -p "$TDIR"
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
: > "$FRESH_FILE"

# Banner
clear
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}         L U P H A H L A   D I S C O V E R Y   E N G I N E        ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
[[ "$DEEP_MODE" == true ]] && echo -e "  ${C}Mode:${R} DEEP (wider scan)" || echo -e "  ${C}Mode:${R} STANDARD"
echo ""

# Network check
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  echo -e "  ${G}✓${R} Online"
  ONLINE=true
else
  echo -e "  ${Y}⚠${R} Offline – using cache"
  ONLINE=false
fi

if [[ "$ONLINE" == true ]]; then
  echo -e "  ${C}●${R} Building target list..."

  # 1. Top domains (200 standard, or fetch 10k if deep)
  if [[ "$DEEP_MODE" == true ]]; then
    echo -e "  ${C}●${R} Fetching Top 10,000 domains (deep mode)..."
    curl -s -m 15 "https://api.hackertarget.com/topdomains/" | head -10000 >> "$FRESH_FILE"
    # Also add a few curated high-value domains
    cat >> "$FRESH_FILE" << 'EOF'
google.com youtube.com facebook.com x.com tesla.com spacex.com starlink.com
econet.co.zw netone.co.zw telcel.co.zw mtn.co.za vodacom.co.za safaricom.co.ke
EOF
  else
    echo -e "  ${C}●${R} Adding top 200 domains..."
    cat >> "$FRESH_FILE" << 'EOF'
google.com youtube.com facebook.com twitter.com x.com tesla.com spacex.com starlink.com
instagram.com whatsapp.com amazon.com microsoft.com apple.com netflix.com reddit.com
linkedin.com github.com live.com yahoo.com office.com zoom.us tiktok.com bing.com
pinterest.com ebay.com adobe.com cnn.com bbc.com nytimes.com wsj.com ft.com
reuters.com bloomberg.com forbes.com techcrunch.com theverge.com wired.com
econet.co.zw netone.co.zw telcel.co.zw mtn.co.za vodacom.co.za safaricom.co.ke
EOF
  fi

  # 2. CT Logs (expand TLDs and depth if deep)
  if [[ "$DEEP_MODE" == true ]]; then
    TLDS="com org net io app dev tv cloud zone xyz online tech co.zw co.za uk de fr jp in br au ca"
    LIMIT=200
    echo -e "  ${C}●${R} Deep CT logs (${LIMIT} per TLD)..."
  else
    TLDS="com org net co.zw co.za uk de fr jp in br au ca"
    LIMIT=50
    echo -e "  ${C}●${R} Standard CT logs (${LIMIT} per TLD)..."
  fi

  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -$LIMIT >> "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"
  echo -e "  ${G}✓${R} CT logs added."

  # 3. DNS Brute‑Force (only in deep mode)
  if [[ "$DEEP_MODE" == true ]]; then
    echo -e "  ${C}●${R} DNS Brute‑Force (common prefixes)..."
    PREFIXES="www mail api admin dev test vpn proxy cdn secure auth m mobile ws app"
    # Take existing domains and add prefixes
    grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" | head -500 | while read -r domain; do
      for p in $PREFIXES; do
        echo "${p}.${domain}"
      done
    done >> "$FRESH_FILE"
    echo -e "  ${G}✓${R} Brute‑force prefixes added."
  fi

  # 4. ISP IP ranges (standard is /24, deep adds /16 sampling)
  echo -e "  ${C}●${R} Adding ISP IP ranges..."
  CURRENT_ASN=$(curl -s -m 5 "https://ipinfo.io/org" | grep -oE 'AS[0-9]+' | head -1)
  if [[ -n "$CURRENT_ASN" ]]; then
    if [[ "$DEEP_MODE" == true ]]; then
      RANGES=$(curl -s -m 10 "https://ipinfo.io/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | grep -E '/(16|24)' | head -10)
    else
      RANGES=$(curl -s -m 10 "https://ipinfo.io/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | grep '/24' | head -3)
    fi
    if [[ -n "$RANGES" ]]; then
      echo "$RANGES" | while read -r cidr; do
        local prefix="${cidr%/*}"
        prefix="${prefix%.*}"
        for i in {1..254}; do echo "${prefix}.${i}"; done
      done >> "$FRESH_FILE"
      echo -e "  ${G}✓${R} ISP IPs added."
    fi
  fi
else
  echo -e "  ${Y}⚠${R} Offline – using cached list."
  [[ -f "$CACHE_FILE" ]] && cp "$CACHE_FILE" "$FRESH_FILE"
fi

# Merge with existing output
[[ -f "$OUTPUT_FILE" ]] && cat "$OUTPUT_FILE" >> "$FRESH_FILE"

# Deduplicate and save
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
cp "$FRESH_FILE" "$OUTPUT_FILE"
cp "$FRESH_FILE" "$CACHE_FILE"

echo ""
echo -e "  ${G}✓${R} Total targets: ${C}$TOTAL${R}"
echo -e "  ${G}✓${R} Saved to ${C}$OUTPUT_FILE${R}"
echo ""
exit 0
