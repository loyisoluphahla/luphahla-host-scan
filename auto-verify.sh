#!/usr/bin/env bash
# Luphahla Host Scan – ULTRA‑WIDE DISCOVERY (always deep)
# Usage: ./auto-verify.sh [--timeout 5]

set -o pipefail

# Defaults
USE_COLOR=true
TIMEOUT=5
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)

# Parse args (only --timeout remains)
while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout) TIMEOUT="$2"; shift ;;
    --help) echo "Usage: $0 [--timeout 5]"; exit 0 ;;
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
echo -e "${BG}${G}      L U P H A H L A   U L T R A - W I D E   D I S C O V E R Y    ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo -e "  ${C}Mode:${R} DEEP (top 10k domains, 20+ TLDs, brute‑force, multiple ASNs)"
echo ""

# Check network
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  echo -e "  ${G}✓${R} Online"
  ONLINE=true
else
  echo -e "  ${Y}⚠${R} Offline – using cache"
  ONLINE=false
fi

if [[ "$ONLINE" == true ]]; then
  echo -e "  ${C}●${R} Building massive target list..."

  # ============================================================
  # 1. TOP DOMAINS (10k from public list + curated)
  # ============================================================
  echo -e "  ${C}●${R} Fetching Top 10,000 domains..."
  curl -s -m 15 "https://api.hackertarget.com/topdomains/" | head -10000 >> "$FRESH_FILE"
  # Curated high‑value domains (ensure they are included)
  cat >> "$FRESH_FILE" << 'EOF'
google.com youtube.com facebook.com twitter.com x.com tesla.com spacex.com starlink.com
instagram.com whatsapp.com amazon.com microsoft.com apple.com netflix.com reddit.com
linkedin.com github.com live.com yahoo.com office.com zoom.us tiktok.com bing.com
econet.co.zw netone.co.zw telcel.co.zw mtn.co.za vodacom.co.za safaricom.co.ke
EOF

  # ============================================================
  # 2. CERTIFICATE TRANSPARENCY LOGS (20+ TLDs, 300 each)
  # ============================================================
  TLDS="com org net io app dev tv cloud zone xyz online tech co.zw co.za uk de fr jp in br au ca ru cn kr za"
  LIMIT=300
  echo -e "  ${C}●${R} Fetching CT logs (${TLDS}) – ${LIMIT} per TLD..."
  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -$LIMIT >> "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"
  echo -e "  ${G}✓${R} CT logs added."

  # ============================================================
  # 3. DNS BRUTE‑FORCE (common subdomains on top 2000 domains)
  # ============================================================
  echo -e "  ${C}●${R} DNS brute‑force (common prefixes on 2000 domains)..."
  PREFIXES="www mail api admin dev test vpn proxy cdn secure auth m mobile ws app portal dashboard static media img video stream live edge"
  grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" | head -2000 | while read -r domain; do
    for p in $PREFIXES; do
      echo "${p}.${domain}"
    done
  done >> "$FRESH_FILE"
  echo -e "  ${G}✓${R} Brute‑force prefixes added."

  # ============================================================
  # 4. ISP IP RANGES (current ASN + hardcoded major ISPs)
  # ============================================================
  echo -e "  ${C}●${R} Fetching IP ranges from multiple ASNs..."
  ASNS=("AS37356" "AS36985" "AS37365" "AS16637" "AS37148" "AS33785" "AS37278" "AS33779")  # Econet, Netone, TelOne, Liquid, MTN, Vodacom, Safaricom, Orange
  # Also detect current ASN
  CURRENT_ASN=$(curl -s -m 5 "https://ipinfo.io/org" | grep -oE 'AS[0-9]+' | head -1)
  [[ -n "$CURRENT_ASN" ]] && ASNS+=("$CURRENT_ASN")
  for asn in "${ASNS[@]}"; do
    ranges=$(curl -s -m 10 "https://ipinfo.io/${asn}" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -5)
    for cidr in $ranges; do
      mask="${cidr#*/}"
      base="${cidr%/*}"
      if [[ "$mask" -eq 24 ]]; then
        prefix="${base%.*}"
        for i in {1..254}; do echo "${prefix}.${i}"; done
      elif [[ "$mask" -eq 16 ]]; then
        prefix="${base%.*.*}"
        # only sample first /24 for speed
        for i in {0..5}; do
          for j in {1..254}; do echo "${prefix}.${i}.${j}"; done
        done
      fi
    done
  done >> "$FRESH_FILE"
  echo -e "  ${G}✓${R} ISP IP ranges added."

  # ============================================================
  # 5. PUBLIC RESOLVERS & CDN EDGE IPs
  # ============================================================
  echo -e "  ${C}●${R} Adding public resolvers and CDN IPs..."
  cat >> "$FRESH_FILE" << 'EOF'
1.1.1.1
8.8.8.8
9.9.9.9
208.67.222.222
208.67.220.220
one.one.one.one
dns.google
cloudflare-dns.com
quad9.net
opendns.com
EOF
  echo -e "  ${G}✓${R} Added public resolvers."

else
  echo -e "  ${Y}⚠${R} Offline – using cached list."
  [[ -f "$CACHE_FILE" ]] && cp "$CACHE_FILE" "$FRESH_FILE"
fi

# ============================================================
# MERGE, DEDUPLICATE, SAVE
# ============================================================
echo -e "  ${C}●${R} Merging and deduplicating..."
[[ -f "$OUTPUT_FILE" ]] && cat "$OUTPUT_FILE" >> "$FRESH_FILE"
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
