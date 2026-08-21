#!/usr/bin/env bash
# Luphahla Host Scan – Discovery Engine (Community Edition)
# Usage: ./auto-verify.sh [--timeout 5]

set -o pipefail

# Defaults
TIMEOUT=5
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"

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
R='\033[0m'; G='\033[32m'; C='\033[36m'; BG='\033[92m'

# Setup temp
mkdir -p "$TDIR"
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
: > "$FRESH_FILE"

# Banner
clear
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}      L U P H A H L A   C O M M U N I T Y   E D I T I O N        ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════${R}"
echo ""

# Network check
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  echo -e "  ${G}✓ Online${R}"
  ONLINE=true
else
  echo -e "  ${Y}⚠ Offline – using cache${R}"
  ONLINE=false
fi

if [[ "$ONLINE" == true ]]; then
  echo -e "  ${C}●${R} Building target list..."

  # ============================================================
  # 1. CORE DOMAINS – TOP 1000 (curated)
  # ============================================================
  cat >> "$FRESH_FILE" << 'EOF'
# --- Global giants ---
google.com youtube.com facebook.com twitter.com x.com tesla.com spacex.com starlink.com
instagram.com whatsapp.com amazon.com microsoft.com apple.com netflix.com reddit.com
linkedin.com github.com live.com yahoo.com office.com zoom.us tiktok.com bing.com
pinterest.com ebay.com adobe.com cnn.com bbc.com nytimes.com wsj.com ft.com
reuters.com bloomberg.com forbes.com techcrunch.com theverge.com wired.com

# --- Zimbabwe ISPs (Econet, Netone, TelOne, Liquid) ---
econet.co.zw netone.co.zw telcel.co.zw telone.co.zw liquid.co.zw
ecocash.co.zw ibills.econet.co.zw meet.econet.co.zw selfcare.econet.co.zw
apps.netone.co.zw vasapi.netone.co.zw apn.netone.co.zw orgonemoney.netone.co.zw
topup.bundles.co.zw elevateyouth.co.zw oldlock.co.zw

# --- Community KOFnet hosts ---
econetwireless.co.za econet.zigssh.com bigmunya.ooguy.com zm.goodinternet.org
www.roshan.af Mobile.etisalat.af www.mtnplay.com.af clickup.up.ac.za
general-runtime.voicemail.com mopsezw.learningpassport.unicef.org econet.net
health.go.ug www.msmehub.org www.corporate.latamairlines.com

# --- Known working IPs ---
104.26.4.145 104.18.189.228 104.26.0.242 105.29.88.77
52.128.23.163 172.67.71.141 104.21.18.87 50.62.198.70

# --- African ISPs (often zero-rated) ---
mtn.co.za vodacom.co.za safaricom.co.ke airtel.africa orange.sn
EOF

  # ============================================================
  # 2. CERTIFICATE TRANSPARENCY LOGS (common TLDs)
  # ============================================================
  TLDS="com org net co.zw co.za uk de fr jp in br au ca"
  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -100 >> "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"

  # ============================================================
  # 3. ISP IP RANGES (current ASN + common Zim ISPs)
  # ============================================================
  ASNS=("AS37356" "AS36985" "AS37365" "AS16637" "AS37148")
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
        for i in {0..5}; do
          for j in {1..254}; do echo "${prefix}.${i}.${j}"; done
        done
      fi
    done
  done >> "$FRESH_FILE"

  # ============================================================
  # 4. PUBLIC RESOLVERS & CDNS
  # ============================================================
  cat >> "$FRESH_FILE" << 'EOF'
1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 208.67.220.220
one.one.one.one dns.google cloudflare-dns.com quad9.net opendns.com
EOF

else
  # Offline – use cache if exists
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

echo -e "  ${G}✓${R} Total targets: ${C}$TOTAL${R}"
echo -e "  ${G}✓${R} Saved to ${C}$OUTPUT_FILE${R}"
echo ""
exit 0
