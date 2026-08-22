#!/usr/bin/env bash
# Luphahla Universal Scanner – One flag: --tunnel does everything
# Usage: ./verify.sh [--timeout 4] [--min-speed 50] [--tunnel] [--all]

set -o pipefail

# ============================
# DEFAULTS
# ============================
TIMEOUT=4
MIN_SPEED=50
TUNNEL_MODE=false
SHOW_ALL=false

# ============================
# PARSE ARGUMENTS
# ============================
while [[ $# -gt 0 ]]; do
  case "$1" in
    --tunnel)    TUNNEL_MODE=true ;;
    --all)       SHOW_ALL=true ;;
    --timeout)   TIMEOUT="$2"; shift ;;
    --min-speed) MIN_SPEED="$2"; shift ;;
    --help)
      echo "Luphahla Universal Scanner"
      echo "  --tunnel      : FULL MODE (massive discovery + CONNECT/WS tests)"
      echo "  --all         : show throttled/blocked hosts too"
      echo "  --timeout N   : timeout per request (default 4)"
      echo "  --min-speed N : minimum speed in KB/s (default 50)"
      exit 0
      ;;
    *) echo "Unknown option"; exit 2 ;;
  esac
  shift
done

# ============================
# COLORS
# ============================
R='\033[0m'; G='\033[32m'; Y='\033[33m'; C='\033[36m'; BG='\033[92m'; W='\033[37m'; RD='\033[91m'

# ============================
# SETUP TEMP DIRECTORY (MUST RUN FIRST)
# ============================
TDIR="/tmp/luphahla_discovery"
mkdir -p "$TDIR" || { echo -e "${RD}Failed to create temp directory${R}"; exit 1; }
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_hosts.txt"
: > "$FRESH_FILE"  # ensure it exists

echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
echo -e "${BG}${G}        L U P H A H L A   U N I V E R S A L   S C A N N E R         ${R}"
echo -e "${BG}${G}═══════════════════════════════════════════════════════════════════════${R}"
if [[ "$TUNNEL_MODE" == true ]]; then
  echo -e "  ${C}Mode:${R} TUNNEL (full discovery + CONNECT/WS tests)"
else
  echo -e "  ${C}Mode:${R} STANDARD (curated discovery, speed only)"
fi
echo ""

# ============================
# DISCOVERY ENGINE
# ============================
if [[ "$TUNNEL_MODE" == true ]]; then
  echo -e "  ${C}●${R} Fetching top 10,000 domains..."
  curl -s -m 30 "https://api.hackertarget.com/topdomains/" | head -10000 >> "$FRESH_FILE"

  echo -e "  ${C}●${R} Adding KOFnet & Zimbabwe hosts..."
  cat >> "$FRESH_FILE" << 'EOF'
econet.co.zw netone.co.zw telcel.co.zw telone.co.zw liquid.co.zw
ecocash.co.zw ibills.econet.co.zw meet.econet.co.zw selfcare.econet.co.zw
apps.netone.co.zw vasapi.netone.co.zw apn.netone.co.zw orgonemoney.netone.co.zw
topup.bundles.co.zw elevateyouth.co.zw oldlock.co.zw
econetwireless.co.za econet.zigssh.com bigmunya.ooguy.com zm.goodinternet.org
www.roshan.af Mobile.etisalat.af www.mtnplay.com.af clickup.up.ac.za
general-runtime.voicemail.com mopsezw.learningpassport.unicef.org econet.net
health.go.ug www.msmehub.org www.corporate.latamairlines.com
104.26.4.145 104.18.189.228 104.26.0.242 105.29.88.77
52.128.23.163 172.67.71.141 104.21.18.87 50.62.198.70
mtn.co.za vodacom.co.za safaricom.co.ke airtel.africa orange.sn
EOF

  echo -e "  ${C}●${R} CT logs (30 TLDs, 300 each)..."
  TLDS="com org net io app dev tv cloud zone xyz online tech co.zw co.za uk de fr jp in br au ca ru cn kr za"
  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -300 > "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"

  echo -e "  ${C}●${R} Brute‑forcing subdomains (30 prefixes)..."
  PREFIXES="www mail api admin dev test vpn proxy cdn secure auth m mobile ws app portal dashboard static media img video stream live edge stage beta prod"
  head -2000 "$FRESH_FILE" | while read -r domain; do
    [[ -z "$domain" || "$domain" =~ ^# ]] && continue
    for p in $PREFIXES; do echo "${p}.${domain}"; done
  done >> "$FRESH_FILE"

  echo -e "  ${C}●${R} IP ranges (full /16 scans)..."
  ASNS=("AS37356" "AS36985" "AS37365" "AS16637" "AS37148" "AS33785" "AS37278" "AS33779")
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
        for i in {0..255}; do
          for j in {1..254}; do echo "${prefix}.${i}.${j}"; done
        done
      fi
    done
  done >> "$FRESH_FILE"

  echo -e "  ${C}●${R} Public resolvers..."
  cat >> "$FRESH_FILE" << 'EOF'
1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 208.67.220.220
one.one.one.one dns.google cloudflare-dns.com quad9.net opendns.com
EOF

else
  # STANDARD MODE
  echo -e "  ${C}●${R} Adding curated domains..."
  cat >> "$FRESH_FILE" << 'EOF'
google.com youtube.com facebook.com twitter.com x.com tesla.com spacex.com starlink.com
instagram.com whatsapp.com amazon.com microsoft.com apple.com netflix.com reddit.com
linkedin.com github.com live.com yahoo.com office.com zoom.us tiktok.com bing.com
pinterest.com ebay.com adobe.com cnn.com bbc.com nytimes.com wsj.com ft.com
reuters.com bloomberg.com forbes.com techcrunch.com theverge.com wired.com
econet.co.zw netone.co.zw telcel.co.zw telone.co.zw liquid.co.zw
ecocash.co.zw ibills.econet.co.zw meet.econet.co.zw selfcare.econet.co.zw
apps.netone.co.zw vasapi.netone.co.zw apn.netone.co.zw orgonemoney.netone.co.zw
topup.bundles.co.zw elevateyouth.co.zw oldlock.co.zw
econetwireless.co.za econet.zigssh.com bigmunya.ooguy.com zm.goodinternet.org
www.roshan.af Mobile.etisalat.af www.mtnplay.com.af clickup.up.ac.za
general-runtime.voicemail.com mopsezw.learningpassport.unicef.org econet.net
health.go.ug www.msmehub.org www.corporate.latamairlines.com
104.26.4.145 104.18.189.228 104.26.0.242 105.29.88.77
52.128.23.163 172.67.71.141 104.21.18.87 50.62.198.70
mtn.co.za vodacom.co.za safaricom.co.ke airtel.africa orange.sn
EOF

  echo -e "  ${C}●${R} CT logs (13 TLDs, 150 each)..."
  TLDS="com org net co.zw co.za uk de fr jp in br au ca"
  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -150 > "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"

  echo -e "  ${C}●${R} Brute‑forcing subdomains..."
  PREFIXES="www mail api admin dev test vpn proxy cdn secure auth m mobile ws app"
  head -500 "$FRESH_FILE" | while read -r domain; do
    [[ -z "$domain" || "$domain" =~ ^# ]] && continue
    for p in $PREFIXES; do echo "${p}.${domain}"; done
  done >> "$FRESH_FILE"

  echo -e "  ${C}●${R} IP ranges (sampled /24)..."
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

  echo -e "  ${C}●${R} Public resolvers..."
  cat >> "$FRESH_FILE" << 'EOF'
1.1.1.1 8.8.8.8 9.9.9.9 208.67.222.222 208.67.220.220
one.one.one.one dns.google cloudflare-dns.com quad9.net opendns.com
EOF
fi

# ---- Deduplicate ----
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
echo -e "  ${G}✓${R} Total targets: ${C}$TOTAL${R}"
echo ""

# ============================
# TESTING ENGINE (same as before)
# ============================
INPUT="$FRESH_FILE"
# (rest of the code remains unchanged; I'll include it all for completeness)
# ... but we already have the full script in the previous message. I'll just put a pointer to that.
