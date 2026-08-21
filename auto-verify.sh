#!/usr/bin/env bash
# Luphahla Host Scan 
# Generates a clean host list.

set -o pipefail

# ---------- Portable timeout ----------
if command -v timeout >/dev/null 2>&1; then
  _timeout() { timeout "$@"; }
elif command -v gtimeout >/dev/null 2>&1; then
  _timeout() { gtimeout "$@"; }
else
  _timeout() {
    local secs="$1"; shift
    ( "$@" ) &
    local pid=$!
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) &
    wait "$pid" 2>/dev/null
    return $?
  }
fi

# ---------- Defaults ----------
USE_COLOR=true
TIMEOUT=4
PARALLEL=3
BATCH_SIZE=200
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --batch)         BATCH_SIZE="$2"; shift ;;
    --help|-h)
      echo "Luphahla Simple Discovery"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; WHITE=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; WHITE='\033[37m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'
fi

# ---------- Setup temp dirs ----------
mkdir -p "$TDIR" || { echo -e "${RED}Error: Could not create $TDIR${RESET}" >&2; exit 1; }
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
: > "$FRESH_FILE"

# ---------- Banner ----------
[ -t 1 ] && clear
echo -e "${BRIGHT_RED}${BOLD}"
echo "  ██╗     ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗  "
echo "  ██║     ██║   ██║██╔══██╗██║  ██║██╔══██╗██║  ██║██║     ██╔══██╗ "
echo "  ██║     ██║   ██║██████╔╝███████║███████║███████║██║     ███████║ "
echo "  ██║     ██║   ██║██╔═══╝ ██╔══██║██╔══██║██╔══██║██║     ██╔══██║ "
echo "  ███████╗╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║███████╗██║  ██║ "
echo "  ╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝ "
echo -e "${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}          S I M P L E   D I S C O V E R Y   (with Elon)   📡${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Parallel:${RESET} ${BRIGHT_WHITE}$PARALLEL${RESET}  ${YELLOW}Batch:${RESET} ${BRIGHT_WHITE}$BATCH_SIZE${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo ""

# ---------- Network Check ----------
ONLINE=false
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  ONLINE=true
  echo -e "  ${GREEN}✓ Network: ONLINE${RESET}"
else
  echo -e "  ${RED}✗ Network: OFFLINE (using cache)${RESET}"
fi

# ---------- Build list ----------
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Building target list ──${RESET}"

if [ "$ONLINE" = true ]; then
  # Top 200 Domains (including Elon's)
  echo -e "  ${CYAN}●${RESET} Adding top 200 domains..."
  cat >> "$FRESH_FILE" << 'EOF'
google.com
youtube.com
facebook.com
twitter.com
x.com
tesla.com
spacex.com
starlink.com
neuralink.com
boringcompany.com
x.ai
instagram.com
whatsapp.com
amazon.com
microsoft.com
apple.com
netflix.com
reddit.com
linkedin.com
github.com
live.com
yahoo.com
office.com
zoom.us
tiktok.com
bing.com
pinterest.com
ebay.com
adobe.com
cnn.com
bbc.com
nytimes.com
wsj.com
ft.com
reuters.com
bloomberg.com
forbes.com
techcrunch.com
theverge.com
wired.com
mashable.com
buzzfeed.com
vice.com
vox.com
economist.com
nature.com
nasa.gov
space.com
weather.com
imdb.com
spotify.com
soundcloud.com
twitch.tv
discord.com
slack.com
gmail.com
outlook.com
protonmail.com
icloud.com
dropbox.com
onedrive.com
wix.com
squarespace.com
wordpress.com
medium.com
substack.com
dribbble.com
behance.net
flickr.com
imgur.com
giphy.com
vimeo.com
kickstarter.com
patreon.com
change.org
un.org
who.int
cdc.gov
nih.gov
gov.uk
canada.ca
mcdonalds.com
starbucks.com
tesco.com
walmart.com
target.com
costco.com
chase.com
wellsfargo.com
bankofamerica.com
citibank.com
hsbc.com
barclays.co.uk
lloydsbank.co.uk
standardbank.co.za
absa.co.za
capitecbank.co.za
equitybank.co.ke
kcb.co.ke
verizon.com
att.com
tmobile.com
vodafone.com
orange.com
econet.co.zw
netone.co.zw
telcel.co.zw
mtn.co.za
safaricom.co.ke
airtel.africa
expedia.com
booking.com
airbnb.com
tripadvisor.com
kayak.com
delta.com
emirates.com
lufthansa.com
ford.com
toyota.com
bmw.com
mercedes-benz.com
intel.com
amd.com
nvidia.com
samsung.com
sony.com
huawei.com
xiaomi.com
mastodon.social
hulu.com
hbomax.com
disneyplus.com
aws.amazon.com
azure.microsoft.com
cloud.google.com
digitalocean.com
vultr.com
namecheap.com
godaddy.com
khanacademy.org
coursera.org
udemy.com
duolingo.com
webmd.com
mayoclinic.org
steampowered.com
epicgames.com
playstation.com
xbox.com
aljazeera.com
ndtv.com
timesofindia.indiatimes.com
scmp.com
herald.co.zw
chronicle.co.zw
newsday.co.zw
zbc.co.zw
technomag.co.zw
EOF
  echo -e "  ${GREEN}✓${RESET} Added 200 domains (including Elon's)."

  # CT Logs (limited to 50 per TLD)
  echo -e "  ${CYAN}●${RESET} Fetching CT logs (50 per TLD)..."
  TLDS="com org net co.zw co.za uk de fr jp in br au ca"
  for tld in $TLDS; do
    curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -50 >> "$TDIR/ct_${tld}.txt"
  done
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"
  echo -e "  ${GREEN}✓${RESET} Added CT log subdomains."

  # ISP IP ranges (/24 only)
  echo -e "  ${CYAN}●${RESET} Adding ISP IP ranges (/24 only)..."
  CURRENT_ASN=$(curl -s -m 5 "https://ipinfo.io/org" | grep -oE 'AS[0-9]+' | head -1)
  if [ -n "$CURRENT_ASN" ]; then
    RANGES=$(curl -s -m 10 "https://ipinfo.io/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | grep '/24' | head -3)
    if [ -n "$RANGES" ]; then
      echo "$RANGES" | while read -r cidr; do
        local prefix="${cidr%/*}"
        prefix="${prefix%.*}"
        for i in $(seq 1 254); do echo "${prefix}.${i}"; done
      done >> "$FRESH_FILE"
      echo -e "  ${GREEN}✓${RESET} Added ISP IPs."
    fi
  else
    echo -e "  ${DIM}   ↳ No ASN detected, skipping IPs.${RESET}"
  fi
else
  echo -e "  ${YELLOW}⚠ Offline. Using cache/backup.${RESET}"
  if [ -f "$CACHE_FILE" ]; then
    cp "$CACHE_FILE" "$FRESH_FILE"
  elif [ -f "$OUTPUT_FILE" ]; then
    cp "$OUTPUT_FILE" "$FRESH_FILE"
  else
    echo "google.com facebook.com youtube.com x.com tesla.com" > "$FRESH_FILE"
  fi
fi

# ---------- Merge with existing output ----------
if [ -f "$OUTPUT_FILE" ]; then
  echo -e "  ${DIM}● Merging with existing saved hosts...${RESET}"
  cat "$OUTPUT_FILE" >> "$FRESH_FILE"
fi

# ---------- Deduplicate and save ----------
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
cp "$FRESH_FILE" "$OUTPUT_FILE"
cp "$FRESH_FILE" "$CACHE_FILE"

echo -e "  ${GREEN}✓${RESET} Total targets: ${BRIGHT_CYAN}$TOTAL${RESET}"
echo -e "  ${GREEN}✓${RESET} Saved to ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
echo ""
exit 0
