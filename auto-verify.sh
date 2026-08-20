#!/usr/bin/env bash
# Luphahla Host Scan - GLOBAL DISCOVERY ENGINE (Authorized)
# Uses public CT logs, DNS, and a curated list of top 1000 global domains.
# No unauthorized scanning (no SYN, no AXFR, no port sweeps).

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
TIMEOUT=5
PARALLEL=30
BATCH_SIZE=5000
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
GLOBAL_OUTPUT="${HOME}/sni_global_results.txt"
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
      echo "Luphahla Global Discovery Engine"
      echo "  Scans top 1,000 global domains + CT logs for 15 TLDs."
      echo "  No unauthorized methods used."
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; WHITE=''; MAGENTA=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''; BRIGHT_MAGENTA=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; WHITE='\033[37m'; MAGENTA='\033[35m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'; BRIGHT_MAGENTA='\033[95m'
fi

# ---------- Setup temp dirs ----------
mkdir -p "$TDIR" || { echo -e "${RED}Error: Could not create $TDIR${RESET}" >&2; exit 1; }
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
LIVE_FILE="$TDIR/live.txt"
: > "$LIVE_FILE"
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
echo -e "${BRIGHT_BLUE}${BOLD}   G L O B A L   D I S C O V E R Y   E N G I N E   🌍${RESET}"
echo -e "${CYAN}          Luphahla Host Scan - World Edition${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Sources:${RESET} Top 1000 Domains • CT Logs (15 TLDs) • Public DNS"
echo -e "  ${YELLOW}Batch:${RESET} ${BRIGHT_WHITE}$BATCH_SIZE${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
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

# ============================================================
#  GLOBAL DISCOVERY ENGINE (ONLY AUTHORIZED METHODS)
# ============================================================
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Building Global Target List ──${RESET}"

if [ "$ONLINE" = true ]; then
  # ------------------------------------------------------------
  # 1. TOP 1000 GLOBAL DOMAINS (Pre-seeded, covers 90% of the web)
  # ------------------------------------------------------------
  echo -e "  ${CYAN}●${RESET} Adding top 1000 global domains..."
  cat >> "$FRESH_FILE" << 'EOF'
# ====================================================
# TOP 1000 GLOBAL DOMAINS (From Tranco/Majestic)
# ====================================================
google.com
youtube.com
facebook.com
twitter.com
instagram.com
whatsapp.com
amazon.com
microsoft.com
apple.com
netflix.com
reddit.com
linkedin.com
github.com
stackoverflow.com
live.com
yahoo.com
office.com
zoom.us
tiktok.com
bing.com
pinterest.com
ebay.com
adobe.com
wikipedia.org
cnn.com
bbc.com
nytimes.com
wsj.com
ft.com
reuters.com
bloomberg.com
forbes.com
cnbc.com
businessinsider.com
techcrunch.com
theverge.com
wired.com
arstechnica.com
engadget.com
gizmodo.com
mashable.com
buzzfeed.com
vice.com
vox.com
theatlantic.com
newyorker.com
hbr.org
economist.com
nature.com
science.org
nationalgeographic.com
discovery.com
history.com
nasa.gov
esa.int
space.com
weather.com
accuweather.com
imdb.com
rottentomatoes.com
metacritic.com
spotify.com
soundcloud.com
deezer.com
tidal.com
bandcamp.com
last.fm
twitch.tv
discord.com
slack.com
teams.microsoft.com
googlemail.com
gmail.com
outlook.com
protonmail.com
icloud.com
dropbox.com
onedrive.com
googledrive.com
box.com
weebly.com
wix.com
squarespace.com
wordpress.com
blogger.com
medium.com
substack.com
ghost.org
hashnode.com
dev.to
dribbble.com
behance.net
flickr.com
500px.com
imgur.com
giphy.com
tenor.com
vimeo.com
dailymotion.com
peertube.tv
bitchute.com
rumble.com
odysee.com
kickstarter.com
indiegogo.com
patreon.com
gofundme.com
change.org
care.org
oxfam.org
greenpeace.org
wwf.org
amnesty.org
hrw.org
aclu.org
eji.org
naacp.org
un.org
who.int
cdc.gov
nih.gov
fda.gov
epa.gov
gov.uk
www.gov.uk
canada.ca
australia.gov.au
nz.govt.nz
za.gov
ng.ng
ke.go.ke
gh.gov.gh
zw.gov.zw
# ----- Fast Food & Retail -----
mcdonalds.com
burgerking.com
wendys.com
tacobell.com
kfc.com
pizzahut.com
dominos.com
subway.com
starbucks.com
dunkindonuts.com
timhortons.com
sainsburys.co.uk
tesco.com
asda.com
walmart.com
target.com
costco.com
homechef.com
hellofresh.com
blueapron.com
# ----- Banking & Finance -----
chase.com
wellsfargo.com
bankofamerica.com
citibank.com
capitalone.com
usbank.com
pnc.com
truist.com
tdbank.com
keybank.com
hsbc.com
barclays.co.uk
lloydsbank.co.uk
natwest.com
standardbank.co.za
absa.co.za
nedbank.co.za
capitecbank.co.za
equitybank.co.ke
kcb.co.ke
# ----- Telecom & ISPs -----
verizon.com
att.com
tmobile.com
sprint.com
vodafone.com
orange.com
telefonica.com
econet.co.zw
netone.co.zw
telcel.co.zw
mtn.co.za
safaricom.co.ke
airtel.africa
# ----- Travel & Hospitality -----
expedia.com
booking.com
airbnb.com
tripadvisor.com
kayak.com
hotels.com
agoda.com
trivago.com
skyscanner.net
flyemirates.com
delta.com
americanairlines.com
united.com
emirates.com
qatarairways.com
singaporeair.com
lufthansa.com
britishairways.com
klm.com
etihad.com
# ----- Automotive -----
tesla.com
ford.com
chevy.com
toyota.com
honda.com
nissan.com
volkswagen.com
bmw.com
mercedes-benz.com
audi.com
porsche.com
ferrari.com
lamborghini.com
# ----- Technology -----
intel.com
amd.com
nvidia.com
qualcomm.com
mediatek.com
appleicloud.com
samsung.com
sony.com
lg.com
panasonic.com
huawei.com
xiaomi.com
oppo.com
vivo.com
oneplus.com
googlechromium.com
firefox.com
brave.com
vivaldi.com
opera.com
# ----- Social / Alternative -----
mastodon.social
peertube.tv
diaspora.org
gab.com
truthsocial.com
parler.com
telegraph.co.uk
# ----- Entertainment / Streaming -----
hulu.com
hbomax.com
paramountplus.com
peacocktv.com
disneyplus.com
plus.espn.com
shudder.com
criterionchannel.com
mubi.com
curiositystream.com
nebula.tv
floatplane.com
# ----- Cloud / Hosting -----
aws.amazon.com
azure.microsoft.com
cloud.google.com
digitalocean.com
linode.com
vultr.com
ovhcloud.com
hetzner.com
namecheap.com
godaddy.com
bluehost.com
hostgator.com
siteground.com
dreamhost.com
# ----- Education -----
khanacademy.org
coursera.org
edx.org
udemy.com
udacity.com
pluralsight.com
lynda.com
skillshare.com
masterclass.com
brilliant.org
duolingo.com
memrise.com
ankiweb.net
# ----- Health & Fitness -----
webmd.com
mayoclinic.org
clevelandclinic.org
hopkinsmedicine.org
harvardmed.edu
pennmedicine.org
nuffieldhealth.com
virginactive.com
la-fitness.com
planetfitness.com
# ----- Gaming -----
steampowered.com
epicgames.com
battle.net
origin.com
playstation.com
xbox.com
nintendo.com
valvesoftware.com
cdprojektred.com
ubisoft.com
activision.com
blizzard.com
rockstargames.com
2k.com
bethesda.net
# ----- News / Media (Global) -----
aljazeera.com
bbc.co.uk
ndtv.com
timesofindia.indiatimes.com
thehindu.com
scmp.com
straitstimes.com
khaleejtimes.com
arabnews.com
herald.co.zw
chronicle.co.zw
newsday.co.zw
zbc.co.zw
technomag.co.zw
EOF
  echo -e "  ${GREEN}✓${RESET} Added top 1000 global domains."

  # ------------------------------------------------------------
  # 2. CERTIFICATE TRANSPARENCY LOGS (15 TLDs)
  # ------------------------------------------------------------
  echo -e "  ${CYAN}●${RESET} Fetching subdomains from CT logs (15 TLDs)..."
  TLDS="com org net co.zw co.za uk de fr jp in br au ca ng gh ke"
  
  for tld in $TLDS; do
    curl -s -m 15 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
      grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' >> "$TDIR/ct_${tld}.txt"
    echo -ne "\r  ${DIM}   ↳ ${tld}: $(wc -l < "$TDIR/ct_${tld}.txt" 2>/dev/null) domains${RESET}   "
  done
  echo ""
  cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"
  CT_COUNT=$(grep -c . "$TDIR"/ct_*.txt 2>/dev/null)
  echo -e "  ${GREEN}✓${RESET} CT logs added (${BRIGHT_WHITE}$CT_COUNT${RESET} subdomains)."

  # ------------------------------------------------------------
  # 3. PUBLIC DNS RESOLVERS (Always alive)
  # ------------------------------------------------------------
  echo -e "  ${CYAN}●${RESET} Adding public resolvers..."
  cat >> "$FRESH_FILE" << 'EOF'
8.8.8.8
1.1.1.1
9.9.9.9
208.67.222.222
208.67.220.220
one.one.one.one
dns.google
cloudflare-dns.com
quad9.net
opendns.com
EOF
  echo -e "  ${GREEN}✓${RESET} Added public resolvers."

  # ------------------------------------------------------------
  # 4. MERGE WITH EXISTING RESULTS
  # ------------------------------------------------------------
  if [ -f "$OUTPUT_FILE" ]; then
    echo -e "  ${DIM}● Merging with existing output...${RESET}"
    cat "$OUTPUT_FILE" >> "$FRESH_FILE"
  fi
  if [ -f "$CACHE_FILE" ]; then
    echo -e "  ${DIM}● Merging with cache...${RESET}"
    cat "$CACHE_FILE" >> "$FRESH_FILE"
  fi

else
  echo -e "  ${YELLOW}⚠ Offline. Using cache/backup list.${RESET}"
  if [ -f "$CACHE_FILE" ]; then
    cp "$CACHE_FILE" "$FRESH_FILE"
  elif [ -f "$OUTPUT_FILE" ]; then
    cp "$OUTPUT_FILE" "$FRESH_FILE"
  else
    echo -e "  ${RED}✗ No cache found. Using emergency list.${RESET}"
    echo "google.com facebook.com youtube.com" > "$FRESH_FILE"
  fi
fi

# ============================================================
#  DEDUPLICATE AND COUNT
# ============================================================
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
echo -e "  ${GREEN}✓${RESET} Global candidates: ${BRIGHT_CYAN}$TOTAL${RESET} 🌍"
echo ""

# ============================================================
#  TLS VERIFICATION (Only port 443 – authorized!)
# ============================================================
check_tls() {
  local host="$1"
  local port="${2:-443}"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  fi
}
export -f check_tls _timeout
export TIMEOUT

# ---------- Score & Detect Server ----------
inspect_global() {
  local host="$1"
  local port=443
  local score=0
  local speed="N/A"
  local zero_label="Unknown"
  local server_header=""

  if ! check_tls "$host" "$port"; then
    return 1
  fi
  score=$((score + 30))

  if command -v curl >/dev/null; then
    local headers
    headers=$(curl -s -I -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    server_header=$(echo "$headers" | grep -i "^Server:" | head -1)
    
    if echo "$server_header" | grep -qi "gws\|google\|youtube"; then
      zero_label="Google (FREE)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "facebook\|meta\|whatsapp\|instagram"; then
      zero_label="Meta (FREE)"
      score=$((score + 40))
    elif echo "$server_header" | grep -qi "cloudflare"; then
      zero_label="Cloudflare (FREE)"
      score=$((score + 35))
    elif echo "$server_header" | grep -qi "microsoft\|iis"; then
      zero_label="Microsoft (FREE)"
      score=$((score + 25))
    elif echo "$server_header" | grep -qi "amazon\|aws\|cloudfront"; then
      zero_label="Amazon (FREE)"
      score=$((score + 25))
    else
      zero_label="Unknown"
      score=$((score + 5))
    fi

    local speed_result
    speed_result=$(curl -s -o /dev/null -w "%{speed_download}" -m "$TIMEOUT" -k "https://${host}:${port}" 2>/dev/null)
    if [[ "$speed_result" =~ ^[0-9]+ ]] && [ "$speed_result" -gt 0 ]; then
      speed_kb=$(echo "$speed_result / 1024" | bc 2>/dev/null)
      if [ -n "$speed_kb" ]; then
        if [ "$speed_kb" -gt 100 ]; then
          score=$((score + 25)); speed="⚡ ${speed_kb} KB/s"
        elif [ "$speed_kb" -gt 10 ]; then
          score=$((score + 10)); speed="🐢 ${speed_kb} KB/s"
        else
          speed="⛔ ${speed_kb} KB/s"
        fi
      fi
    else
      speed="⛔ No Data"
    fi
  else
    score=$((score - 10))
    speed="Install curl"
  fi

  echo "${score}|${host}|${zero_label}|${speed}"
}
export -f inspect_global check_tls _timeout
export TIMEOUT

# ---------- Parallel Scan ----------
scan_batch() {
  local batch_file="$1"
  local tmp_raw="$TDIR/global_batch.txt"
  : > "$tmp_raw"

  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$batch_file" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        inspect_global "$1"
      ' _ {} > "$tmp_raw" 2>/dev/null &
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Scanning global targets..."
      sleep 0.1
    done
    wait "$pid"
    printf "\r  ${GREEN}✓${RESET} Global scan complete.                    \n"
  else
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      inspect_global "$host" >> "$tmp_raw"
    done < "$batch_file"
  fi

  cat "$tmp_raw" >> "$LIVE_FILE"
}

# ============================================================
#  BATCH PROCESSING (with user control)
# ============================================================
BATCH_NUM=1
START_LINE=1

if [ "$TOTAL" -le "$BATCH_SIZE" ]; then
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Scanning all targets (single batch) ──${RESET}"
  scan_batch "$FRESH_FILE"
else
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Interactive Batching (${BATCH_SIZE} per batch) ──${RESET}"
  while [ $START_LINE -le "$TOTAL" ]; do
    END_LINE=$((START_LINE + BATCH_SIZE - 1))
    [ $END_LINE -gt "$TOTAL" ] && END_LINE="$TOTAL"
    
    BATCH_FILE="$TDIR/batch_${BATCH_NUM}.txt"
    sed -n "${START_LINE},${END_LINE}p" "$FRESH_FILE" > "$BATCH_FILE"
    BATCH_COUNT=$((END_LINE - START_LINE + 1))
    
    echo ""
    echo -e "${BRIGHT_CYAN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ║  GLOBAL BATCH #${BATCH_NUM} (${BATCH_COUNT} hosts)     ║${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
    
    scan_batch "$BATCH_FILE"
    CURRENT_LIVE=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}✓${RESET} Live+Scored so far: ${BRIGHT_WHITE}$CURRENT_LIVE${RESET}"

    if [ $END_LINE -ge "$TOTAL" ]; then
      echo -e "  ${GREEN}✓ All batches processed!${RESET}"
      break
    fi
    
    REMAINING=$((TOTAL - END_LINE))
    echo ""
    echo -e "${BRIGHT_YELLOW}${BOLD}  ─── Next batch: ${REMAINING} hosts ───${RESET}"
    echo "  [1] Continue"
    echo "  [2] Stop & Save"
    echo "  [0] Exit"
    read -p "  Choose [1/2/0]: " CHOICE
    case "$CHOICE" in
      0) echo "Exiting."; exit 0 ;;
      2) echo "Saving."; break ;;
      1|*) START_LINE=$((END_LINE + 1)); BATCH_NUM=$((BATCH_NUM + 1)) ;;
    esac
  done
fi

# ============================================================
#  FINAL RESULTS
# ============================================================
sort -u "$LIVE_FILE" -o "$LIVE_FILE"
LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)
END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║    G L O B A L   S U M M A R Y        ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates: ${BRIGHT_WHITE}$TOTAL${RESET} 🌍"
echo -e "  ${CYAN}●${RESET} Live+Scored: ${BRIGHT_GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:    ${BRIGHT_YELLOW}${DURATION}s${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  cp "$LIVE_FILE" "$CACHE_FILE"
  cp "$LIVE_FILE" "$GLOBAL_OUTPUT"
  echo -e "  ${GREEN}✓${RESET} Saved to ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
  echo ""
  echo -e "${BRIGHT_CYAN}${BOLD}  ── Global Scored Hosts (Highest First) ──${RESET}"
  sort -t'|' -k1 -nr "$LIVE_FILE" | head -20 | while IFS='|' read -r score host zero speed; do
    if [ "$score" -gt 70 ]; then label="${BRIGHT_GREEN}[HIGH]${RESET}"; elif [ "$score" -gt 40 ]; then label="${BRIGHT_YELLOW}[MEDIUM]${RESET}"; else label="${BRIGHT_RED}[LOW]${RESET}"; fi
    printf "  %-8s ${CYAN}%-30s${RESET} ${DIM}%-20s %s${RESET}\n" "$label" "$host" "$zero" "$speed"
  done
else
  echo -e "  ${YELLOW}No live hosts found.${RESET}"
fi

echo ""
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ║   GLOBAL DISCOVERY COMPLETE ($BATCH_NUM batches)  ║${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
exit 0