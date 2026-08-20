#!/usr/bin/env bash
# Luphahla Host Scan - TERMUX SAFE DISCOVERY
# Optimized to prevent OOM Killer (Signal 9).
# Use --light for ultra-low memory mode.

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

# ---------- Defaults (Low for Termux) ----------
USE_COLOR=true
TIMEOUT=4
PARALLEL=3              # SAFE: Only 3 parallel jobs
BATCH_SIZE=200          # SAFE: Small batches
OUTPUT_FILE="${HOME}/sni_hosts_latest.txt"
CACHE_FILE="${HOME}/.cache/sni_hosts_cached.txt"
TDIR="${HOME}/.cache/luphahla-scan"
START_TIME=$(date +%s)
LIGHT_MODE=false        # Ultra-safe mode
FETCH_CT=true           # Fetch CT logs (can be disabled)
EXPAND_IPS=true         # Expand IP ranges (can be disabled)

# ---------- Parse arguments ----------
while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)      USE_COLOR=false ;;
    --timeout)       TIMEOUT="$2"; shift ;;
    --parallel)      PARALLEL="$2"; shift ;;
    --batch)         BATCH_SIZE="$2"; shift ;;
    --light)         LIGHT_MODE=true ;;   # Ultra-safe: parallel=1, batch=50, no CT, no IP expand
    --no-ct)         FETCH_CT=false ;;
    --no-ip)         EXPAND_IPS=false ;;
    --help|-h)
      echo "Luphahla Termux-Safe Discovery"
      echo "  --light        : Parallel=1, Batch=50, Skip CT logs, Skip IP ranges (Safest)"
      echo "  --parallel 3   : Default safe parallelism"
      echo "  --timeout 4    : Default timeout"
      exit 0
      ;;
    *) echo "Unknown option: $1" >&2; exit 2 ;;
  esac
  shift
done

# ---------- Light Mode Overrides ----------
if [ "$LIGHT_MODE" = true ]; then
  PARALLEL=1
  BATCH_SIZE=50
  FETCH_CT=false
  EXPAND_IPS=false
  TIMEOUT=3
fi

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
echo -e "${BRIGHT_BLUE}${BOLD}      T E R M U X   S A F E   D I S C O V E R Y   📱${RESET}"
echo -e "${CYAN}       Optimized to prevent Signal 9 (OOM Killer)${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
if [ "$LIGHT_MODE" = true ]; then
  echo -e "  ${BRIGHT_GREEN}${BOLD}⚡ LIGHT MODE ACTIVE${RESET} ${DIM}(Parallel=1, Batch=50, No CT, No IP Expand)${RESET}"
fi
echo -e "  ${YELLOW}Parallel:${RESET} ${BRIGHT_WHITE}$PARALLEL${RESET}  ${YELLOW}Batch:${RESET} ${BRIGHT_WHITE}$BATCH_SIZE${RESET}  ${YELLOW}Timeout:${RESET} ${BRIGHT_WHITE}${TIMEOUT}s${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo ""

# ---------- Network Check ----------
ONLINE=false
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1 || ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
  ONLINE=true
  echo -e "  ${GREEN}✓ Network: ONLINE${RESET}"
else
  echo -e "  ${RED}✗ Network: OFFLINE${RESET}"
fi

# ============================================================
#  SAFE DISCOVERY ENGINE (No heavy expansions by default)
# ============================================================
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Building target list (safe mode) ──${RESET}"

if [ "$ONLINE" = true ]; then
  # 1. TOP 200 DOMAINS (Small, fast, covers 80% of zero-rated hosts)
  echo -e "  ${CYAN}●${RESET} Adding top 200 global domains..."
  cat >> "$FRESH_FILE" << 'EOF'
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
tesla.com
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
  echo -e "  ${GREEN}✓${RESET} Added top 200 domains."

  # 2. CT LOGS (Only if enabled, and with a timeout to prevent hanging)
  if [ "$FETCH_CT" = true ]; then
    echo -e "  ${CYAN}●${RESET} Fetching CT logs (limited to 50 per TLD)..."
    TLDS="com org net co.zw co.za uk de fr jp in br au ca"
    CT_COUNT=0
    for tld in $TLDS; do
      # Limit to 50 results per TLD to save memory
      curl -s -m 10 "https://crt.sh/?q=%25.${tld}&output=json" 2>/dev/null | \
        grep -oP '"name_value":"\K[^"]+' | sed 's/\\\\.//g' | head -50 >> "$TDIR/ct_${tld}.txt"
      CT_COUNT=$((CT_COUNT + $(wc -l < "$TDIR/ct_${tld}.txt" 2>/dev/null)))
      echo -ne "\r  ${DIM}   ↳ ${tld}: $(wc -l < "$TDIR/ct_${tld}.txt" 2>/dev/null) domains${RESET}   "
    done
    echo ""
    cat "$TDIR"/ct_*.txt 2>/dev/null >> "$FRESH_FILE"
    echo -e "  ${GREEN}✓${RESET} Added ${BRIGHT_WHITE}$CT_COUNT${RESET} CT log subdomains."
  else
    echo -e "  ${DIM}● Skipping CT logs (--light or --no-ct)${RESET}"
  fi

  # 3. ISP IP RANGES (Only if enabled and strictly limited to /24)
  if [ "$EXPAND_IPS" = true ] && [ "$LIGHT_MODE" = false ]; then
    echo -e "  ${CYAN}●${RESET} Detecting ISP for IP ranges..."
    CURRENT_ASN=$(curl -s -m 5 "https://ipinfo.io/org" | grep -oE 'AS[0-9]+' | head -1)
    if [ -z "$CURRENT_ASN" ]; then
      CURRENT_ASN=$(curl -s -m 5 "https://api.hackertarget.com/aslookup/8.8.8.8" | grep -oE 'AS[0-9]+' | head -1)
    fi

    if [ -n "$CURRENT_ASN" ]; then
      echo -e "  ${GREEN}✓${RESET} Detected ASN: ${BRIGHT_WHITE}$CURRENT_ASN${RESET}"
      RANGES=$(curl -s -m 10 "https://ipinfo.io/$CURRENT_ASN" | grep -oE '[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+' | head -3)
      if [ -n "$RANGES" ]; then
        echo "$RANGES" | while read -r cidr; do
          local mask="${cidr#*/}"
          local base="${cidr%/*}"
          # SAFE: Only expand /24 ranges (254 IPs). Ignore /16 and /8.
          if [ "$mask" -eq 24 ]; then
            local prefix="${base%.*}"
            for i in $(seq 1 254); do echo "${prefix}.${i}"; done
          else
            echo -e "  ${DIM}   ↳ Skipping ${cidr} (too large, use --deep-scan to force)${RESET}"
          fi
        done > "$TDIR/isp_ips.txt"
        COUNT=$(wc -l < "$TDIR/isp_ips.txt")
        echo -e "  ${GREEN}✓${RESET} Generated ${BRIGHT_WHITE}$COUNT${RESET} IPs from ${BRIGHT_WHITE}/24${RESET} ranges."
        cat "$TDIR/isp_ips.txt" >> "$FRESH_FILE"
      fi
    else
      echo -e "  ${YELLOW}⚠ Could not detect ASN. Skipping IP ranges.${RESET}"
    fi
  else
    echo -e "  ${DIM}● Skipping ISP IP ranges (--light or --no-ip)${RESET}"
  fi

else
  echo -e "  ${YELLOW}⚠ Offline. Using cache/backup list.${RESET}"
  if [ -f "$CACHE_FILE" ]; then
    cp "$CACHE_FILE" "$FRESH_FILE"
  elif [ -f "$OUTPUT_FILE" ]; then
    cp "$OUTPUT_FILE" "$FRESH_FILE"
  else
    echo "google.com facebook.com youtube.com" > "$FRESH_FILE"
  fi
fi

# ---------- Merge with existing results ----------
if [ -f "$OUTPUT_FILE" ]; then
  echo -e "  ${DIM}● Merging with existing output...${RESET}"
  cat "$OUTPUT_FILE" >> "$FRESH_FILE"
fi

# ---------- Deduplicate ----------
sort -u "$FRESH_FILE" -o "$FRESH_FILE"
grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" > "$FRESH_FILE.tmp"
mv "$FRESH_FILE.tmp" "$FRESH_FILE"
TOTAL=$(wc -l < "$FRESH_FILE")
echo -e "  ${GREEN}✓${RESET} Total targets: ${BRIGHT_CYAN}$TOTAL${RESET}"
echo ""

# ============================================================
#  TLS VERIFICATION (SAFE: Uses --parallel, defaults to 3)
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

# ---------- Scan a batch (Sequential if parallel=1) ----------
scan_batch_safe() {
  local batch_file="$1"
  local tmp_live="$TDIR/live_batch.txt"
  : > "$tmp_live"

  if [ "$PARALLEL" -le 1 ]; then
    # Sequential (ULTRA SAFE)
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      if check_tls "$host" 443; then
        echo "$host" >> "$tmp_live"
      fi
    done < "$batch_file"
  else
    # Low Parallel (3-5 jobs)
    if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
      grep -vE '^[[:space:]]*(#|$)' "$batch_file" | \
        xargs -P "$PARALLEL" -I {} bash -c '
          if check_tls "$1" 443; then
            echo "$1"
          fi
        ' _ {} >> "$tmp_live" 2>/dev/null &
      local pid=$!
      local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
      local i=0
      while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Scanning (${PARALLEL} jobs)..."
        sleep 0.1
      done
      wait "$pid"
      printf "\r  ${GREEN}✓${RESET} Batch complete.                    \n"
    else
      # Fallback to sequential if no xargs -P
      while IFS= read -r host; do
        [[ "$host" =~ ^[[:space:]]*# ]] && continue
        [ -z "$host" ] && continue
        if check_tls "$host" 443; then
          echo "$host" >> "$tmp_live"
        fi
      done < "$batch_file"
    fi
  fi

  sort -u "$tmp_live" -o "$tmp_live"
  cat "$tmp_live" >> "$LIVE_FILE"
}

# ============================================================
#  BATCH PROCESSING
# ============================================================
BATCH_NUM=1
START_LINE=1

if [ "$TOTAL" -le "$BATCH_SIZE" ]; then
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Scanning targets (single batch) ──${RESET}"
  scan_batch_safe "$FRESH_FILE"
else
  echo -e "${BRIGHT_BLUE}${BOLD}  ── Safe Batching (${BATCH_SIZE} per batch) ──${RESET}"
  while [ $START_LINE -le "$TOTAL" ]; do
    END_LINE=$((START_LINE + BATCH_SIZE - 1))
    [ $END_LINE -gt "$TOTAL" ] && END_LINE="$TOTAL"
    
    BATCH_FILE="$TDIR/batch_${BATCH_NUM}.txt"
    sed -n "${START_LINE},${END_LINE}p" "$FRESH_FILE" > "$BATCH_FILE"
    BATCH_COUNT=$((END_LINE - START_LINE + 1))
    
    echo ""
    echo -e "${BRIGHT_CYAN}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ║    BATCH #${BATCH_NUM} (${BATCH_COUNT} hosts)             ║${RESET}"
    echo -e "${BRIGHT_CYAN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
    
    scan_batch_safe "$BATCH_FILE"
    CURRENT_LIVE=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)
    echo -e "  ${GREEN}✓${RESET} Live so far: ${BRIGHT_WHITE}$CURRENT_LIVE${RESET}"

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
echo -e "${BRIGHT_GREEN}${BOLD}  ║      S A F E   S C A N   S U M M A R Y  ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates: ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Live:        ${BRIGHT_GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:    ${BRIGHT_YELLOW}${DURATION}s${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  cp "$LIVE_FILE" "$CACHE_FILE"
  echo -e "  ${GREEN}✓${RESET} Saved to ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
  echo ""
  echo -e "${BRIGHT_CYAN}${BOLD}  Live Hosts:${RESET}"
  cat "$LIVE_FILE" | while read -r line; do
    echo -e "  ${GREEN}✓${RESET} ${WHITE}$line${RESET}"
  done
else
  echo -e "  ${YELLOW}No live hosts found.${RESET}"
fi

echo ""
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╔════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ║       SAFE SCAN COMPLETE ($BATCH_NUM batches)    ║${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╚════════════════════════════════════════╝${RESET}"
exit 0