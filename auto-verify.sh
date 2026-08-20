#!/usr/bin/env bash
# Luphahla Host Scan - auto-verify.sh (GLOBAL)
# Automatically builds a GLOBAL host list and verifies TLS in parallel.
# Options:
#   --no-color        disable colors
#   --timeout N       timeout per host (default 5)
#   --parallel N      parallel jobs (default 30)
#   --hosts-file FILE use custom host list instead of built-in
#   -o FILE           write live hosts to FILE (default: ~/sni_hosts_latest.txt)
#   --help            show help

set -o pipefail

# ---------- Portable wrappers ----------
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

# Portable stat
_get_mtime() {
  local file="$1"
  if stat -c %y "$file" 2>/dev/null; then
    stat -c %y "$file"
  else
    stat -f %Sm "$file" 2>/dev/null
  fi
}
export -f _get_mtime

# ---------- Defaults ----------
USE_COLOR=true
TIMEOUT=5
PARALLEL=30
HOSTS_FILE=""
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
    --hosts-file)    HOSTS_FILE="$2"; shift ;;
    -o)              OUTPUT_FILE="$2"; shift ;;
    --help|-h)
      sed -n '2,/^$/p' "$0" | sed 's/^# //'
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      exit 2
      ;;
  esac
  shift
done

# ---------- Color setup ----------
if [ "$USE_COLOR" = false ]; then
  RESET=''; BOLD=''; DIM=''; UNDERLINE=''
  RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''
  BRIGHT_RED=''; BRIGHT_GREEN=''; BRIGHT_YELLOW=''; BRIGHT_BLUE=''; BRIGHT_CYAN=''; BRIGHT_MAGENTA=''
else
  RESET='\033[0m'; BOLD='\033[1m'; DIM='\033[2m'; UNDERLINE='\033[4m'
  RED='\033[31m'; GREEN='\033[32m'; YELLOW='\033[33m'; BLUE='\033[34m'; CYAN='\033[36m'; MAGENTA='\033[35m'; WHITE='\033[37m'
  BRIGHT_RED='\033[91m'; BRIGHT_GREEN='\033[92m'; BRIGHT_YELLOW='\033[93m'; BRIGHT_BLUE='\033[94m'; BRIGHT_CYAN='\033[96m'; BRIGHT_MAGENTA='\033[95m'
fi

# ---------- Setup temp dirs ----------
mkdir -p "$TDIR" || {
  echo -e "${RED}Error: Could not create $TDIR${RESET}" >&2
  exit 1
}
trap 'rm -rf "$TDIR"' EXIT INT TERM
FRESH_FILE="$TDIR/fresh_sni.txt"
LIVE_FILE="$TDIR/live.txt"
: > "$LIVE_FILE"

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
echo -e "${BRIGHT_BLUE}${BOLD}            G L O B A L   H O S T   S C A N     🌍${RESET}"
echo -e "${CYAN}               Luphahla Host Scan - Auto Verify${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo -e "  ${YELLOW}Zimbabwe${RESET} • ${GREEN}Africa${RESET} • ${BLUE}Americas${RESET} • ${MAGENTA}Europe${RESET} • ${CYAN}Asia${RESET}"
echo -e "${DIM}           ───────────────────────────────────────────────${RESET}"
echo ""

# ---------- Network check ----------
ONLINE=false
if command -v ping >/dev/null; then
  if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
    ONLINE=true
  elif ping -c 1 -t 2 8.8.8.8 >/dev/null 2>&1; then
    ONLINE=true
  fi
fi

if [ "$ONLINE" = true ]; then
  echo -e "  ${GREEN}${BOLD}✓${RESET} ${GREEN}Network: ONLINE${RESET}"
else
  echo -e "  ${RED}${BOLD}✗${RESET} ${RED}Network: OFFLINE${RESET}"
fi

# ---------- Build GLOBAL host list ----------
echo ""
echo -e "${BRIGHT_BLUE}${BOLD}  ── Building Global Target List ──${RESET}"

if [ -n "$HOSTS_FILE" ] && [ -f "$HOSTS_FILE" ]; then
  cp "$HOSTS_FILE" "$FRESH_FILE"
  echo -e "  ${CYAN}●${RESET} Using custom host list: ${BRIGHT_WHITE}$HOSTS_FILE${RESET}"
elif [ "$ONLINE" = true ]; then
  # ================================================================
  # FULL MASSIVE GLOBAL LIST (UNTRUNCATED)
  # ================================================================
  cat > "$FRESH_FILE" << 'EOF'
# ====================================================
# ZIMBABWE - ECONET, NETONE, TELECEL, LIQUID, BANKS
# ====================================================
econet.co.zw
www.econet.co.zw
mms.econet.co.zw
messaging.econet.co.zw
ecocash.co.zw
www.ecocash.co.zw
api.ecocash.co.zw
netone.co.zw
www.netone.co.zw
onemoney.co.zw
www.onemoney.co.zw
telecel.co.zw
www.telecel.co.zw
liquid.co.zw
www.liquidtelecom.com
liquid.africa
potraz.gov.zw
zimpost.co.zw
cabs.co.zw
www.cabs.co.zw
stewardbank.co.zw
www.stewardbank.co.zw
fbc.co.zw
www.fbc.co.zw
herald.co.zw
newsday.co.zw
chronicle.co.zw
technomag.co.zw
zbc.co.zw
www.zbc.co.zw

# ====================================================
# AFRICA (MTN, VODACOM, SAFARICOM, ORANGE, AIRTEL)
# ====================================================
mtn.co.za
www.mtn.co.za
vodacom.co.za
www.vodacom.co.za
cellc.co.za
www.cellc.co.za
telkom.co.za
www.telkom.co.za
safaricom.co.ke
www.safaricom.co.ke
airtel.africa
www.airtel.africa
orange.sn
www.orange.sn
africastalking.com
www.africastalking.com
mybroadband.co.za
www.mybroadband.co.za
standardbank.co.za
www.standardbank.co.za
absa.co.za
www.absa.co.za
capitecbank.co.za
www.capitecbank.co.za
equitybank.co.ke
www.equitybank.co.ke
kcb.co.ke
www.kcb.co.ke

# ====================================================
# NORTH AMERICA (US/Canada - Google, Meta, MS, Amazon)
# ====================================================
google.com
www.google.com
mail.google.com
gmail.com
android.clients.google.com
android.googleapis.com
play.googleapis.com
update.googleapis.com
connectivitycheck.gstatic.com
googleapis.com
www.googleapis.com
youtube.com
www.youtube.com
m.youtube.com
youtu.be
googlevideo.com
ggpht.com
googleusercontent.com
googleadservices.com
facebook.com
www.facebook.com
m.facebook.com
connect.facebook.com
graph.facebook.com
instagram.com
www.instagram.com
cdninstagram.com
whatsapp.com
www.whatsapp.com
api.whatsapp.com
microsoft.com
www.microsoft.com
live.com
login.live.com
outlook.com
office.com
azure.com
windowsupdate.com
update.microsoft.com
amazon.com
www.amazon.com
aws.amazon.com
amazonaws.com
cloudfront.net
netflix.com
www.netflix.com
cdn.netflix.com
apple.com
www.apple.com
apps.apple.com
itunes.apple.com
icloud.com
www.icloud.com
swscan.apple.com
mesu.apple.com
ocsp.apple.com
captive.apple.com
spotify.com
www.spotify.com
spotifycdn.com
github.com
raw.githubusercontent.com
stackoverflow.com
reddit.com
x.com
twitter.com
t.co
linkedin.com
www.linkedin.com
adobe.com
www.adobe.com
salesforce.com
www.salesforce.com
slack.com
www.slack.com
zoom.us
www.zoom.us

# ====================================================
# EUROPE (UK, Germany, France, Netherlands)
# ====================================================
bbc.co.uk
www.bbc.co.uk
bbc.com
www.bbc.com
deutsche-bank.de
www.deutsche-bank.de
sap.com
www.sap.com
siemens.com
www.siemens.com
zalando.de
www.zalando.de
bp.com
www.bp.com
vodafone.com
www.vodafone.com
vodafone.co.uk
www.vodafone.co.uk
sky.com
www.sky.com
ft.com
www.ft.com
reuters.com
www.reuters.com
nginx.com
www.nginx.com

# ====================================================
# ASIA / PACIFIC (China, Japan, India, Australia)
# ====================================================
baidu.com
www.baidu.com
alibaba.com
www.alibaba.com
tencent.com
www.tencent.com
qq.com
www.qq.com
yahoo.co.jp
www.yahoo.co.jp
naver.com
www.naver.com
line.me
www.line.me
shopee.sg
www.shopee.sg
tokopedia.com
www.tokopedia.com
flipkart.com
www.flipkart.com
paytm.com
www.paytm.com
telstra.com.au
www.telstra.com.au
optus.com.au
www.optus.com.au
abc.net.au
www.abc.net.au
airtel.in
www.airtel.in
jio.com
www.jio.com

# ====================================================
# SOUTH AMERICA
# ====================================================
globo.com
www.globo.com
uol.com.br
www.uol.com.br
mercadolivre.com.br
www.mercadolivre.com.br
mercadolibre.com
www.mercadolibre.com
claro.com.br
www.claro.com.br

# ====================================================
# CDNs / CLOUD PROVIDERS / PUBLIC RESOLVERS
# ====================================================
one.one.one.one
cloudflare-dns.com
1.1.1.1
quad9.net
opendns.com
akamaiedge.net
fastly.net
cdn77.net
b-cdn.net
edgecastcdn.net
stackpathcdn.com
azureedge.net
cloudflare.com
www.cloudflare.com
EOF
  # ================================================================
  # END OF FULL GLOBAL LIST
  # ================================================================

  echo -e "  ${CYAN}●${RESET} Generated ${BRIGHT_WHITE}global${RESET} target list (full)."
elif [ -f "$CACHE_FILE" ]; then
  cp "$CACHE_FILE" "$FRESH_FILE"
  CACHE_DATE=$(_get_mtime "$CACHE_FILE")
  echo -e "  ${YELLOW}●${RESET} Using cached list ${DIM}(last online: $CACHE_DATE)${RESET}"
elif [ -f "$OUTPUT_FILE" ]; then
  cp "$OUTPUT_FILE" "$FRESH_FILE"
  echo -e "  ${YELLOW}●${RESET} Using existing output file: ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
else
  echo -e "  ${RED}✗ No hosts available. Run online first.${RESET}" >&2
  exit 3
fi

# Merge and sort
if [ -f "$OUTPUT_FILE" ]; then
  cat "$OUTPUT_FILE" >> "$FRESH_FILE"
fi
sort -u "$FRESH_FILE" -o "$FRESH_FILE"

TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" | wc -l)
if [ "$TOTAL" -eq 0 ]; then
  echo -e "  ${RED}✗ No valid hosts found.${RESET}" >&2
  exit 3
fi
echo -e "  ${GREEN}✓${RESET} Total Global Candidates: ${BRIGHT_CYAN}$TOTAL${RESET}"
echo ""

# ---------- TLS check function ----------
check_tls() {
  local host="$1"
  local port="$2"
  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -verify_return_error -verify_ip "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  else
    _timeout "$TIMEOUT" openssl s_client -connect "$host:$port" -servername "$host" -verify_return_error -verify_hostname "$host" -verify_quiet -brief -no_ign_eof </dev/null >/dev/null 2>&1
  fi
}
export -f check_tls _timeout
export TIMEOUT

# ---------- Parallel verification (fast) ----------
parallel_check() {
  local port="$1"
  local tmp_live="$TDIR/live_${port}.txt"
  : > "$tmp_live"
  
  echo -e "${BRIGHT_BLUE}${BOLD}  ── TLS Checking Port ${port} (Global) ──${RESET}"
  echo -e "  ${DIM}Scanning $TOTAL hosts in parallel (${PARALLEL} jobs)...${RESET}"
  
  # Use xargs -P for maximum speed
  if command -v xargs >/dev/null && xargs --help 2>&1 | grep -q -- '-P'; then
    grep -vE '^[[:space:]]*(#|$)' "$FRESH_FILE" | \
      xargs -P "$PARALLEL" -I {} bash -c '
        if check_tls "$1" '"$port"'; then
          echo "$1"
        fi
      ' _ {} >> "$tmp_live" 2>/dev/null &
    
    # Show a spinner while xargs runs in background
    local pid=$!
    local spin='⣾⣽⣻⢿⡿⣟⣯⣷'
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
      printf "\r  ${CYAN}${spin:i++%${#spin}:1}${RESET} Scanning in progress..."
      sleep 0.1
    done
    wait "$pid"
    printf "\r  ${GREEN}✓${RESET} Scan complete.                    \n"
  else
    # Fallback to sequential if no xargs -P
    echo -e "  ${YELLOW}⚠${RESET} Parallel not available – using sequential (slower)."
    while IFS= read -r host; do
      [[ "$host" =~ ^[[:space:]]*# ]] && continue
      [ -z "$host" ] && continue
      if check_tls "$host" "$port"; then
        echo "$host" >> "$tmp_live"
      fi
    done < "$FRESH_FILE"
  fi
  
  sort -u "$tmp_live" -o "$tmp_live"
  cat "$tmp_live" >> "$LIVE_FILE"
}

# ---------- Run checks ----------
parallel_check 443
parallel_check 8080

# ---------- Finalize results ----------
sort -u "$LIVE_FILE" -o "$LIVE_FILE"
LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

# ---------- Beautiful Summary Box ----------
echo ""
echo -e "${BRIGHT_GREEN}${BOLD}  ╔═══════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ║            G L O B A L   S U M M A R Y            ║${RESET}"
echo -e "${BRIGHT_GREEN}${BOLD}  ╚═══════════════════════════════════════════════════╝${RESET}"
echo -e "  ${CYAN}●${RESET} Candidates:  ${BRIGHT_WHITE}$TOTAL${RESET}"
echo -e "  ${CYAN}●${RESET} Live:         ${BRIGHT_GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}●${RESET} Duration:     ${BRIGHT_YELLOW}${DURATION}s${RESET}"

# ---------- Show sample of live hosts ----------
if [ "$LIVECOUNT" -gt 0 ]; then
  echo ""
  echo -e "${BRIGHT_CYAN}${BOLD}  ── Live Hosts (Top 10) ──${RESET}"
  head -10 "$LIVE_FILE" | nl -w2 -s'. ' | while read -r line; do
    echo -e "  ${GREEN}✓${RESET} ${WHITE}$line${RESET}"
  done
  if [ "$LIVECOUNT" -gt 10 ]; then
    echo -e "  ${DIM}... and $(($LIVECOUNT - 10)) more.${RESET}"
  fi
else
  echo -e "  ${YELLOW}${BOLD}⚠${RESET} ${YELLOW}No live hosts found globally.${RESET}"
fi

# ---------- Save output and cache ----------
echo ""
if [ "$LIVECOUNT" -gt 0 ]; then
  cp "$LIVE_FILE" "$OUTPUT_FILE"
  cp "$LIVE_FILE" "$CACHE_FILE"
  echo -e "  ${GREEN}✓${RESET} ${GREEN}Saved${RESET} ${BRIGHT_CYAN}$LIVECOUNT${RESET} ${GREEN}hosts to${RESET} ${BRIGHT_WHITE}$OUTPUT_FILE${RESET}"
  echo -e "  ${GREEN}✓${RESET} ${GREEN}Cached for offline use at${RESET} ${BRIGHT_WHITE}$CACHE_FILE${RESET}"
else
  echo -e "  ${YELLOW}⚠${RESET} ${YELLOW}Existing output unchanged.${RESET}"
fi

echo ""
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╔═══════════════════════════════════════════════════╗${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ║        LUPHAHLA GLOBAL SCAN COMPLETE             ║${RESET}"
echo -e "${BRIGHT_MAGENTA}${BOLD}  ╚═══════════════════════════════════════════════════╝${RESET}"
echo ""
exit 0
