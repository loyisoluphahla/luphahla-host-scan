#!/data/data/com.termux/files/usr/bin/bash
# Luphahla Host Scan
# auto-verify.sh — Online/Offline/Wi-Fi/Mobile

set -o pipefail

# ==============================
# LUPHAHLA HOST SCAN
# ==============================
RESET='\033[0m'
BOLD='\033[1m'
RED='\033[31m'
GREEN='\033[32m'
YELLOW='\033[33m'
BLUE='\033[34m'
CYAN='\033[36m'
WHITE='\033[37m'
BRIGHT_RED='\033[91m'
BRIGHT_BLUE='\033[94m'
BRIGHT_CYAN='\033[96m'
DIM='\033[2m'

USE_COLOR=true
TIMEOUT=5

while [ $# -gt 0 ]; do
  case "$1" in
    --no-color)
      USE_COLOR=false
      ;;
    --timeout)
      if [ -z "${2:-}" ] || ! [[ "$2" =~ ^[0-9]+$ ]] || [ "$2" -lt 1 ]; then
        echo "Error: --timeout requires a positive number."
        exit 2
      fi
      TIMEOUT="$2"
      shift
      ;;
    --help|-h)
      echo "Luphahla Host Scan"
      echo ""
      echo "Usage:"
      echo "  ./auto-verify.sh"
      echo "  ./auto-verify.sh --no-color"
      echo "  ./auto-verify.sh --timeout 10"
      exit 0
      ;;
    *)
      echo "Error: Unknown option: $1"
      echo "Use --help for usage."
      exit 2
      ;;
  esac
  shift
done

if [ "$USE_COLOR" = false ]; then
  RESET=''
  BOLD=''
  RED=''
  GREEN=''
  YELLOW=''
  BLUE=''
  CYAN=''
  WHITE=''
  BRIGHT_RED=''
  BRIGHT_BLUE=''
  BRIGHT_CYAN=''
  DIM=''
fi

LIST=~/sni_hosts_latest.txt
CACHE=~/.cache/sni_hosts_cached.txt
TDIR=$HOME/.cache/sni-scanner

START_TIME=$(date +%s)

cleanup() {
  rm -rf "$TDIR"
}
trap cleanup EXIT INT TERM

mkdir -p "$TDIR" || {
  echo -e "${RED}Error: Could not create scanner directory.${RESET}"
  exit 1
}

rm -f "$TDIR/fresh_sni.txt"

clear

echo -e "${BRIGHT_RED}${BOLD}"
echo "██╗     ██╗   ██╗██████╗ ██╗  ██╗ █████╗ ██╗  ██╗██╗      █████╗"
echo "██║     ██║   ██║██╔══██╗██║  ██║██╔══██╗██║  ██║██║     ██╔══██╗"
echo "██║     ██║   ██║██████╔╝███████║███████║███████║██║     ███████║"
echo "██║     ██║   ██║██╔═══╝ ██╔══██║██╔══██║██╔══██║██║     ██╔══██║"
echo "███████╗╚██████╔╝██║     ██║  ██║██║  ██║██║  ██║███████╗██║  ██║"
echo "╚══════╝ ╚═════╝ ╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝"
echo -e "${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}                 H O S T   S C A N${RESET}"
echo -e "${CYAN}              Luphahla Host Scan${RESET}"
echo -e "${DIM}        Online • Offline • Wi-Fi • Mobile${RESET}"
echo ""

echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${WHITE}  Scan started: ${CYAN}$(date)${RESET}"
echo -e "${WHITE}  Timeout:      ${CYAN}${TIMEOUT}s${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

# ---- Dependency check ----
MISSING=()

for cmd in ping ip openssl timeout sort wc grep stat cp cat tee nl; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    MISSING+=("$cmd")
  fi
done

if [ "${#MISSING[@]}" -gt 0 ]; then
  echo -e "${RED}${BOLD}[!] Missing dependencies:${RESET}"
  printf '  %s\n' "${MISSING[@]}"
  echo ""
  echo -e "${YELLOW}Install the missing Termux packages before running the scanner.${RESET}"
  exit 1
fi

echo -e "${GREEN}${BOLD}[✓]${RESET} Dependencies: ${GREEN}OK${RESET}"
echo ""

# ---- Check network status ----
if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
  echo -e "${GREEN}${BOLD}[+]${RESET} Network: ${GREEN}ONLINE${RESET}"
  ONLINE=true
else
  echo -e "${YELLOW}${BOLD}[!]${RESET} Network: ${YELLOW}OFFLINE (no internet)${RESET}"
  ONLINE=false
fi

# Detect current interface
if ip route | grep -q wlan; then
  MODE="Wi-Fi"
elif ip route | grep -q "ccmni\|rmnet\|wwan"; then
  MODE="Mobile Data"
else
  MODE="Unknown"
fi

echo -e "${BLUE}${BOLD}[+]${RESET} Interface: ${CYAN}$MODE${RESET}"
echo ""

# ---- OFFLINE MODE ----
if [ "$ONLINE" = false ]; then
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
  echo -e "${BRIGHT_BLUE}${BOLD}  OFFLINE MODE${RESET}"
  echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

  if [ -f "$CACHE" ]; then
    CACHE_DATE=$(stat -c %y "$CACHE" 2>/dev/null | cut -d. -f1)

    echo -e "${CYAN}[*]${RESET} Using cached host list ${DIM}(last online: $CACHE_DATE)${RESET}"

    cp "$CACHE" "$LIST"

    echo -e "${GREEN}[✓]${RESET} Loaded from cache → ${CYAN}$LIST${RESET}"
    cat "$LIST"

  elif [ -f "$LIST" ]; then
    echo -e "${YELLOW}[!]${RESET} No cache, but ${CYAN}$LIST${RESET} exists from a previous run"
    cat "$LIST"

  else
    echo -e "${RED}[!]${RESET} No cached or saved hosts found. Run again when online."
  fi

  exit 0
fi

# ---- ONLINE MODE ----

cat > "$TDIR/fresh_sni.txt" << 'UNIVERSAL'
# Google infrastructure (works on everything)
mtalk.google.com
alt1.mtalk.google.com
alt2.mtalk.google.com
alt3.mtalk.google.com
alt4.mtalk.google.com
alt5.mtalk.google.com
alt6.mtalk.google.com
alt7.mtalk.google.com
alt8.mtalk.google.com
client1.google.com
client2.google.com
client3.google.com
client4.google.com
client5.google.com
google.com
www.google.com
mail.google.com
gmail.com
android.clients.google.com
android.googleapis.com
play.googleapis.com
update.googleapis.com
connectivitycheck.gstatic.com
connectivitycheck.platform.googleapis.com
firebase-settings.crashlytics.com
googleapis.com
www.googleapis.com
youtube.com
www.youtube.com
m.youtube.com
youtu.be
google-analytics.com
ssl.google-analytics.com
googletagmanager.com
googlevideo.com
ggpht.com
googleusercontent.com
googleadservices.com
googleads.g.doubleclick.net
pagead2.googlesyndication.com
tpc.googlesyndication.com
doubleclick.net
goo.gl
g.co
# Apple
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
gs.apple.com
# Meta/Facebook
facebook.com
www.facebook.com
m.facebook.com
connect.facebook.com
graph.facebook.com
api.facebook.com
facebook.net
fbcdn.net
fbsbx.com
whatsapp.com
www.whatsapp.com
api.whatsapp.com
whatsapp.net
instagram.com
www.instagram.com
cdninstagram.com
# Microsoft
microsoft.com
www.microsoft.com
live.com
login.live.com
outlook.com
office.com
azure.com
windowsupdate.com
update.microsoft.com
# Cloudflare/General
gn.total.com
www.mango4g.com
info.chunhomall.com
one.one.one.one
cloudflare-dns.com
1.1.1.1
# Android
android.com
www.android.com
play.google.com
support.google.com
market.android.com
developer.android.com
UNIVERSAL

echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}  NETWORK PROFILE${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${CYAN}[*]${RESET} Detected: ${YELLOW}$MODE${RESET} — adding ISP-specific hosts..."

case "$MODE" in
  *Wi-Fi*)
    cat >> "$TDIR/fresh_sni.txt" << 'WIFI'
amazon.com
www.amazon.com
aws.amazon.com
amazonaws.com
cloudfront.net
netflix.com
www.netflix.com
cdn.netflix.com
spotify.com
spotifycdn.com
twitch.tv
github.com
raw.githubusercontent.com
stackoverflow.com
reddit.com
twitter.com
x.com
t.co
pinterest.com
linkedin.com
cloudflare.com
www.cloudflare.com
WIFI
    ;;
  *Mobile*)
    cat >> "$TDIR/fresh_sni.txt" << 'MOBILE'
# Zim ISP first-party
econet.co.zw
www.econet.co.zw
mms.econet.co.zw
messaging.econet.co.zw
onai.co.zw
netone.co.zw
www.netone.co.zw
onemoney.co.zw
www.onemoney.co.zw
telecel.co.zw
www.telecel.co.zw
liquid.co.zw
www.liquidtelecom.com
potraz.gov.zw
zimpost.co.zw
# CDNs that pass through Zim ISPs
auth.mtn.cm
smscloud.mtn.ci
log.postmaster.apple.com
sandbox.itunes.apple.com
firestore.googleapis.com
firebaseremoteconfig.googleapis.com
firebaseinstallations.googleapis.com
app-measurement.com
MOBILE
    ;;
esac

# ---- Merge existing list ----
if [ -f "$LIST" ]; then
  cat "$LIST" >> "$TDIR/fresh_sni.txt"
fi

sort -u "$TDIR/fresh_sni.txt" -o "$TDIR/fresh_sni.txt"

# Count actual hosts, excluding comments and blank lines
TOTAL=$(grep -vE '^[[:space:]]*(#|$)' "$TDIR/fresh_sni.txt" | wc -l)

if [ "$TOTAL" -eq 0 ]; then
  echo -e "${RED}[!] No valid hosts found.${RESET}"
  exit 3
fi

echo ""
echo -e "${GREEN}${BOLD}[+]${RESET} Total candidates: ${CYAN}$TOTAL${RESET}"
echo ""

# ---- TLS verification helper ----
check_tls() {
  local host="$1"
  local port="$2"

  if [[ "$host" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
    timeout "$TIMEOUT" openssl s_client \
      -connect "$host:$port" \
      -verify_return_error \
      -verify_ip "$host" \
      -verify_quiet \
      -brief \
      -no_ign_eof \
      </dev/null >/dev/null 2>&1
  else
    timeout "$TIMEOUT" openssl s_client \
      -connect "$host:$port" \
      -servername "$host" \
      -verify_return_error \
      -verify_hostname "$host" \
      -verify_quiet \
      -brief \
      -no_ign_eof \
      </dev/null >/dev/null 2>&1
  fi
}

# ---- Verify 443 ----
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}  TLS VERIFICATION • PORT 443${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

LIVE_FILE="$TDIR/live.txt"
: > "$LIVE_FILE"

COUNT=0
CHECKED=0

while IFS= read -r host; do
  [[ "$host" =~ ^[[:space:]]*# ]] && continue
  [ -z "$host" ] && continue

  COUNT=$((COUNT + 1))

  echo -ne "\r${CYAN}[*]${RESET} ${WHITE}$COUNT/$TOTAL${RESET} — ${CYAN}$host${RESET}...   "

  if check_tls "$host" 443; then
    echo ""
    echo -e "  ${GREEN}${BOLD}✓${RESET} ${GREEN}$host:443${RESET}"
    printf '%s\n' "$host" >> "$LIVE_FILE"
  fi

  CHECKED=$COUNT
done < "$TDIR/fresh_sni.txt"

# ---- Check 8080 ----
echo ""
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}  SECONDARY TLS CHECK • PORT 8080${RESET}"
echo -e "${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

while IFS= read -r host; do
  [[ "$host" =~ ^[[:space:]]*# ]] && continue
  [ -z "$host" ] && continue

  if grep -Fxq "$host" "$LIVE_FILE"; then
    continue
  fi

  echo -ne "\r${CYAN}[*]${RESET} 8080 — ${CYAN}$host${RESET}...   "

  if check_tls "$host" 8080; then
    echo ""
    echo -e "  ${GREEN}${BOLD}✓${RESET} ${GREEN}$host:8080${RESET}"
    printf '%s\n' "$host" >> "$LIVE_FILE"
  fi
done < "$TDIR/fresh_sni.txt"

# ---- Save results ----
sort -u "$LIVE_FILE" -o "$LIVE_FILE"

LIVECOUNT=$(grep -cve '^[[:space:]]*$' "$LIVE_FILE" 2>/dev/null || echo 0)

if [ "$LIVECOUNT" -gt 0 ]; then
  cp "$LIVE_FILE" "$LIST"
else
  : > "$LIST"
fi

END_TIME=$(date +%s)
DURATION=$((END_TIME - START_TIME))

echo ""
echo -e "${BRIGHT_BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_RED}${BOLD}                 SCAN SUMMARY${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "  ${CYAN}Candidates:${RESET} $TOTAL"
echo -e "  ${CYAN}Checked:${RESET}    $CHECKED"
echo -e "  ${CYAN}Live:${RESET}       ${GREEN}$LIVECOUNT${RESET}"
echo -e "  ${CYAN}Mode:${RESET}       $MODE"
echo -e "  ${CYAN}Duration:${RESET}   ${DURATION}s"
echo -e "  ${CYAN}Time:${RESET}       $(date)"
echo -e "${BRIGHT_BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"

if [ "$LIVECOUNT" -gt 0 ]; then
  echo ""
  cat "$LIST"

  echo ""
  echo -e "${GREEN}${BOLD}[✓]${RESET} Saved to ${CYAN}$LIST${RESET} ($LIVECOUNT hosts)"

  cp "$LIST" "$CACHE"
  echo -e "${GREEN}${BOLD}[✓]${RESET} Cached for offline use → ${CYAN}$CACHE${RESET}"

  if command -v termux-clipboard-set >/dev/null 2>&1; then
    head -5 "$LIST" | termux-clipboard-set
    echo -e "${GREEN}${BOLD}[✓]${RESET} Top hosts copied to clipboard"
  fi

  echo ""
  echo -e "${BRIGHT_BLUE}${BOLD}  QUICK PICK${RESET}"
  echo -e "${BLUE}  ─────────────────────────────${RESET}"
  nl -ba "$LIST" | head -10

else
  echo ""
  echo -e "${YELLOW}[!]${RESET} No hosts passed TLS verification."
  echo -e "${YELLOW}[!]${RESET} Existing cache was not replaced."
fi

echo ""
echo -e "${BRIGHT_RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo -e "${BRIGHT_BLUE}${BOLD}          LUPHAHLA HOST SCAN COMPLETE${RESET}"
echo -e "${BRIGHT_RED}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
echo ""

exit 0
