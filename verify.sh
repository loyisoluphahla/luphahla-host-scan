#!/usr/bin/env bash
# Simple sequential scanner (no parallel, no xargs)

set -o pipefail

TIMEOUT=3
INPUT_FILE=$(mktemp)
trap 'rm -f "$INPUT_FILE"' EXIT

# Read stdin
cat > "$INPUT_FILE"

# Scan each host one by one
while IFS= read -r host; do
  [[ "$host" =~ ^[[:space:]]*# ]] && continue
  [ -z "$host" ] && continue
  
  # TLS check
  if timeout "$TIMEOUT" openssl s_client -connect "$host:443" -servername "$host" -verify_quiet -brief </dev/null 2>/dev/null | grep -q "Verify return code: 0"; then
    # Get speed
    speed=$(curl -s -o /dev/null -w "%{speed_download}" -m "$TIMEOUT" "https://$host" 2>/dev/null)
    if [[ "$speed" =~ ^[0-9]+ ]] && [ "$speed" -gt 0 ]; then
      speed_kb=$((speed / 1024))
      if [ "$speed_kb" -gt 100 ]; then speed_label="⚡ ${speed_kb} KB/s"; else speed_label="🐢 ${speed_kb} KB/s"; fi
    else
      speed_label="N/A"
    fi
    
    # Get server header
    server=$(curl -s -I -m "$TIMEOUT" -k "https://$host" 2>/dev/null | grep -i "^Server:" | head -1 | cut -d' ' -f2- | head -c 20)
    [ -z "$server" ] && server="Unknown"
    
    echo "$host | $server | $speed_label"
  fi
done < "$INPUT_FILE"
