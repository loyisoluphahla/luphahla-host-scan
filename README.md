# SNI / Bug Host Scanner

Async SNI/Bug Host scanner for zero-rated VPN tunneling (HA Tunnel Plus, Stark VPN).
Works on Linux, Windows, macOS, and Termux (Android).

## Install (Termux)

    pkg update && pkg upgrade
    pkg install python git
    git clone https://github.com/YOUR_USERNAME/sni-scanner.git
    cd sni-scanner
    pip install -r requirements.txt
    python main.py --serve

Open http://localhost:8000 in your browser. Working SNI feed: http://localhost:8000/hosts

## Other platforms

    git clone https://github.com/YOUR_USERNAME/sni-scanner.git
    cd sni-scanner
    pip install -r requirements.txt
    python main.py

## CLI options

    --no-scrape       scan embedded fallback pool only (fast, offline-safe)
    --concurrency N   max parallel workers (default 250)
    --output FILE     output file (default clean_hosts.txt)
    --serve           launch web dashboard after scan

## GitHub Actions

The workflow `.github/workflows/sni_cron.yml` runs every 2 hours, scans,
writes clean_hosts.txt, and auto-commits it to main.
