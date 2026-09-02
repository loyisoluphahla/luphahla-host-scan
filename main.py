"""
Luphahla Bugscan — CLI orchestrator.

Usage:
  python main.py                      # harvest + scan -> clean_hosts.txt
  python main.py --no-scrape          # fallback pool only (fast test)
  python main.py --reuse-harvest      # skip harvest, use harvest_cache.json
  python main.py --probe              # ZERO-RATING probe on zero-balance SIM
  python main.py --serve              # dashboard after scanning
  python main.py --no-scrape --probe  # probe the fallback pool directly
"""

from __future__ import annotations

import asyncio
import json
import logging
import sys
import time

import scanner
import scraper


# ---------------------------------------------------------------------------
# Scan pipeline
# ---------------------------------------------------------------------------


async def run_pipeline(no_scrape, reuse_harvest, concurrency, output):
    if no_scrape:
        hosts = list(scraper.FALLBACK_POOL)
    elif reuse_harvest:
        cached = scraper.load_cache()
        if cached:
            hosts = cached
            logging.info("using cached harvest: %d hosts", len(hosts))
        else:
            logging.warning("no harvest cache found — running full harvest")
            hosts = await scraper.harvest_all()
    else:
        hosts = await scraper.harvest_all()

    results = await scanner.scan_hosts(hosts, concurrency=concurrency)

    counts = {}
    for r in results:
        counts[r.verdict] = counts.get(r.verdict, 0) + 1
    for verdict, count in sorted(counts.items()):
        logging.info("  %-12s %d", verdict, count)

    working = scanner.filter_working(results)
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(scanner.working_hosts_text(results) + "\n")
    logging.info("scan complete: %d/%d hosts working -> %s",
                 len(working), len(results), output)
    return results


def run_probe(output):
    """
    Zero-rating probe. Run on the TARGET zero-balance SIM:
    mobile data ON, Wi-Fi OFF, no airtime.
    """
    try:
        with open(output, "r", encoding="utf-8") as fh:
            candidates = [line.strip() for line in fh if line.strip()]
    except OSError:
        logging.error("cannot read %s — run a scan first", output)
        return

    hosts = [c.split(":")[0] for c in candidates]
    logging.info("probing %d hosts for zero-rating on THIS SIM...", len(hosts))
    free = asyncio.run(scanner.probe_hosts(hosts, concurrency=20))
    good = [r for r in free if r["zero_rated"]]

    with open("zero_rated_hosts.txt", "w", encoding="utf-8") as fh:
        fh.write("\n".join(f"{r['host']}:{r['port']}" for r in good) + "\n")

    logging.info("=" * 60)
    logging.info("ZERO-RATED VERIFIED: %d/%d hosts -> zero_rated_hosts.txt",
                 len(good), len(hosts))
    logging.info("These are the hosts YOUR carrier lets through free.")
    logging.info("Paste those into HA Tunnel Plus / Stark VPN.")
    logging.info("=" * 60)


# ---------------------------------------------------------------------------
# Dashboard — aiohttp, Termux-proof, Luphahla Bugscan theme
# ---------------------------------------------------------------------------

THEME_CSS = """
<style>
:root { --red:#ef4444; --violet:#7c3aed; --indigo:#4f46e5; }
body { background:linear-gradient(160deg,#0b0614 0%,#14041f 50%,#0a0418 100%);
       color:#e5e7eb; min-height:100vh; font-family:system-ui,sans-serif; }
.hero { background:linear-gradient(90deg,var(--red),var(--violet),var(--indigo));
        padding:3px; border-radius:16px; }
.hero-inner { background:#0d0518; border-radius:14px; padding:24px; }
.title { font-size:2rem; font-weight:800;
         background:linear-gradient(90deg,#f87171,#a78bfa,#818cf8);
         -webkit-background-clip:text; background-clip:text; color:transparent; }
.badge { background:linear-gradient(90deg,var(--red),var(--violet));
         color:#fff; padding:2px 10px; border-radius:999px; font-size:.75rem; }
table { width:100%; border-collapse:collapse; }
thead { background:linear-gradient(90deg,rgba(239,68,68,.25),rgba(124,58,237,.25)); }
th { text-align:left; padding:12px 16px; font-size:.7rem; letter-spacing:.08em;
     text-transform:uppercase; color:#c4b5fd; }
td { padding:8px 16px; font-family:monospace; font-size:.8rem;
     border-top:1px solid rgba(124,58,237,.2); }
tr:hover td { background:rgba(124,58,237,.12); }
.v-fast    { color:#f87171; font-weight:700; }   /* red = fastest */
.v-usable  { color:#a78bfa; font-weight:700; }   /* violet = usable */
.v-throt   { color:#fbbf24; }
.v-tls     { color:#6b7280; }
.v-mitm    { color:#e879f9; }
a { color:#a78bfa; }
.card { background:rgba(124,58,237,.08); border:1px solid rgba(124,58,237,.3);
        border-radius:12px; padding:12px 16px; }
</style>
"""


def build_web_app(results):
    from aiohttp import web

    STATE = {"results": results, "last_scan_epoch": time.time()}

    def _color(verdict):
        return {
            "fast": "v-fast", "usable": "v-usable",
            "throttled": "v-throt", "tls-blocked": "v-tls",
            "proxy-mitm": "v-mitm", "blocked": "v-tls",
        }.get(verdict, "v-tls")

    async def dashboard(request):
        working = scanner.filter_working(STATE["results"])
        last = time.strftime("%Y-%m-%d %H:%M UTC",
                             time.gmtime(STATE["last_scan_epoch"]))
        rows = ""
        for i, r in enumerate(working, 1):
            rows += (
                f"<tr><td>{i}</td>"
                f"<td>{r.host}</td>"
                f"<td>{r.port}</td>"
                f"<td class='{_color(r.verdict)}'>{r.verdict}</td>"
                f"<td>{r.speed_kbps or '—'}</td>"
                f"<td>{r.latency_ms or '—'}</td>"
                f"<td style='color:#9ca3af'>{r.server_header or '—'}</td>"
                f"<td>{r.status_code or '—'}</td></tr>"
            )
        html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Luphahla Bugscan</title>{THEME_CSS}</head>
<body><div class="hero"><div class="hero-inner">
  <h1 class="title">Luphahla Bugscan</h1>
  <p style="color:#9ca3af;font-size:.85rem">
    <span class="badge">LIVE</span>
    Last scan: {last} &middot;
    <span style="color:#f87171;font-weight:700">{len(working)}</span>
    verified SNI hosts out of {len(STATE['results'])} scanned
  </p>
  <div style="overflow-x:auto;border:1px solid rgba(124,58,237,.35);
              border-radius:12px;margin-top:18px">
    <table>
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>Verdict</th>
      <th>KB/s</th><th>Latency ms</th><th>Server</th><th>Status</th></tr></thead>
      <tbody>{rows or '<tr><td colspan="8" style="text-align:center;color:#6b7280">No working hosts yet.</td></tr>'}</tbody>
    </table>
  </div>
  <div class="card" style="margin-top:18px;font-size:.8rem;color:#9ca3af">
    SNI feed: <a href="/hosts">/hosts</a> &middot;
    JSON: <a href="/api/results">/api/results</a><br>
    Run <b style="color:#f87171">python main.py --no-scrape --probe</b> on your
    zero-balance SIM to verify which of these are truly FREE.
  </div>
</div></div></body></html>"""
        return web.Response(text=html, content_type="text/html")

    async def hosts_feed(request):
        body = scanner.working_hosts_text(STATE["results"])
        return web.Response(text=body + "\n", content_type="text/plain")

    async def api_results(request):
        payload = {
            "tool": "Luphahla Bugscan",
            "last_scan_epoch": STATE["last_scan_epoch"],
            "results": [r.to_row() for r in STATE["results"]],
        }
        return web.Response(text=json.dumps(payload),
                            content_type="application/json")

    async def favicon(request):
        return web.Response(status=204)

    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/hosts", hosts_feed)
    app.router.add_get("/api/results", api_results)
    app.router.add_get("/favicon.ico", favicon)
    return app


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------


def main():
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    args = sys.argv[1:]

    no_scrape = "--no-scrape" in args
    reuse_harvest = "--reuse-harvest" in args
    probe = "--probe" in args
    serve = "--serve" in args
    output = "clean_hosts.txt"
    if "--output" in args:
        output = args[args.index("--output") + 1]
    concurrency = (int(args[args.index("--concurrency") + 1])
                   if "--concurrency" in args else 250)

    if probe:
        run_probe(output)
        return 0

    results = asyncio.run(run_pipeline(no_scrape, reuse_harvest,
                                       concurrency, output))

    if serve:
        from aiohttp import web
        logging.info("Luphahla Bugscan dashboard live on http://0.0.0.0:8000")
        web.run_app(build_web_app(results), host="0.0.0.0", port=8000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
