"""
Luphahla Bugscan — CLI orchestrator.

Usage:
  python main.py                      # harvest + scan -> clean_hosts.txt
  python main.py --no-scrape          # fallback pool only (fast test)
  python main.py --reuse-harvest      # skip harvest, use harvest_cache.json
  python main.py --pull               # pull verified working hosts from the
                                      #   Render service (LUPHAHLA_API env or
                                      #   default https://luphahla-bugscan.onrender.com)
  python main.py --probe              # ZERO-RATING probe on zero-balance SIM
  python main.py --serve              # dashboard after scanning
  python main.py --pull --probe       # pull from server, then probe on carrier

Environment:
  LUPHAHLA_API    base URL of the Render service (default shown above)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time

import aiohttp

import scanner
import scraper

RENDER_API = os.environ.get(
    "LUPHAHLA_API", "https://luphahla-bugscan.onrender.com"
).rstrip("/")


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
    # Plain machine-readable format: one host:port per line, score-ordered.
    with open(output, "w", encoding="utf-8") as fh:
        fh.write(scanner.working_hosts_plain(results) + "\n")
    logging.info("scan complete: %d/%d hosts working -> %s",
                 len(working), len(results), output)
    return results


# ---------------------------------------------------------------------------
# Pull verified working hosts from the Render service
# ---------------------------------------------------------------------------


async def pull_from_server(output, top_n=1000):
    """Fetch the service's verified working host list (uses /top, which
    returns only working verdicts, unlike /hosts which returns all rows)."""
    url = f"{RENDER_API}/top?n={top_n}"
    async with aiohttp.ClientSession() as session:
        async with session.get(
            url, timeout=aiohttp.ClientTimeout(total=60)
        ) as resp:
            resp.raise_for_status()
            rows = await resp.json()

    hosts = sorted({f"{row['host']}:{row['port']}" for row in rows})
    with open(output, "w", encoding="utf-8") as fh:
        fh.write("\n".join(hosts) + "\n")
    logging.info("pulled %d working hosts from %s -> %s",
                 len(hosts), RENDER_API, output)
    return hosts


# ---------------------------------------------------------------------------
# Zero-rating probe
# ---------------------------------------------------------------------------


def run_probe(output):
    """
    Zero-rating probe. Run on the TARGET zero-balance SIM:
    mobile data ON, Wi-Fi OFF, no airtime.
    """
    try:
        with open(output, "r", encoding="utf-8") as fh:
            candidates = [line.strip() for line in fh if line.strip()]
    except OSError:
        logging.error("cannot read %s — run a scan or --pull first", output)
        return

    # Accept both plain "host:port" lines and annotated
    # "host:port  #score v=... sni=... kbps=..." lines.
    cleaned = []
    for line in candidates:
        entry = line.split("#", 1)[0].strip()
        if entry:
            cleaned.append(entry)

    logging.info("probing %d candidates on this carrier...", len(cleaned))
    results = asyncio.run(scanner.probe_hosts(cleaned))

    free = [r for r in results if r["handshake_ok"]]
    blocked = [r for r in results if not r["handshake_ok"]]

    free_hosts = "\n".join(f"{r['host']}:{r['port']}" for r in free)
    with open("free_hosts.txt", "w", encoding="utf-8") as fh:
        fh.write(free_hosts + "\n" if free_hosts else "")

    logging.info("probe done: %d FREE, %d blocked -> free_hosts.txt",
                 len(free), len(blocked))


# ---------------------------------------------------------------------------
# Dashboard (unchanged)
# ---------------------------------------------------------------------------

THEME_CSS = """
<style>
/* ... keep your existing THEME_CSS block here, unchanged ... */
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
    pull = "--pull" in args
    output = "clean_hosts.txt"
    if "--output" in args:
        output = args[args.index("--output") + 1]
    concurrency = (int(args[args.index("--concurrency") + 1])
                   if "--concurrency" in args else 250)

    if pull:
        asyncio.run(pull_from_server(output))
        if probe:
            run_probe(output)
        return 0

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
