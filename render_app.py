"""
render_app.py — Luphahla Bugscan live web service for Render.com.

Binds to $PORT immediately (Render requirement), then runs a continuous
harvest -> scan -> verify loop in the background. Dashboard shows top
domains ranked by speed, refreshing after every scan cycle.

Deploy: connect your GitHub repo to Render with render.yaml.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

from aiohttp import web

import scanner
import scraper

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(message)s")
log = logging.getLogger("luphahla.render")

PORT = int(os.environ.get("PORT", 8000))
SCAN_INTERVAL_S = 2 * 60 * 60  # rescan every 2 hours

STATE = {
    "results": [],
    "last_scan_epoch": 0.0,
    "scanning": False,
    "scan_count": 0,
}


# ---------------------------------------------------------------------------
# Background scan loop
# ---------------------------------------------------------------------------


async def scan_loop(app):
    """Harvest + scan at startup, then every SCAN_INTERVAL_S forever."""
    while True:
        try:
            STATE["scanning"] = True
            log.info("scan cycle starting...")
            hosts = await scraper.harvest_all()
            log.info("harvest: %d hosts — scanning...", len(hosts))
            # Render free tier = 512MB RAM / shared CPU; keep concurrency sane
            results = await scanner.scan_hosts(hosts, concurrency=100)
            STATE["results"] = results
            STATE["last_scan_epoch"] = time.time()
            STATE["scan_count"] += 1
            working = scanner.filter_working(results)
            log.info("scan done: %d working hosts", len(working))
            # Persist for Render's ephemeral disk (resets on redeploy — fine)
            with open("clean_hosts.txt", "w", encoding="utf-8") as fh:
                fh.write(scanner.working_hosts_text(results) + "\n")
        except Exception as exc:
            log.exception("scan cycle failed: %s", exc)
        finally:
            STATE["scanning"] = False
        await asyncio.sleep(SCAN_INTERVAL_S)


# ---------------------------------------------------------------------------
# Web UI — Luphahla Bugscan theme (red / violet-blue)
# ---------------------------------------------------------------------------

THEME_CSS = """
<style>
:root { --red:#ef4444; --violet:#7c3aed; --indigo:#4f46e5; }
body { background:linear-gradient(160deg,#0b0614 0%,#14041f 50%,#0a0418 100%);
       color:#e5e7eb; min-height:100vh; font-family:system-ui,sans-serif; margin:0; }
.hero { background:linear-gradient(90deg,var(--red),var(--violet),var(--indigo));
        padding:3px; border-radius:16px; max-width:1100px; margin:24px auto; }
.hero-inner { background:#0d0518; border-radius:14px; padding:24px; }
.title { font-size:2rem; font-weight:800; margin:0;
         background:linear-gradient(90deg,#f87171,#a78bfa,#818cf8);
         -webkit-background-clip:text; background-clip:text; color:transparent; }
.badge { background:linear-gradient(90deg,var(--red),var(--violet));
         color:#fff; padding:2px 10px; border-radius:999px; font-size:.75rem; }
table { width:100%; border-collapse:collapse; }
thead { background:linear-gradient(90deg,rgba(239,68,68,.25),rgba(124,58,237,.25)); }
th { text-align:left; padding:12px 14px; font-size:.7rem; letter-spacing:.08em;
     text-transform:uppercase; color:#c4b5fd; }
td { padding:8px 14px; font-family:monospace; font-size:.8rem;
     border-top:1px solid rgba(124,58,237,.2); }
tr:hover td { background:rgba(124,58,237,.12); }
.v-fast   { color:#f87171; font-weight:700; }
.v-usable { color:#a78bfa; font-weight:700; }
.v-throt  { color:#fbbf24; }
.v-tls    { color:#6b7280; }
.v-mitm   { color:#e879f9; }
a { color:#a78bfa; }
.card { background:rgba(124,58,237,.08); border:1px solid rgba(124,58,237,.3);
        border-radius:12px; padding:12px 16px; font-size:.8rem; color:#9ca3af; }
.top3 { display:flex; gap:12px; flex-wrap:wrap; margin:16px 0; }
.top3 .card { flex:1; min-width:220px; }
.top3 b { color:#f87171; font-family:monospace; }
.pulse { animation:p 1.2s infinite; }
@keyframes p { 50% { opacity:.4; } }
</style>
"""


def _color(verdict):
    return {"fast": "v-fast", "usable": "v-usable", "throttled": "v-throt",
            "tls-blocked": "v-tls", "proxy-mitm": "v-mitm",
            "blocked": "v-tls"}.get(verdict, "v-tls")


async def dashboard(request):
    results = STATE["results"]
    working = scanner.filter_working(results)
    last = (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(STATE["last_scan_epoch"]))
            if STATE["last_scan_epoch"] else "first scan running…")
    scanning = ('<span class="badge pulse">SCANNING</span>'
                if STATE["scanning"] else '<span class="badge">LIVE</span>')

    # Top 3 fastest hosts spotlight
    top_cards = ""
    for i, r in enumerate(working[:3], 1):
        top_cards += (f'<div class="card">#{i} FASTEST<br>'
                      f'<b>{r.host}</b><br>'
                      f'{r.speed_kbps or "—"} KB/s &middot; port {r.port} &middot; {r.verdict}</div>')

    rows = ""
    for i, r in enumerate(working, 1):
        rows += (f"<tr><td>{i}</td><td>{r.host}</td><td>{r.port}</td>"
                 f"<td class='{_color(r.verdict)}'>{r.verdict}</td>"
                 f"<td>{r.speed_kbps or '—'}</td>"
                 f"<td>{r.latency_ms or '—'}</td>"
                 f"<td style='color:#9ca3af'>{r.server_header or '—'}</td>"
                 f"<td>{r.status_code or '—'}</td></tr>")
    if not rows:
        rows = ('<tr><td colspan="8" style="text-align:center;color:#6b7280">'
                'First scan in progress — refresh in a few minutes.</td></tr>')

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Luphahla Bugscan — Live</title>{THEME_CSS}</head>
<body><div class="hero"><div class="hero-inner">
  <h1 class="title">Luphahla Bugscan</h1>
  <p style="color:#9ca3af;font-size:.85rem">
    {scanning}
    Last scan: {last} &middot;
    Cycle #{STATE['scan_count']} &middot;
    <span style="color:#f87171;font-weight:700">{len(working)}</span>
    verified SNI hosts out of {len(results)} scanned
  </p>
  <div class="top3">{top_cards}</div>
  <div style="overflow-x:auto;border:1px solid rgba(124,58,237,.35);
              border-radius:12px">
    <table>
      <thead><tr><th>#</th><th>Host</th><th>Port</th><th>Verdict</th>
      <th>KB/s</th><th>Latency ms</th><th>Server</th><th>Status</th></tr></thead>
      <tbody>{rows}</tbody>
    </table>
  </div>
  <div class="card" style="margin-top:18px">
    SNI feed: <a href="/hosts">/hosts</a> &middot;
    JSON API: <a href="/api/results">/api/results</a> &middot;
    Top 25: <a href="/top">/top</a><br>
    Verified automatically every 2 hours &middot;
    Always confirm on your zero-balance SIM before tunneling.
  </div>
</div></div></body></html>"""
    return web.Response(text=html, content_type="text/html")


async def hosts_feed(request):
    body = scanner.working_hosts_text(STATE["results"])
    return web.Response(text=(body + "\n") if body else "# scanning…\n",
                        content_type="text/plain")


async def top_hosts(request):
    working = scanner.filter_working(STATE["results"])[:25]
    lines = [f"{r.host}:{r.port}" for r in working]
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


async def api_results(request):
    return web.Response(
        text=json.dumps({
            "tool": "Luphahla Bugscan",
            "scan_count": STATE["scan_count"],
            "last_scan_epoch": STATE["last_scan_epoch"],
            "results": [r.to_row() for r in STATE["results"]],
        }),
        content_type="application/json")


async def health(request):
    return web.Response(text="ok", content_type="text/plain")


async def favicon(request):
    return web.Response(status=204)


def build_app():
    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/hosts", hosts_feed)
    app.router.add_get("/top", top_hosts)
    app.router.add_get("/api/results", api_results)
    app.router.add_get("/healthz", health)
    app.router.add_get("/favicon.ico", favicon)

    async def start_background(app):
        app["scan_task"] = asyncio.create_task(scan_loop(app))

    async def stop_background(app):
        app["scan_task"].cancel()

    app.on_startup.append(start_background)
    app.on_cleanup.append(stop_background)
    return app


if __name__ == "__main__":
    log.info("Luphahla Bugscan live on port %d", PORT)
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
