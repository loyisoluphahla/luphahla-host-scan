"""
render_app.py — Luphahla Bugscan live web service for Render.com.

Fixes over v1:
  - Self-ping keep-alive: free tier sleeps after 15 min of HTTP idleness,
    which killed the first scan mid-harvest. We ping /healthz every 5 min.
  - Quick pass: verifies the embedded fallback pool at startup so hosts
    appear within ~3 minutes instead of "first scan running…" forever.
  - Cold-start seed: reloads last results from disk, and unverified hosts
    from the GitHub clean_hosts.txt, so restarts are not blind.
  - Country selector: per-country ISP/TLD harvesting (zw, za, ng, ke, gh,
    zm, ug, tz). Visiting ?country=xx triggers an on-demand scan.
  - Errors visible: dashboard shows last scan error, not silence.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

import aiohttp
from aiohttp import web

import scanner
import scraper

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)-7s %(message)s")
log = logging.getLogger("luphahla.render")

PORT = int(os.environ.get("PORT", 8000))
DEFAULT_COUNTRY = "zw"
REPO_RAW = ("https://raw.githubusercontent.com/"
            "loyisoluphahla/luphahla-host-scan/main")
SCAN_INTERVAL_S = 2 * 60 * 60
KEEPALIVE_EVERY_S = 5 * 60
CRT_TIMEOUT_S = 30

# ---------------------------------------------------------------------------
# Country maps — ISPs + gov/edu TLDs swept per country
# ---------------------------------------------------------------------------

COUNTRIES = {
    "all": {"label": "\U0001F30D Global / All",
            "tlds": ("gov.zw", "edu.zw", "gov.za", "edu.za",
                     "gov.ng", "gov.ke"),
            "orgs": ("econet", "netone", "telone", "liquidtelecom",
                     "mtn", "vodacom", "safaricom", "airtel",
                     "glo", "9mobile"),
            "isps": ()},
    "zw": {"label": "\U0001F1FF\U0001F1FC Zimbabwe",
           "tlds": ("gov.zw", "edu.zw"),
           "orgs": ("econet", "netone", "telone", "liquidtelecom",
                    "zol", "utande", "telecel"),
           "isps": ("econet.co.zw", "netone.co.zw", "telone.co.zw",
                    "zol.co.zw", "liquidtelecom.co.zw",
                    "utande.co.zw", "telecel.co.zw")},
    "za": {"label": "\U0001F1FF\U0001F1E6 South Africa",
           "tlds": ("gov.za", "edu.za"),
           "orgs": ("mtn", "vodacom", "cellc", "telkom",
                    "rain", "openserve"),
           "isps": ("mtn.co.za", "vodacom.co.za", "cellc.co.za",
                    "telkom.co.za", "rain.co.za", "openserve.co.za")},
    "ng": {"label": "\U0001F1F3\U0001F1EC Nigeria",
           "tlds": ("gov.ng",),
           "orgs": ("mtn", "glo", "9mobile", "airtel"),
           "isps": ("mtnonline.com", "glo.com.ng",
                    "9mobile.com.ng", "airtel.com.ng")},
    "ke": {"label": "\U0001F1F0\U0001F1EA Kenya",
           "tlds": ("gov.ke",),
           "orgs": ("safaricom", "airtel", "telkom"),
           "isps": ("safaricom.co.ke", "airtel.co.ke",
                    "telkom.co.ke")},
    "gh": {"label": "\U0001F1EC\U0001F1ED Ghana",
           "tlds": ("gov.gh", "edu.gh"),
           "orgs": ("mtn", "vodafone", "airteltigo"),
           "isps": ("mtn.com.gh", "vodafone.com.gh",
                    "airteltigo.com.gh")},
    "zm": {"label": "\U0001F1FF\U0001F1F2 Zambia",
           "tlds": ("gov.zm", "edu.zm"),
           "orgs": ("airtel", "mtn", "zamtel", "liquidtelecom"),
           "isps": ("airtel.co.zm", "mtn.co.zm", "zamtel.co.zm")},
    "ug": {"label": "\U0001F1FA\U0001F1EC Uganda",
           "tlds": ("gov.ug",),
           "orgs": ("mtn", "airtel", "lycamobile"),
           "isps": ("mtn.co.ug", "airtel.co.ug")},
    "tz": {"label": "\U0001F1F9\U0001F1FF Tanzania",
           "tlds": ("gov.tz",),
           "orgs": ("vodacom", "airtel", "tigo", "halotel"),
           "isps": ("vodacom.co.tz", "airtel.co.tz")},
}

# ---------------------------------------------------------------------------
# Per-country state
# ---------------------------------------------------------------------------

STATE = {}

def state(cc):
    if cc not in STATE:
        STATE[cc] = {"results": [], "scanning": False,
                     "last_epoch": 0.0, "scan_count": 0,
                     "last_error": "", "phase": ""}
    return STATE[cc]


def persist(cc):
    try:
        with open(f"render_results_{cc}.json", "w", encoding="utf-8") as fh:
            json.dump({"epoch": state(cc)["last_epoch"],
                       "count": state(cc)["scan_count"],
                       "rows": _rows_json(state(cc)["results"])}, fh)
    except OSError as exc:
        log.warning("persist %s failed: %s", cc, exc)


def restore(cc):
    try:
        with open(f"render_results_{cc}.json", "r", encoding="utf-8") as fh:
            data = json.load(fh)
        state(cc)["last_epoch"] = data.get("epoch", 0.0)
        state(cc)["scan_count"] = data.get("count", 0)
        log.info("restored %s results from disk (%d rows)",
                 cc, len(data.get("rows", [])))
    except (OSError, ValueError):
        pass


def _rows_json(results):
    return [{"host": r.host, "port": r.port, "verdict": r.verdict,
             "reason": r.reason, "speed_kbps": r.speed_kbps,
             "latency_ms": r.latency_ms, "status_code": r.status_code,
             "server_header": r.server_header}
            for r in results]

# ---------------------------------------------------------------------------
# Harvesting (country-aware) + verification
# ---------------------------------------------------------------------------


async def _crt_sh(session, query, sem):
    url = f"https://crt.sh/?q=%.{query}&output=json"
    out = set()
    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=CRT_TIMEOUT_S),
                headers={"User-Agent": "luphahla-bugscan/3.0"}) as resp:
                if resp.status != 200:
                    return out
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return out
    if not isinstance(data, list):
        return out
    for entry in data[:500]:
        for cand in str(entry.get("name_value", "")).split("\n"):
            cand = cand.strip().lstrip("*.").lower()
            if cand and "." in cand and " " not in cand:
                out.add(cand)
    return out


async def harvest_country(session, cc, sem):
    cfg = COUNTRIES[cc]
    queries = list(cfg["tlds"]) + list(cfg["orgs"]) + list(cfg["isps"])
    tasks = [_crt_sh(session, q, sem) for q in queries]
    tasks.append(scraper.harvest_github_lists(session))
    done = await asyncio.gather(*tasks, return_exceptions=True)
    pools = [scraper.FALLBACK_POOL]
    pools += [item for item in done if isinstance(item, set)]
    hosts = scraper.merge_and_dedup(*pools)
    log.info("harvest[%s]: %d unique hosts", cc, len(hosts))
    return hosts


async def verify_and_store(cc, hosts):
    st = state(cc)
    st["phase"] = f"verifying {len(hosts)} hosts"
    results = await scanner.scan_hosts(hosts, concurrency=100)
    working = scanner.filter_working(results)
    st["results"] = results
    st["last_epoch"] = time.time()
    st["scan_count"] += 1
    st["last_error"] = ""
    st["phase"] = "idle"
    persist(cc)
    log.info("scan[%s] done: %d working hosts", cc, len(working))
    return working

# ---------------------------------------------------------------------------
# Background scan pipeline (per country)
# ---------------------------------------------------------------------------


async def country_scan_task(app, cc):
    st = state(cc)
    while True:
        try:
            st["scanning"] = True
            connector = aiohttp.TCPConnector(limit=8)
            sem = asyncio.Semaphore(8)
            async with aiohttp.ClientSession(connector=connector) as session:
                # Quick pass — embedded pool, no harvest wait, results fast
                st["phase"] = "quick pass (fallback pool)"
                await verify_and_store(cc, list(scraper.FALLBACK_POOL))
                # Deep pass — country harvest + verify
                st["phase"] = "deep harvest (crt.sh + ISPs + lists)"
                hosts = await harvest_country(session, cc, sem)
                await verify_and_store(cc, hosts)
        except Exception as exc:
            st["last_error"] = f"{type(exc).__name__}: {exc}"
            log.exception("scan[%s] failed", cc)
        finally:
            st["scanning"] = False
            st["phase"] = "idle"
        await asyncio.sleep(SCAN_INTERVAL_S)


def ensure_scan_task(app, cc):
    running = app["scan_tasks"]
    if cc not in running or running[cc].done():
        running[cc] = asyncio.create_task(country_scan_task(app, cc))
        log.info("scan task started for %s", cc)


async def keepalive_task(app):
    """Ping ourselves so Render never sleeps mid-scan (15-min idle limit)."""
    url = f"http://127.0.0.1:{PORT}/healthz"
    while True:
        await asyncio.sleep(KEEPALIVE_EVERY_S)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url,
                                 timeout=aiohttp.ClientTimeout(total=10)):
                    pass
            log.info("keep-alive ping ok")
        except Exception as exc:
            log.warning("keep-alive ping failed: %s", exc)

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
select { background:#1b0b2e; color:#e5e7eb; border:1px solid var(--violet);
         border-radius:8px; padding:6px 10px; font-size:.85rem; }
button { background:linear-gradient(90deg,var(--red),var(--violet));
         color:#fff; border:0; border-radius:8px; padding:6px 16px;
         font-size:.85rem; cursor:pointer; }
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
.err { color:#f87171; }
</style>
"""


def _color(verdict):
    return {"fast": "v-fast", "usable": "v-usable", "throttled": "v-throt",
            "tls-blocked": "v-tls", "proxy-mitm": "v-mitm",
            "blocked": "v-tls"}.get(verdict, "v-tls")


async def dashboard(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    if cc not in COUNTRIES:
        cc = DEFAULT_COUNTRY
    ensure_scan_task(request.app, cc)
    st = state(cc)

    last = (time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime(st["last_epoch"]))
            if st["last_epoch"] else "never completed yet")
    scanning = ('<span class="badge pulse">SCANNING</span>'
                if st["scanning"] else '<span class="badge">LIVE</span>')
    working = scanner.filter_working(st["results"])

    top_cards = ""
    for i, r in enumerate(working[:3], 1):
        top_cards += (f'<div class="card">#{i} FASTEST<br>'
                      f'<b>{r.host}</b><br>'
                      f'{r.speed_kbps or "—"} KB/s &middot; '
                      f'port {r.port} &middot; {r.verdict}</div>')

    rows = ""
    for i, r in enumerate(working, 1):
        rows += (f"<tr><td>{i}</td><td>{r.host}</td><td>{r.port}</td>"
                 f"<td class='{_color(r.verdict)}'>{r.verdict}</td>"
                 f"<td>{r.speed_kbps or '—'}</td>"
                 f"<td>{r.latency_ms or '—'}</td>"
                 f"<td style='color:#9ca3af'>{r.server_header or '—'}</td>"
                 f"<td>{r.status_code or '—'}</td></tr>")
    if not rows:
        phase = (f"Current phase: {st['phase']}." if st["scanning"]
                 else "No results yet.")
        err = (f"<div class='err'>Last scan error: {st['last_error']}</div>"
               if st["last_error"] else "")
        rows = (f'<tr><td colspan="8" style="text-align:center;color:#6b7280">'
                f'{phase} The quick pass lands in ~2–3 min after startup; '
                f'the deep pass takes 10–20 min. Keep this page open or '
                f'refresh — the self-ping keeps the scanner awake.</td></tr>'
                f'{err}')

    options = "".join(
        f'<option value="{c}" {"selected" if c == cc else ""}>'
        f'{COUNTRIES[c]["label"]}</option>' for c in COUNTRIES)

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>Luphahla Bugscan — Live</title>{THEME_CSS}</head>
<body><div class="hero"><div class="hero-inner">
  <h1 class="title">Luphahla Bugscan</h1>
  <p style="color:#9ca3af;font-size:.85rem">
    {scanning} {COUNTRIES[cc]['label']} &middot;
    Last scan: {last} &middot; Cycle #{st['scan_count']} &middot;
    <span style="color:#f87171;font-weight:700">{len(working)}</span>
    verified SNI hosts out of {len(st['results'])} scanned
  </p>
  <form method="get" action="/" style="margin:12px 0">
    <label style="font-size:.8rem;color:#c4b5fd">Scan within country ISP:
    </label>
    <select name="country" onchange="this.form.submit()">{options}</select>
    <button type="submit">Scan this country</button>
  </form>
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
    SNI feed: <a href="/hosts?country={cc}">/hosts</a> &middot;
    JSON API: <a href="/api/results?country={cc}">/api/results</a> &middot;
    Top 25: <a href="/top?country={cc}">/top</a><br>
    Auto-reverifies every 2 hours &middot; selecting a country triggers an
    on-demand scan of its ISPs &middot; always confirm on your zero-balance
    SIM before tunneling.
  </div>
</div></div></body></html>"""
    return web.Response(text=html, content_type="text/html")


async def hosts_feed(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    ensure_scan_task(request.app, cc)
    body = scanner.working_hosts_text(state(cc)["results"])
    return web.Response(text=(body + "\n") if body else "# scanning…\n",
                        content_type="text/plain")


async def top_hosts(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    ensure_scan_task(request.app, cc)
    working = scanner.filter_working(state(cc)["results"])[:25]
    lines = [f"{r.host}:{r.port}" for r in working]
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


async def api_results(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    ensure_scan_task(request.app, cc)
    st = state(cc)
    return web.Response(
        text=json.dumps({
            "tool": "Luphahla Bugscan",
            "country": cc,
            "scanning": st["scanning"],
            "phase": st["phase"],
            "last_error": st["last_error"],
            "scan_count": st["scan_count"],
            "last_scan_epoch": st["last_epoch"],
            "results": _rows_json(st["results"]),
        }),
        content_type="application/json")


async def health(request):
    return web.Response(text="ok", content_type="text/plain")


async def favicon(request):
    return web.Response(status=204)

# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------


def build_app():
    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/hosts", hosts_feed)
    app.router.add_get("/top", top_hosts)
    app.router.add_get("/api/results", api_results)
    app.router.add_get("/healthz", health)
    app.router.add_get("/favicon.ico", favicon)

    async def start_background(app):
        app["scan_tasks"] = {}
        for cc in (DEFAULT_COUNTRY,):
            restore(cc)
        app["keepalive"] = asyncio.create_task(keepalive_task(app))
        ensure_scan_task(app, DEFAULT_COUNTRY)
        log.info("Luphahla Bugscan live on port %d — keep-alive active",
                 PORT)

    async def stop_background(app):
        app["keepalive"].cancel()
        for task in app["scan_tasks"].values():
            task.cancel()

    app.on_startup.append(start_background)
    app.on_cleanup.append(stop_background)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
