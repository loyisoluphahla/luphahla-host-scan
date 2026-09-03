"""
render_app.py - Luphahla Bugscan web service (Render + local).

Serves the redesigned dashboard (static/index.html + /static assets)
and exposes the JSON/feed APIs the UI reads.

Routes (all original routes/params preserved):
    GET  /                     dashboard (?country= ensures scan task runs)
    GET  /hosts                 plain-text verified SNI feed (?country=)
    GET  /top                   top 25 working hosts (?country=)
    GET  /api/results           full scan JSON for a country (?country=)
    GET  /api/config            UI config (countries, ports, interval, feeds)
    POST /api/scan             force an on-demand scan for a country
    GET  /healthz               health check (Render + keep-alive pings)
    GET  /favicon.ico           204

Scan engine unchanged: country-aware harvest -> verify -> auto re-verify
every SCAN_INTERVAL_S. Keep-alive self-pings /healthz so the Render free
tier never sleeps mid-scan.
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
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
INDEX_FILE = os.path.join(STATIC_DIR, "index.html")

SCAN_INTERVAL_S = 2 * 60 * 60      # auto-reverify every 2 hours
KEEPALIVE_EVERY_S = 5 * 60         # self-ping: survive free-tier 15-min idle
CRT_TIMEOUT_S = 30

# ---------------------------------------------------------------------------
# Country maps - ISPs + gov/edu TLDs swept per country (unchanged)
# ---------------------------------------------------------------------------

COUNTRIES = {
    "all": {"label": "Global / All",
            "tlds": ("gov.zw", "edu.zw", "gov.za", "edu.za",
                     "gov.ng", "gov.ke"),
            "orgs": ("econet", "netone", "telone", "liquidtelecom",
                     "mtn", "vodacom", "safaricom", "airtel",
                     "glo", "9mobile"),
            "isps": ()},
    "zw": {"label": "Zimbabwe",
           "tlds": ("gov.zw", "edu.zw"),
           "orgs": ("econet", "netone", "telone", "liquidtelecom",
                    "zol", "utande", "telecel"),
           "isps": ("econet.co.zw", "netone.co.zw", "telone.co.zw",
                    "zol.co.zw", "liquidtelecom.co.zw",
                    "utande.co.zw", "telecel.co.zw")},
    "za": {"label": "South Africa",
           "tlds": ("gov.za", "edu.za"),
           "orgs": ("mtn", "vodacom", "cellc", "telkom",
                    "rain", "openserve"),
           "isps": ("mtn.co.za", "vodacom.co.za", "cellc.co.za",
                    "telkom.co.za", "rain.co.za", "openserve.co.za")},
    "ng": {"label": "Nigeria",
           "tlds": ("gov.ng",),
           "orgs": ("mtn", "glo", "9mobile", "airtel"),
           "isps": ("mtnonline.com", "glo.com.ng",
                    "9mobile.com.ng", "airtel.com.ng")},
    "ke": {"label": "Kenya",
           "tlds": ("gov.ke",),
           "orgs": ("safaricom", "airtel", "telkom"),
           "isps": ("safaricom.co.ke", "airtel.co.ke",
                    "telkom.co.ke")},
    "gh": {"label": "Ghana",
           "tlds": ("gov.gh", "edu.gh"),
           "orgs": ("mtn", "vodafone", "airteltigo"),
           "isps": ("mtn.com.gh", "vodafone.com.gh",
                    "airteltigo.com.gh")},
    "zm": {"label": "Zambia",
           "tlds": ("gov.zm", "edu.zm"),
           "orgs": ("airtel", "mtn", "zamtel", "liquidtelecom"),
           "isps": ("airtel.co.zm", "mtn.co.zm", "zamtel.co.zm")},
    "ug": {"label": "Uganda",
           "tlds": ("gov.ug",),
           "orgs": ("mtn", "airtel", "lycamobile"),
           "isps": ("mtn.co.ug", "airtel.co.ug")},
    "tz": {"label": "Tanzania",
           "tlds": ("gov.tz",),
           "orgs": ("vodacom", "airtel", "tigo", "halotel"),
           "isps": ("vodacom.co.tz", "airtel.co.tz")},
}

# ---------------------------------------------------------------------------
# Per-country state (unchanged)
# ---------------------------------------------------------------------------

STATE = {}


def state(cc):
    if cc not in STATE:
        STATE[cc] = {"results": [], "scanning": False,
                     "last_epoch": 0.0, "scan_count": 0,
                     "last_error": "", "phase": ""}
    return STATE[cc]


def _rows_json(results):
    return [{"host": r.host, "port": r.port, "verdict": r.verdict,
             "reason": r.reason, "speed_kbps": r.speed_kbps,
             "latency_ms": r.latency_ms, "status_code": r.status_code,
             "server_header": r.server_header}
            for r in results]


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
        log.info("restored %s metadata from disk (%d rows cached)",
                 cc, len(data.get("rows", [])))
    except (OSError, ValueError):
        pass


def _resolve_cc(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    return cc if cc in COUNTRIES else DEFAULT_COUNTRY


# ---------------------------------------------------------------------------
# Harvesting + verification (unchanged)
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
# Background scan pipeline + keep-alive (unchanged)
# ---------------------------------------------------------------------------


async def country_scan_task(app, cc):
    st = state(cc)
    while True:
        try:
            st["scanning"] = True
            connector = aiohttp.TCPConnector(limit=8)
            sem = asyncio.Semaphore(8)
            async with aiohttp.ClientSession(connector=connector) as session:
                st["phase"] = "quick pass (fallback pool)"
                await verify_and_store(cc, list(scraper.FALLBACK_POOL))
                st["phase"] = "deep harvest (crt.sh + ISPs + lists)"
                hosts = await harvest_country(session, cc, sem)
                await verify_and_store(cc, hosts)
        except asyncio.CancelledError:
            log.info("scan task cancelled for %s", cc)
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


async def force_rescan(app, cc):
    """Cancel any running task for cc and start a fresh one immediately."""
    tasks = app["scan_tasks"]
    old = tasks.get(cc)
    if old and not old.done():
        old.cancel()
        await asyncio.gather(old, return_exceptions=True)
    st = state(cc)
    st["phase"] = "queued - starting fresh scan"
    st["scanning"] = False
    tasks[cc] = asyncio.create_task(country_scan_task(app, cc))
    log.info("forced rescan started for %s", cc)
    return st


async def keepalive_task(app):
    """Ping ourselves so Render never sleeps mid-scan (15-min idle limit)."""
    url = f"http://127.0.0.1:{PORT}/healthz"
    while True:
        await asyncio.sleep(KEEPALIVE_EVERY_S)
        try:
            async with aiohttp.ClientSession() as s:
                async with s.get(url, timeout=aiohttp.ClientTimeout(total=10)):
                    pass
            log.info("keep-alive ping ok")
        except Exception as exc:
            log.warning("keep-alive ping failed: %s", exc)


# ---------------------------------------------------------------------------
# Web handlers - UI reads real data from these JSON endpoints
# ---------------------------------------------------------------------------


async def dashboard(request):
    cc = _resolve_cc(request)
    ensure_scan_task(request.app, cc)
    try:
        return web.FileResponse(INDEX_FILE)
    except OSError:
        html = ("<h1>Luphahla Bugscan</h1>"
                "<p>static/index.html not found - run <code>git pull</code> "
                "so the <code>static/</code> folder is present, then "
                "redeploy.</p>"
                "<p>Raw data still live: <a href='/api/results'>/api/results"
                "</a> | <a href='/hosts'>/hosts</a> | <a href='/top'>/top"
                "</a></p>")
        return web.Response(text=html, content_type="text/html", status=503)


async def hosts_feed(request):
    cc = _resolve_cc(request)
    ensure_scan_task(request.app, cc)
    body = scanner.working_hosts_text(state(cc)["results"])
    return web.Response(text=(body + "\n") if body else "# scanning...\n",
                        content_type="text/plain")


async def top_hosts(request):
    cc = _resolve_cc(request)
    ensure_scan_task(request.app, cc)
    working = scanner.filter_working(state(cc)["results"])[:25]
    lines = [f"{r.host}:{r.port}" for r in working]
    return web.Response(text="\n".join(lines) + "\n", content_type="text/plain")


async def api_results(request):
    cc = _resolve_cc(request)
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


async def api_config(request):
    return web.Response(
        text=json.dumps({
            "tool": "Luphahla Bugscan",
            "subtitle": "Network Diagnostics",
            "ports": list(scanner.PORTS),
            "reverify_every_s": SCAN_INTERVAL_S,
            "default_country": DEFAULT_COUNTRY,
            "countries": COUNTRIES,
            "endpoints": {
                "dashboard": "/",
                "hosts": "/hosts",
                "top": "/top",
                "results": "/api/results",
                "config": "/api/config",
                "scan": "/api/scan",
                "health": "/healthz",
            },
        }),
        content_type="application/json")


async def api_scan(request):
    cc = DEFAULT_COUNTRY
    try:
        data = await request.json()
        cc = data.get("country", cc)
    except Exception:
        cc = request.query.get("country", cc)
    if cc not in COUNTRIES:
        cc = DEFAULT_COUNTRY
    st = await force_rescan(request.app, cc)
    return web.json_response({"ok": True, "country": cc,
                              "scanning": st["scanning"],
                              "phase": st["phase"]})


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
    app.router.add_get("/api/config", api_config)
    app.router.add_post("/api/scan", api_scan)
    app.router.add_get("/healthz", health)
    app.router.add_get("/favicon.ico", favicon)

    if os.path.isdir(STATIC_DIR):
        app.router.add_static("/static/", STATIC_DIR, show_index=False)
        log.info("static UI mounted from %s", STATIC_DIR)
    else:
        log.warning("static dir missing at %s - UI will not load", STATIC_DIR)

    async def start_background(app):
        app["scan_tasks"] = {}
        for cc in (DEFAULT_COUNTRY,):
            restore(cc)
        app["keepalive"] = asyncio.create_task(keepalive_task(app))
        ensure_scan_task(app, DEFAULT_COUNTRY)
        log.info("Luphahla Bugscan live on port %d - keep-alive active", PORT)

    async def stop_background(app):
        app["keepalive"].cancel()
        for task in app["scan_tasks"].values():
            task.cancel()

    app.on_startup.append(start_background)
    app.on_cleanup.append(stop_background)
    return app


if __name__ == "__main__":
    web.run_app(build_app(), host="0.0.0.0", port=PORT)
