"""
render_app.py — Luphahla Bugscan Render service (aiohttp).

Changes in this version (the "Connecting... / Backend unreachable" fix):
  1. CORS middleware — every response (API + static) now carries
     Access-Control-Allow-Origin: *, so the WebView/APK dashboard can read
     the JSON APIs cross-origin.
  2. OPTIONS preflight is answered 204 + CORS headers, so the APK's
     POST /api/scan is no longer blocked.
  3. Headers are applied in one middleware — no per-handler edits.

Everything else (harvester, verifier, keep-alive, persistence, endpoint
shapes) keeps the same behavior as before.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time

import aiohttp
import scanner
import scraper
from aiohttp import web

log = logging.getLogger("luphahla.render")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("PORT", 8000))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SELF_URL = os.environ.get("SELF_URL", f"http://127.0.0.1:{PORT}")

DEFAULT_COUNTRY = "zw"
REVERIFY_EVERY_S = 1800        # live /api/config reports 1800
KEEPALIVE_EVERY_S = 600        # self-ping while awake (Render free tier)
HARVEST_TIMEOUT_S = 45
HARVEST_CONCURRENCY = 8
SCAN_CONCURRENCY = 200
HOSTS_PER_QUERY = 500

COUNTRIES = {
    "zw": {"label": "Zimbabwe",
           "tlds": ("gov.zw", "edu.zw"),
           "orgs": ("econet", "netone", "telone", "liquidtelecom",
                    "zol", "utande", "telecel"),
           "isps": ("econet.co.zw", "netone.co.zw", "telone.co.zw", "zol.co.zw",
                    "liquidtelecom.co.zw", "utande.co.zw", "telecel.co.zw")},
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
# NEW: CORS middleware — the fix for WebView/APK cross-origin reads
# ---------------------------------------------------------------------------

@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        resp = web.Response(status=204)
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp

# ---------------------------------------------------------------------------
# Harvesting + verification (unchanged behavior)
# ---------------------------------------------------------------------------

async def _crt_sh(session, query, sem):
    url = f"https://crt.sh/?q=%.{query}&output=json"
    out = set()
    async with sem:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=HARVEST_TIMEOUT_S)
            ) as resp:
                if resp.status != 200:
                    return out
                data = await resp.json(content_type=None)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            return out
    if isinstance(data, list):
        for entry in data[:HOSTS_PER_QUERY]:
            name = str(entry.get("name_value", "") or "")
            for candidate in name.splitlines():
                candidate = candidate.strip().lstrip("*.").lower()
                if candidate and "." in candidate and " " not in candidate:
                    out.add(candidate)
    log.info("crt.sh %s: %d hosts", query, len(out))
    return out

def _clean_hosts(pool):
    merged = set()
    for host in pool:
        if not host:
            continue
        host = str(host).strip().lower()
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]
        if host and "." in host:
            merged.add(host)
    return sorted(merged)

async def harvest_hosts(cc):
    """crt.sh sweep for the country + community/cache fallback pool."""
    cfg = COUNTRIES[cc]
    sem = asyncio.Semaphore(HARVEST_CONCURRENCY)
    connector = aiohttp.TCPConnector(limit=HARVEST_CONCURRENCY * 2)
    queries = (list(cfg["tlds"]) + list(cfg["orgs"]) + list(cfg["isps"]))
    found = set()
    async with aiohttp.ClientSession(connector=connector) as session:
        done = await asyncio.gather(
            *[_crt_sh(session, q, sem) for q in queries],
            return_exceptions=True)
    for item in done:
        if isinstance(item, set):
            found |= item
    # Enrich with the embedded fallback pool + cached harvest + bug lists
    found |= set(scraper.FALLBACK_POOL)
    cached = scraper.load_cache()
    if cached:
        found |= set(cached)
    hosts = _clean_hosts(found)
    log.info("harvest %s: %d unique hosts", cc, len(hosts))
    return hosts

async def run_scan_cycle(app, cc):
    st = state(cc)
    st.update(scanning=True, phase="harvesting domains", last_error="")
    try:
        hosts = await harvest_hosts(cc)
        if not hosts:
            st["last_error"] = "empty-harvest-pool"
            st["phase"] = "error"
            return
        st["phase"] = f"verifying {len(hosts)} hosts"
        results = await scanner.scan_hosts(hosts, concurrency=SCAN_CONCURRENCY)
        st["results"] = results
        st["last_epoch"] = time.time()
        st["scan_count"] += 1
        st["phase"] = "idle"
        persist(cc)
        log.info("scan cycle %s done: %d hosts verified",
                 cc, len(scanner.filter_working(results)))
    except Exception as exc:
        st["last_error"] = f"{type(exc).__name__}: {exc}"
        st["phase"] = "error"
        log.exception("scan cycle %s failed", cc)
    finally:
        st["scanning"] = False

async def cycle_loop(app, cc):
    while True:
        await run_scan_cycle(app, cc)
        await asyncio.sleep(REVERIFY_EVERY_S)

def ensure_scan_task(app, cc):
    tasks = app["scan_tasks"]
    if cc not in tasks or tasks[cc].done():
        tasks[cc] = asyncio.create_task(cycle_loop(app, cc))

async def force_rescan(app, cc):
    tasks = app["scan_tasks"]
    if tasks.get(cc) and not tasks[cc].done():
        tasks[cc].cancel()
    st = state(cc)
    st.update(scanning=True, phase="rescan requested")
    tasks[cc] = asyncio.create_task(cycle_loop(app, cc))
    return st

# ---------------------------------------------------------------------------
# Keep-alive self-ping (unchanged — while instance is awake)
# ---------------------------------------------------------------------------

async def keepalive_task(app):
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    SELF_URL + "/healthz",
                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        log.warning("keepalive got %s", resp.status)
        except Exception as exc:
            log.debug("keepalive ping failed: %s", exc)
        await asyncio.sleep(KEEPALIVE_EVERY_S)

# ---------------------------------------------------------------------------
# Handlers — same JSON shapes as the live service
# ---------------------------------------------------------------------------

async def dashboard(request):
    return web.FileResponse(os.path.join(STATIC_DIR, "index.html"),
                            headers={"Cache-Control": "no-cache"})

async def hosts_feed(request):
    cc = _resolve_cc(request)
    working = scanner.filter_working(state(cc)["results"])
    text = "\n".join(f"{r.host}:{r.port}" for r in working)
    return web.Response(text=text + "\n", content_type="text/plain")

async def top_hosts(request):
    cc = _resolve_cc(request)
    working = scanner.filter_working(state(cc)["results"])[:20]
    text = "\n".join(f"{r.host}:{r.port}" for r in working)
    return web.Response(text=text + "\n", content_type="text/plain")

async def api_results(request):
    cc = _resolve_cc(request)
    st = state(cc)
    return web.json_response({
        "tool": "Luphahla Bugscan",
        "country": cc,
        "default_country": DEFAULT_COUNTRY,
        "ports": list(scanner.PORTS),
        "countries": COUNTRIES,
        "reverify_every_s": REVERIFY_EVERY_S,
        "scanning": st["scanning"],
        "scan_count": st["scan_count"],
        "last_epoch": st["last_epoch"],
        "phase": st["phase"],
        "last_error": st["last_error"],
        "endpoints": {
            "results": "/api/results",
            "config": "/api/config",
            "scan": "/api/scan",
            "health": "/healthz",
        },
        "results": _rows_json(st["results"]),
    })

async def api_config(request):
    return web.json_response({
        "tool": "Luphahla Bugscan",
        "role": "Network Diagnostics",
        "default_country": DEFAULT_COUNTRY,
        "ports": list(scanner.PORTS),
        "reverify_every_s": REVERIFY_EVERY_S,
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
    })

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
# App assembly — middleware wired in
# ---------------------------------------------------------------------------

def build_app():
    app = web.Application(middlewares=[cors_middleware])

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
