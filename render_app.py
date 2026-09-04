"""
render_app.py - Luphahla Bugscan web service for Render (v4).

v4 corresponds to scanner.py v4:

  * Results are persisted to disk on every cycle AND restored on boot,
    so a Render cold-start wake shows the last verified hosts
    immediately instead of an empty table while a fresh scan runs.
  * POST /api/scan is gated by an X-Scan-Token (set SCAN_TOKEN in the
    Render environment; the APK must send the same value) to stop
    free-tier CPU abuse.
  * Scan becomes adaptive:
      - quick pass: re-verifies and re-scores the current working set
        every REVERIFY_EVERY_S (cheap handshakes),
      - full pass: fresh harvest + full sweep every HARVEST_EVERY_S.
  * /hosts, /top and /api/results carry v4 fields (sni_flex, stable,
    latency_ms, speed_kbps, jitter_pct, tunnel_score) and are sorted by
    tunnel_score.
  * CORS middleware stays, so the WebView/APK dashboard can read JSON
    cross-origin.

The COUNTRIES table is the authoritative source used by this service.
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
# Configuration (env-driven)
# ---------------------------------------------------------------------------

PORT = int(os.environ.get("PORT", 8000))
DEFAULT_COUNTRY = os.environ.get("DEFAULT_COUNTRY", "zw")
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
RESULT_FILE = "render_results_{}.json"

SCAN_TOKEN = os.environ.get("SCAN_TOKEN", "")

REVERIFY_EVERY_S = int(os.environ.get("REVERIFY_EVERY_S", 1800))
HARVEST_EVERY_S = int(os.environ.get("HARVEST_EVERY_S", 6 * 60 * 60))
KEEPALIVE_EVERY_S = int(os.environ.get("KEEPALIVE_EVERY_S", 600))

SCAN_CONCURRENCY = int(os.environ.get("SCAN_CONCURRENCY", 60))
DEEP_PROBE = os.environ.get("DEEP_PROBE", "1") == "1"
MAX_HOSTS_PER_SCAN = int(os.environ.get("MAX_HOSTS_PER_SCAN", 700))

# ---------------------------------------------------------------------------
# Authoritative country table
# ---------------------------------------------------------------------------

COUNTRIES = {
    "all": {
        "label": "Global / All",
        "tlds": ("gov.zw", "edu.zw", "gov.za", "edu.za", "gov.ng", "gov.ke"),
        "orgs": (),
        "isps": (),
    },
    "zw": {
        "label": "Zimbabwe",
        "tlds": ("gov.zw", "edu.zw"),
        "orgs": ("econet", "netone", "telone", "liquidtelecom",
                 "zol", "utande", "telecel"),
        "isps": ("econet.co.zw", "netone.co.zw", "telone.co.zw",
                 "zol.co.zw", "liquidtelecom.co.zw", "utande.co.zw",
                 "telecel.co.zw"),
    },
    "za": {
        "label": "South Africa",
        "tlds": ("gov.za", "edu.za"),
        "orgs": ("mtn", "vodacom", "cellc", "telkom", "rain", "openserve"),
        "isps": ("mtn.co.za", "vodacom.co.za", "cellc.co.za",
                 "telkom.co.za", "rain.co.za", "openserve.co.za"),
    },
    "ng": {
        "label": "Nigeria",
        "tlds": ("gov.ng",),
        "orgs": ("mtn", "glo", "9mobile", "airtel"),
        "isps": ("mtnonline.com", "glo.com.ng",
                 "9mobile.com.ng", "airtel.com.ng"),
    },
    "ke": {
        "label": "Kenya",
        "tlds": ("gov.ke",),
        "orgs": ("safaricom", "airtel", "telkom"),
        "isps": ("safaricom.co.ke", "airtel.co.ke", "telkom.co.ke"),
    },
    "gh": {
        "label": "Ghana",
        "tlds": ("gov.gh", "edu.gh"),
        "orgs": ("mtn", "vodafone", "airteltigo"),
        "isps": ("mtn.com.gh", "vodafone.com.gh", "airteltigo.com.gh"),
    },
    "zm": {
        "label": "Zambia",
        "tlds": ("gov.zm", "edu.zm"),
        "orgs": ("airtel", "mtn", "zamtel", "liquidtelecom"),
        "isps": ("airtel.co.zm", "mtn.co.zm", "zamtel.co.zm"),
    },
    "ug": {
        "label": "Uganda",
        "tlds": ("gov.ug",),
        "orgs": ("mtn", "airtel", "lycamobile"),
        "isps": ("mtn.co.ug", "airtel.co.ug"),
    },
    "tz": {
        "label": "Tanzania",
        "tlds": ("gov.tz",),
        "orgs": ("vodacom", "airtel", "tigo", "halotel"),
        "isps": ("vodacom.co.tz", "airtel.co.tz"),
    },
}

# ---------------------------------------------------------------------------
# Per-country state
# ---------------------------------------------------------------------------

STATE = {}


def state(cc):
    key = cc if cc in COUNTRIES else DEFAULT_COUNTRY
    if key not in STATE:
        STATE[key] = {
            "results": [],
            "scanning": False,
            "last_epoch": 0.0,
            "scan_count": 0,
            "last_error": "",
            "phase": "",
            "running": None,
            "last_request": 0.0,
        }
        restore(key)
    return STATE[key]


# ---------------------------------------------------------------------------
# Persistence - rows survive Render restarts
# ---------------------------------------------------------------------------


def _rows_to_json(results):
    out = []
    for r in results:
        out.append({
            "host": r.host,
            "port": r.port,
            "verdict": r.verdict,
            "status_code": r.status_code,
            "server_header": r.server_header,
            "latency_ms": r.latency_ms,
            "speed_kbps": r.speed_kbps,
            "jitter_pct": r.jitter_pct,
            "reason": r.reason,
            "sni_flex": r.sni_flex,
            "no_sni_ok": r.no_sni_ok,
            "alpn": r.alpn,
            "stable": r.stable,
            "tunnel_score": r.tunnel_score,
        })
    return out


def persist(cc):
    st = state(cc)
    try:
        with open(RESULT_FILE.format(cc), "w", encoding="utf-8") as fh:
            json.dump({
                "epoch": st["last_epoch"],
                "count": st["scan_count"],
                "rows": _rows_to_json(st["results"]),
            }, fh)
    except OSError as exc:
        log.warning("persist %s failed: %s", cc, exc)


def restore(cc):
    try:
        with open(RESULT_FILE.format(cc), "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return
    st = state(cc)
    st["last_epoch"] = data.get("epoch", 0.0)
    st["scan_count"] = data.get("count", 0)
    built = []
    for row in data.get("rows", []):
        try:
            r = scanner.ScanResult(
                host=row.get("host", ""),
                port=row.get("port", 443),
                verdict=row.get("verdict", "blocked"),
                status_code=row.get("status_code"),
                server_header=row.get("server_header", ""),
                latency_ms=row.get("latency_ms"),
                speed_kbps=row.get("speed_kbps"),
                jitter_pct=row.get("jitter_pct"),
                reason=row.get("reason", ""),
                sni_flex=row.get("sni_flex", "untested"),
                no_sni_ok=row.get("no_sni_ok", False),
                alpn=row.get("alpn", ""),
                stable=row.get("stable"),
                tunnel_score=row.get("tunnel_score", 0),
            )
            if r.host:
                built.append(r)
        except Exception:
            continue
    st["results"] = built
    if built:
        log.info("restored %s from disk: %d rows", cc, len(built))


def _resolve_cc(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    return cc if cc in COUNTRIES else DEFAULT_COUNTRY


# ---------------------------------------------------------------------------
# Harvesting for the configured country
# ---------------------------------------------------------------------------


async def _crt_sh(session, query, sem):
    url = f"https://crt.sh/?q=%.{query}&output=json"
    out = set()
    async with sem:
        try:
            async with session.get(
                url,
                timeout=aiohttp.ClientTimeout(total=45),
                headers={"User-Agent": "luphahla-bugscan/4.0"},
            ) as resp:
                if resp.status == 200:
                    data = await resp.json(content_type=None)
                    if isinstance(data, list):
                        for entry in data[:500]:
                            name = str(entry.get("name_value", "") or "")
                            for candidate in name.splitlines():
                                candidate = (candidate.strip()
                                             .lstrip("*.")
                                             .lower())
                                if (candidate and "." in candidate
                                        and " " not in candidate):
                                    out.add(candidate)
        except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
            pass
    return out


def _clean(hosts):
    cleaned = set()
    for host in hosts:
        if not host:
            continue
        host = str(host).strip().lower()
        for prefix in ("https://", "http://"):
            if host.startswith(prefix):
                host = host[len(prefix):]
        host = host.split("/")[0].split(":")[0]
        if host and "." in host:
            cleaned.add(host)
    return sorted(cleaned)


async def harvest_country(cc):
    cfg = COUNTRIES[cc]
    queries = list(cfg["tlds"]) + list(cfg["orgs"]) + list(cfg["isps"])
    if not queries:
        queries = list(COUNTRIES["all"]["tlds"])
    sem = asyncio.Semaphore(8)
    found = set()
    connector = aiohttp.TCPConnector(limit=16)
    async with aiohttp.ClientSession(connector=connector) as session:
        done = await asyncio.gather(
            *[_crt_sh(session, q, sem) for q in queries],
            return_exceptions=True)
    for item in done:
        if isinstance(item, set):
            found |= item
    found |= set(scraper.FALLBACK_POOL)
    hosts = _clean(found)
    if len(hosts) > MAX_HOSTS_PER_SCAN:
        log.info("harvest trimmed %d -> %d for %s", len(hosts),
                 MAX_HOSTS_PER_SCAN, cc)
        hosts = hosts[:MAX_HOSTS_PER_SCAN]
    log.info("harvested %d hosts for %s", len(hosts), cc)
    return hosts


# ---------------------------------------------------------------------------
# Passes
# ---------------------------------------------------------------------------


async def quick_pass(cc):
    st = state(cc)
    st["scanning"] = True
    st["phase"] = "quick verify current working set"
    try:
        cur = [r for r in st["results"]
               if r.verdict in scanner.VERDICTS_WORKING]
        if not cur:
            return
        targets = [f"{r.host}:{r.port}" for r in cur]
        fresh = await scanner.scan_hosts(
            targets, concurrency=SCAN_CONCURRENCY, deep_probe=DEEP_PROBE)
        by_key = {(r.host, r.port): r for r in fresh}
        st["results"] = [
            by_key.get((r.host, r.port), r) for r in st["results"]
        ]
        st["last_epoch"] = time.time()
        st["scan_count"] += 1
        st["last_error"] = ""
        persist(cc)
        log.info("quick pass %s done: %d rows", cc, len(st["results"]))
    except Exception as exc:
        st["last_error"] = f"quick:{type(exc).__name__}:{exc}"
        log.exception("quick pass %s failed", cc)
    finally:
        st["scanning"] = False
        st["phase"] = "idle"


async def full_pass(cc):
    st = state(cc)
    st["scanning"] = True
    st["phase"] = "harvesting domains"
    try:
        hosts = await harvest_country(cc)
        st["phase"] = f"verifying {len(hosts)} hosts"
        results = await scanner.scan_hosts(
            hosts, concurrency=SCAN_CONCURRENCY, deep_probe=DEEP_PROBE)
        st["results"] = results
        st["last_epoch"] = time.time()
        st["scan_count"] += 1
        st["last_error"] = ""
        persist(cc)
        log.info("full pass %s done: %d of %d working", cc,
                 len(scanner.filter_working(results)), len(results))
    except Exception as exc:
        st["last_error"] = f"full:{type(exc).__name__}:{exc}"
        log.exception("full pass %s failed", cc)
    finally:
        st["scanning"] = False
        st["phase"] = "idle"


# ---------------------------------------------------------------------------
# Adaptive loop + task management
# ---------------------------------------------------------------------------


async def country_loop(cc):
    await full_pass(cc)
    cycles = 0
    while True:
        await asyncio.sleep(REVERIFY_EVERY_S)
        cycles += 1
        if cycles * REVERIFY_EVERY_S >= HARVEST_EVERY_S:
            cycles = 0
            await full_pass(cc)
        else:
            await quick_pass(cc)


def ensure_scan_task(app, cc):
    st = state(cc)
    if st["running"] is not None and st["running"].done():
        st["running"] = None
    if st["running"] is None:
        st["running"] = asyncio.create_task(country_loop(cc))
        log.info("scan task started for %s", cc)


async def force_rescan(app, cc):
    st = state(cc)
    now = time.time()
    if now - st["last_request"] < 20:
        return {"ok": False, "cooldown": True, "phase": st["phase"],
                "message": "scan already running, try again shortly"}
    st["last_request"] = now
    st["scanning"] = True
    st["phase"] = "rescan queued"
    if st["running"] is not None:
        st["running"].cancel()
    st["running"] = asyncio.create_task(country_loop(cc))
    return {"ok": True, "cooldown": False, "phase": st["phase"]}


# ---------------------------------------------------------------------------
# Keep-alive self-ping (while instance is awake)
# ---------------------------------------------------------------------------


async def keepalive_task(app):
    self_url = f"http://127.0.0.1:{PORT}/healthz"
    while True:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self_url,
                    timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status != 200:
                        log.warning("keepalive got %s", resp.status)
        except Exception as exc:
            log.debug("keepalive failed: %s", exc)
        await asyncio.sleep(KEEPALIVE_EVERY_S)


# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------


@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        resp = web.Response(status=204)
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = "Content-Type, X-Scan-Token"
    resp.headers["Access-Control-Max-Age"] = "86400"
    return resp


# ---------------------------------------------------------------------------
# JSON / response helpers
# ---------------------------------------------------------------------------


def _result_row(r):
    return {
        "host": r.host,
        "port": r.port,
        "verdict": r.verdict,
        "status_code": r.status_code,
        "server_header": r.server_header,
        "latency_ms": r.latency_ms,
        "speed_kbps": r.speed_kbps,
        "jitter_pct": r.jitter_pct,
        "reason": r.reason,
        "sni_flex": r.sni_flex,
        "no_sni_ok": r.no_sni_ok,
        "alpn": r.alpn,
        "stable": r.stable,
        "tunnel_score": r.tunnel_score,
    }


def _public(cc):
    st = state(cc)
    rows = sorted(st["results"],
                  key=lambda r: (r.tunnel_score,
                                 0 if r.verdict == scanner.VERDICT_FAST
                                 else 1),
                  reverse=True)
    return {
        "tool": "Luphahla Bugscan",
        "country": cc,
        "default_country": DEFAULT_COUNTRY,
        "ports": list(scanner.PORTS),
        "countries": {
            k: {"label": v["label"], "tlds": list(v["tlds"]),
                "orgs": list(v["orgs"]), "isps": list(v["isps"])}
            for k, v in COUNTRIES.items()
        },
        "reverify_every_s": REVERIFY_EVERY_S,
        "scanning": st["scanning"],
        "scan_count": st["scan_count"],
        "last_epoch": st["last_epoch"],
        "phase": st["phase"],
        "last_error": st["last_error"],
        "endpoints": ["/", "/hosts", "/top", "/static/",
                      "/api/results", "/api/config", "/api/scan"],
        "results": [_result_row(r) for r in rows],
    }


# ---------------------------------------------------------------------------
# Handlers
# ---------------------------------------------------------------------------


async def dashboard(request):
    path = os.path.join(STATIC_DIR, "index.html")
    return web.FileResponse(path,
                            headers={"Cache-Control": "no-cache"})


async def static_assets(request):
    rel = request.match_info.get("path", "")
    if not rel or ".." in rel:
        raise web.HTTPNotFound()
    path = os.path.join(STATIC_DIR, rel)
    if not os.path.isfile(path):
        raise web.HTTPNotFound()
    return web.FileResponse(path,
                            headers={"Cache-Control": "no-cache"})


async def api_config(request):
    cc = _resolve_cc(request)
    cfg = COUNTRIES[cc]
    return web.json_response({
        "tool": "Luphahla Bugscan",
        "country": cc,
        "default_country": DEFAULT_COUNTRY,
        "label": cfg["label"],
        "tlds": list(cfg["tlds"]),
        "orgs": list(cfg["orgs"]),
        "isps": list(cfg["isps"]),
        "ports": list(scanner.PORTS),
        "countries": {k: v["label"] for k, v in COUNTRIES.items()},
        "reverify_every_s": REVERIFY_EVERY_S,
        "concurrency": SCAN_CONCURRENCY,
        "deep_probe": DEEP_PROBE,
    })


async def api_results(request):
    cc = _resolve_cc(request)
    return web.json_response(_public(cc))


async def hosts(request):
    cc = _resolve_cc(request)
    rows = sorted(_public(cc)["results"],
                  key=lambda r: (r["tunnel_score"],
                                 0 if r["verdict"] == scanner.VERDICT_FAST
                                 else 1),
                  reverse=True)
    return web.json_response(rows)


async def top(request):
    cc = _resolve_cc(request)
    limit = 200
    try:
        limit = int(request.query.get("n", 200))
    except ValueError:
        limit = 200
    working = scanner.filter_working(state(cc)["results"])[:limit]
    return web.json_response([_result_row(r) for r in working])


async def healthz(request):
    return web.json_response({
        "ok": True,
        "tool": "Luphahla Bugscan",
        "time": time.time(),
        "default_country": DEFAULT_COUNTRY,
    })


async def api_scan(request):
    cc = _resolve_cc(request)

    # Token gate.
    provided = request.headers.get("X-Scan-Token", "")
    if SCAN_TOKEN and provided != SCAN_TOKEN:
        return web.json_response({"ok": False, "error": "invalid-token"},
                                 status=403)

    # Body may carry country/override.
    body = {}
    if request.body_exists:
        try:
            body = await request.json()
        except (ValueError, json.JSONDecodeError):
            body = {}
    if body.get("country"):
        cc = body["country"]
    if cc not in COUNTRIES:
        return web.json_response({"ok": False, "error": "bad-country"},
                                 status=400)

    result = await force_rescan(request.app, cc)
    return web.json_response(result)


async def favicon(request):
    return web.Response(status=204)


# ---------------------------------------------------------------------------
# App assembly
# ---------------------------------------------------------------------------


def build_app():
    app = web.Application(middlewares=[cors_middleware])
    app.router.add_get("/", dashboard)
    app.router.add_get("/hosts", hosts)
    app.router.add_get("/top", top)
    app.router.add_get("/healthz", healthz)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/api/config", api_config)
    app.router.add_get("/api/results", api_results)
    app.router.add_post("/api/scan", api_scan)
    app.router.add_get("/static/{path:.*}", static_assets)

    app.on_startup.append(boot)
    app.on_cleanup.append(shutdown_running_tasks)
    app["background_tasks"] = []
    return app


async def boot(app):
    # Restore state for the default country right away so the dashboard
    # shows data from the previous disk snapshot if present.
    st = state(DEFAULT_COUNTRY)
    log.info("boot: restored %d results for %s (scan a fresh full pass "
             "starts in the background)",
             len(st["results"]), DEFAULT_COUNTRY)

    keepalive_task_obj = asyncio.create_task(keepalive_task(app))
    app["background_tasks"].append(keepalive_task_obj)

    ensure_scan_task(app, DEFAULT_COUNTRY)


async def shutdown_running_tasks(app):
    for task in app.get("background_tasks", []):
        task.cancel()
        try:
            await task
        except (asyncio.CancelledError, Exception):
            pass


# ---------------------------------------------------------------------------
# Entrypoint
# ---------------------------------------------------------------------------

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    app = build_app()
    log.info("Luphahla Bugscan v4 listening on :%s (cc=%s)",
             PORT, DEFAULT_COUNTRY)
    web.run_app(app, host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    main()
