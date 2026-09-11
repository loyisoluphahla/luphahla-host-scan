"""
render_app.py - Luphahla Bugscan web service for Render (v4.1).

v4.1 changes vs v4:
  * FIX: GET /hosts now returns only WORKING hosts (fast/usable),
    matching /top and the dashboard. Previously it returned every
    scanned row including blocked/tls-blocked, which inflated the
    apparent host count vs clean_hosts.txt.
  * Everything else (adaptive scan cycle, disk persistence,
    keepalive, token-gated /api/scan, CORS) is unchanged.

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
    latency_ms, speed_kbps, jitter_pct, tunnel_score) and are sorted
    by tunnel_score.
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
DEEP_PROBE = os.environ.get("DEEP_PROBE", "1") not in ("0", "false", "no")

# ---------------------------------------------------------------------------
# Countries — authoritative scan-pool source for the service.
# (tlds/orgs/isps seeded from scraper.py's harvest targets; adjust freely.)
# ---------------------------------------------------------------------------

COUNTRIES = {
    "zw": {
        "label": "Zimbabwe",
        "tlds": ("gov.zw", "edu.zw"),
        "orgs": ("econet", "netone", "telone", "liquidtelecom", "zimra",
                 "parliament", "ministry"),
        "isps": ("econet.co.zw", "netone.co.zw", "telone.co.zw",
                 "zol.co.zw", "liquidtelecom.co.zw", "utande.co.zw",
                 "telecel.co.zw"),
    },
    "za": {
        "label": "South Africa",
        "tlds": ("gov.za", "edu.za"),
        "orgs": ("mtn", "vodafone", "telkom"),
        "isps": ("mtn.co.za", "vodacom.co.za", "cellc.co.za",
                 "telkom.co.za", "rain.co.za", "openserve.co.za"),
    },
    "ke": {
        "label": "Kenya",
        "tlds": ("gov.ke",),
        "orgs": ("safaricom",),
        "isps": ("safaricom.co.ke", "airtel.co.ke", "telkom.co.ke"),
    },
    "ng": {
        "label": "Nigeria",
        "tlds": ("gov.ng",),
        "orgs": ("airtel", "glo", "9mobile"),
        "isps": ("mtnonline.com", "airtel.com.ng", "glo.com.ng",
                 "9mobile.com.ng"),
    },
}

# ---------------------------------------------------------------------------
# Per-country state (in-memory + disk persistence)
# ---------------------------------------------------------------------------

_STATES: dict = {}


def _result_file(cc):
    return RESULT_FILE.format(cc)


def state(cc):
    """Get (or lazily restore from disk) the state dict for a country."""
    if cc in _STATES:
        return _STATES[cc]

    st = {
        "results": [],
        "scanning": False,
        "scan_count": 0,
        "last_epoch": 0,
        "phase": "idle",
        "last_error": "",
    }
    try:
        with open(_result_file(cc), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, dict):
            st["scan_count"] = int(data.get("scan_count", 0))
            st["last_epoch"] = float(data.get("last_epoch", 0))
            rows = data.get("results", [])
            for row in rows:
                try:
                    r = scanner.ScanResult(
                        host=row["host"],
                        port=int(row.get("port", 443)),
                        verdict=row.get("verdict", scanner.VERDICT_BLOCKED),
                        status_code=row.get("status_code"),
                        server_header=row.get("server_header", ""),
                        latency_ms=row.get("latency_ms"),
                        speed_kbps=row.get("speed_kbps"),
                        jitter_pct=row.get("jitter_pct"),
                        reason=row.get("reason", ""),
                        sni_flex=row.get("sni_flex", "untested"),
                        no_sni_ok=bool(row.get("no_sni_ok", False)),
                        alpn=row.get("alpn", ""),
                        stable=row.get("stable"),
                        tunnel_score=int(row.get("tunnel_score", 0)),
                    )
                    st["results"].append(r)
                except (KeyError, TypeError, ValueError):
                    continue
        log.info("restored %d rows from %s", len(st["results"]),
                 _result_file(cc))
    except FileNotFoundError:
        log.info("no snapshot on disk for %s — starting fresh", cc)
    except (OSError, ValueError) as exc:
        log.warning("snapshot restore failed for %s: %s", cc, exc)

    _STATES[cc] = st
    return st


def persist(cc):
    st = state(cc)
    payload = {
        "scan_count": st["scan_count"],
        "last_epoch": st["last_epoch"],
        "results": [_result_row(r) for r in st["results"]],
    }
    try:
        with open(_result_file(cc), "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    except OSError as exc:
        log.warning("persist failed for %s: %s", cc, exc)


def _resolve_cc(request):
    cc = request.query.get("country", DEFAULT_COUNTRY)
    return cc if cc in COUNTRIES else DEFAULT_COUNTRY


# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------

@web.middleware
async def cors_middleware(request, handler):
    if request.method == "OPTIONS":
        resp = web.Response()
    else:
        resp = await handler(request)
    resp.headers["Access-Control-Allow-Origin"] = "*"
    resp.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
    resp.headers["Access-Control-Allow-Headers"] = (
        "Content-Type, X-Scan-Token")
    return resp


# ---------------------------------------------------------------------------
# Scan cycle
# ---------------------------------------------------------------------------


def _country_pool(cc):
    """Seed host list for a country: fallback pool + org/ISP domains."""
    cfg = COUNTRIES[cc]
    hosts = set(scraper.FALLBACK_POOL)
    hosts.update(cfg["isps"])
    hosts.update(f"www.{org}.{'.' + cfg['tlds'][0] if cfg['tlds'] else 'com'}"
                 for org in cfg["orgs"])
    return sorted(hosts)


async def run_scan_cycle(app, cc, full_pass):
    st = state(cc)
    if st["scanning"]:
        return {"ok": False, "error": "scan-already-running"}
    st["scanning"] = True
    st["last_error"] = ""
    try:
        if full_pass:
            st["phase"] = "harvest"
            log.info("[%s] full pass: harvesting...", cc)
            harvested = await scraper.harvest_all()
            hosts = sorted(set(harvested) | set(_country_pool(cc)))
        else:
            # Quick pass: re-verify the current working set only.
            working = scanner.filter_working(st["results"])
            hosts = [f"{r.host}:{r.port}" for r in working]
            if not hosts:
                hosts = _country_pool(cc)
            st["phase"] = "reverify"

        st["phase"] = "scanning"
        log.info("[%s] scanning %d targets (full=%s deep=%s)",
                 cc, len(hosts), full_pass, DEEP_PROBE)
        results = await scanner.scan_hosts(
            hosts, concurrency=SCAN_CONCURRENCY, deep_probe=DEEP_PROBE)

        if not full_pass:
            # Keep rejected rows from the previous full sweep, replace
            # re-verified rows in place.
            merged = {f"{r.host}:{r.port}": r for r in st["results"]}
            for r in results:
                merged[f"{r.host}:{r.port}"] = r
            results = list(merged.values())

        st["results"] = results
        st["scan_count"] += 1
        st["last_epoch"] = time.time()
        st["phase"] = "idle"
        persist(cc)
        working = len(scanner.filter_working(results))
        log.info("[%s] cycle done: %d rows, %d working",
                 cc, len(results), working)
        return {"ok": True, "rows": len(results), "working": working}
    except Exception as exc:  # keep the service alive no matter what
        st["phase"] = "idle"
        st["last_error"] = f"{type(exc).__name__}: {exc}"
        log.exception("[%s] scan cycle failed", cc)
        return {"ok": False, "error": st["last_error"]}
    finally:
        st["scanning"] = False


def ensure_scan_task(app, cc, full_pass=True):
    loop = asyncio.get_event_loop()
    task = loop.create_task(run_scan_cycle(app, cc, full_pass))
    app["background_tasks"].append(task)
    return task


async def force_rescan(app, cc):
    st = state(cc)
    if st["scanning"]:
        return {"ok": False, "error": "scan-already-running"}
    return await run_scan_cycle(app, cc, full_pass=True)


# ---------------------------------------------------------------------------
# Background loops
# ---------------------------------------------------------------------------


async def scan_scheduler_task(app):
    """Quick reverify every REVERIFY_EVERY_S; full harvest sweep every
    HARVEST_EVERY_S. Only for the default country."""
    log.info("scheduler live: reverify=%ss harvest=%ss",
             REVERIFY_EVERY_S, HARVEST_EVERY_S)
    last_full = 0.0
    while True:
        try:
            await asyncio.sleep(REVERIFY_EVERY_S)
            full = (time.time() - last_full) >= HARVEST_EVERY_S
            if full:
                last_full = time.time()
            await run_scan_cycle(app, DEFAULT_COUNTRY, full_pass=full)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("scheduler iteration failed")


async def keepalive_task(app):
    """Self-ping so the Render free tier does not idle-spin us down
    mid-scan. Harmless if the service is already awake."""
    url = f"http://127.0.0.1:{PORT}/healthz"
    while True:
        try:
            await asyncio.sleep(KEEPALIVE_EVERY_S)
            timeout = aiohttp.ClientTimeout(total=10)
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=timeout) as resp:
                    log.debug("keepalive ping -> %s", resp.status)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.debug("keepalive ping failed: %s", exc)


# ---------------------------------------------------------------------------
# Row/serialization helpers
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
    # v4.1 FIX: only working hosts. /hosts previously returned every
    # scanned row (incl. blocked/tls-blocked), inflating the count vs
    # clean_hosts.txt and confusing CLI pulls.
    cc = _resolve_cc(request)
    rows = [_result_row(r)
            for r in scanner.filter_working(state(cc)["results"])]
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

    scheduler_task_obj = asyncio.create_task(scan_scheduler_task(app))
    app["background_tasks"].append(scheduler_task_obj)

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
    log.info("Luphahla Bugscan v4.1 listening on :%s (cc=%s)",
             PORT, DEFAULT_COUNTRY)
    web.run_app(app, host="0.0.0.0", port=PORT)


if __name__ == "__main__":
    main()
