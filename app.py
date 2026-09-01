"""
app.py — Universal FastAPI web server + REST API layer.

Endpoints:
  GET /            → responsive Tailwind dashboard (live verified host table)
  GET /hosts       → plain-text array of 'fast' + 'usable' SNI hosts
  GET /api/results → JSON dump of the last scan
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import HTMLResponse, PlainTextResponse

import scanner
import scraper

log = logging.getLogger("sni.app")

STATE = {
    "results": [],
    "last_scan_epoch": 0.0,
    "scanning": False,
}

SCAN_INTERVAL_S = 2 * 60 * 60  # refresh working set every 2 hours


async def background_refresher():
    """Continuously re-harvest and re-scan so the API is always current."""
    while True:
        try:
            STATE["scanning"] = True
            hosts = await scraper.harvest_all()
            log.info("scan cycle starting: %d hosts", len(hosts))
            results = await scanner.scan_hosts(hosts, concurrency=300)
            STATE["results"] = results
            STATE["last_scan_epoch"] = time.time()
            working = scanner.filter_working(results)
            log.info("scan done: %d working hosts", len(working))
            with open("clean_hosts.txt", "w", encoding="utf-8") as fh:
                fh.write(scanner.working_hosts_text(results) + "\n")
        except Exception as exc:
            log.exception("scan cycle failed: %s", exc)
        finally:
            STATE["scanning"] = False
        await asyncio.sleep(SCAN_INTERVAL_S)


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(background_refresher())
    yield
    task.cancel()


app = FastAPI(title="SNI Bug Host Scanner", lifespan=lifespan)

DASH_TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SNI Scanner Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
<div class="max-w-6xl mx-auto px-4 py-8">
  <header class="mb-6">
    <h1 class="text-2xl md:text-3xl font-bold text-emerald-400">SNI / Bug Host Scanner</h1>
    <p class="text-gray-400 text-sm mt-1">
      Last scan: <span>{last_scan}</span> &middot;
      Verified working: <span class="text-emerald-400 font-semibold">{working_count}</span>
      hosts out of {total} scanned
      {scan_badge}
    </p>
  </header>

  <div class="overflow-x-auto rounded-xl border border-gray-800 shadow-lg">
    <table class="min-w-full text-sm">
      <thead class="bg-gray-900 text-left text-gray-300 uppercase text-xs tracking-wider">
        <tr>
          <th class="px-4 py-3">#</th>
          <th class="px-4 py-3">Host</th>
          <th class="px-4 py-3">Port</th>
          <th class="px-4 py-3">Verdict</th>
          <th class="px-4 py-3">Speed (KB/s)</th>
          <th class="px-4 py-3">Latency (ms)</th>
          <th class="px-4 py-3">Server Header</th>
          <th class="px-4 py-3">Status</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-800 font-mono text-xs md:text-sm">
        {rows}
      </tbody>
    </table>
  </div>

  <p class="text-gray-500 text-xs mt-4">
    Plain-text feed for tunnel configs:
    <a class="text-emerald-400 underline" href="/hosts">/hosts</a>
  </p>
</div>
</body>
</html>"""


def _row_class(verdict: str) -> str:
    return {
        "fast": "text-emerald-400",
        "usable": "text-lime-400",
        "throttled": "text-amber-400",
        "tls-blocked": "text-red-400",
        "proxy-mitm": "text-fuchsia-400",
        "blocked": "text-rose-500",
    }.get(verdict, "text-gray-400")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    results = STATE["results"]
    working = scanner.filter_working(results)
    last = "never"
    if STATE["last_scan_epoch"]:
        last = datetime.datetime.fromtimestamp(
            STATE["last_scan_epoch"], datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M UTC")
    badge = (' <span class="ml-2 px-2 py-0.5 rounded bg-blue-900 text-blue-300 '
             'text-xs animate-pulse">scanning</span>') if STATE["scanning"] else ""
    rows = []
    for i, r in enumerate(working, 1):
        zebra = "bg-gray-900/40" if i % 2 == 0 else ""
        rows.append(
            f"<tr class='{zebra} hover:bg-gray-800/60'>"
            f"<td class='px-4 py-2'>{i}</td>"
            f"<td class='px-4 py-2'>{r.host}</td>"
            f"<td class='px-4 py-2'>{r.port}</td>"
            f"<td class='px-4 py-2 {_row_class(r.verdict)} font-semibold'>{r.verdict}</td>"
            f"<td class='px-4 py-2'>{r.speed_kbps or '—'}</td>"
            f"<td class='px-4 py-2'>{r.latency_ms or '—'}</td>"
            f"<td class='px-4 py-2 text-gray-400'>{r.server_header or '—'}</td>"
            f"<td class='px-4 py-2'>{r.status_code or '—'}</td>"
            "</tr>"
        )
    html = DASH_TEMPLATE.format(
        last_scan=last,
        working_count=len(working),
        total=len(results),
        scan_badge=badge,
        rows="\n".join(rows) or
            '<tr><td colspan="8" class="px-4 py-6 text-center text-gray-500">'
            "No working hosts yet — first scan in progress.</td></tr>",
    )
    return HTMLResponse(html)


@app.get("/hosts", response_class=PlainTextResponse)
async def hosts():
    """Filtered plain-text array of only 'fast' + 'usable' SNI hosts."""
    if not STATE["last_scan_epoch"]:
        return PlainTextResponse("# no scan results yet\n", status_code=202)
    body = scanner.working_hosts_text(STATE["results"])
    return PlainTextResponse(
        body + "\n",
        headers={
            "Cache-Control": "no-store",
            "X-Generated-At": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        },
    )


@app.get("/api/results")
async def api_results():
    generated = None
    if STATE["last_scan_epoch"]:
        generated = datetime.datetime.fromtimestamp(
            STATE["last_scan_epoch"], datetime.timezone.utc
        ).isoformat()
    return {
        "scanning": STATE["scanning"],
        "last_scan_epoch": STATE["last_scan_epoch"],
        "generated_at": generated,
        "results": [r.to_row() for r in STATE["results"]],
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
