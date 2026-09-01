"""
main.py — CLI orchestrator: harvest → scan → clean_hosts.txt.

Usage:
  python main.py                  # full harvest + scan
  python main.py --no-scrape     # scan embedded fallback pool only
  python main.py --concurrency 300
  python main.py --serve         # launch web dashboard after scanning
"""

from __future__ import annotations

import asyncio
import logging
import sys

import scanner
import scraper


async def run_pipeline(no_scrape: bool, concurrency: int, output: str):
    hosts = list(scraper.FALLBACK_POOL) if no_scrape else await scraper.harvest_all()
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


def build_web_app(results):
    """Self-contained aiohttp dashboard — no fastapi/uvicorn/pydantic needed."""
    import time
    from aiohttp import web

    STATE = {
        "results": results,
        "last_scan_epoch": time.time(),
    }

    async def dashboard(request):
        working = scanner.filter_working(STATE['results'])
        last = time.strftime("%Y-%m-%d %H:%M UTC",
                             time.gmtime(STATE['last_scan_epoch']))
        rows = ""
        for i, r in enumerate(working, 1):
            color = {
                "fast": "text-emerald-400",
                "usable": "text-lime-400",
                "throttled": "text-amber-400",
                "tls-blocked": "text-red-400",
                "proxy-mitm": "text-fuchsia-400",
                "blocked": "text-rose-500",
            }.get(r.verdict, "text-gray-400")
            rows += (
                f"<tr class='hover:bg-gray-800/60'>"
                f"<td class='px-4 py-2'>{i}</td>"
                f"<td class='px-4 py-2'>{r.host}</td>"
                f"<td class='px-4 py-2'>{r.port}</td>"
                f"<td class='px-4 py-2 {color} font-semibold'>{r.verdict}</td>"
                f"<td class='px-4 py-2'>{r.speed_kbps or '—'}</td>"
                f"<td class='px-4 py-2'>{r.latency_ms or '—'}</td>"
                f"<td class='px-4 py-2 text-gray-400'>{r.server_header or '—'}</td>"
                f"<td class='px-4 py-2'>{r.status_code or '—'}</td>"
                f"</tr>"
            )
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SNI Scanner Dashboard</title>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="bg-gray-950 text-gray-100 min-h-screen">
<div class="max-w-6xl mx-auto px-4 py-8">
  <h1 class="text-2xl md:text-3xl font-bold text-emerald-400">SNI / Bug Host Scanner</h1>
  <p class="text-gray-400 text-sm mt-1">
    Last scan: {last} &middot;
    Verified working: <span class="text-emerald-400 font-semibold">{len(working)}</span>
    hosts out of {len(STATE['results'])} scanned
  </p>
  <div class="overflow-x-auto rounded-xl border border-gray-800 shadow-lg mt-6">
    <table class="min-w-full text-sm">
      <thead class="bg-gray-900 text-left text-gray-300 uppercase text-xs tracking-wider">
        <tr>
          <th class="px-4 py-3">#</th><th class="px-4 py-3">Host</th>
          <th class="px-4 py-3">Port</th><th class="px-4 py-3">Verdict</th>
          <th class="px-4 py-3">Speed (KB/s)</th><th class="px-4 py-3">Latency (ms)</th>
          <th class="px-4 py-3">Server</th><th class="px-4 py-3">Status</th>
        </tr>
      </thead>
      <tbody class="divide-y divide-gray-800 font-mono text-xs md:text-sm">{rows}</tbody>
    </table>
  </div>
  <p class="text-gray-500 text-xs mt-4">
    Plain-text feed: <a class="text-emerald-400 underline" href="/hosts">/hosts</a>
    &middot; JSON: <a class="text-emerald-400 underline" href="/api/results">/api/results</a>
  </p>
</div>
</body>
</html>"""
        return web.Response(text=html, content_type="text/html")

    async def hosts_feed(request):
        body = scanner.working_hosts_text(STATE['results'])
        return web.Response(text=body + "\n", content_type="text/plain")

    async def api_results(request):
        import json
        payload = {
            "last_scan_epoch": STATE['last_scan_epoch'],
            "results": [r.to_row() for r in STATE['results']],
        }
        return web.Response(text=json.dumps(payload),
                            content_type="application/json")

    app = web.Application()
    app.router.add_get("/", dashboard)
    app.router.add_get("/hosts", hosts_feed)
    app.router.add_get("/api/results", api_results)
    return app


def main() -> int:
    logging.basicConfig(level=logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    args = sys.argv[1:]
    no_scrape = "--no-scrape" in args
    serve = "--serve" in args
    output = "clean_hosts.txt"
    if "--output" in args:
        output = args[args.index("--output") + 1]
    concurrency = int(args[args.index("--concurrency") + 1]) if "--concurrency" in args else 250

    results = asyncio.run(run_pipeline(no_scrape, concurrency, output))

    if serve:
        from aiohttp import web
        logging.info("dashboard live on http://0.0.0.0:8000")
        web.run_app(build_web_app(results), host="0.0.0.0", port=8000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
