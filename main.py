"""
main.py — CLI orchestrator: harvest → scan → clean_hosts.txt.

Usage:
  python main.py                  # full harvest + scan
  python main.py --no-scrape     # scan embedded fallback pool only
  python main.py --concurrency 300
  python main.py --serve         # launch the dashboard after scanning
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
        import time
        import uvicorn
        import app as webapp
        webapp.STATE["results"] = results
        webapp.STATE["last_scan_epoch"] = time.time()
        uvicorn.run(webapp.app, host="0.0.0.0", port=8000)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
