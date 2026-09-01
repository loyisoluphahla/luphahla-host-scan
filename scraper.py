"""
scraper.py — Async domain harvester for zero-rating SNI vectors.

Sources:
  - HackerTarget host search API (per seed domain)
  - crt.sh Certificate Transparency logs (wildcard + suffix queries)
  - Targeted TLD sweep: .gov.zw .edu.zw .gov.za .edu.za .gov.ng .gov.ke
  - Embedded fallback pool of global CDN fronts + regional operator portals

Output: deduplicated, sorted host array ready for scanner.scan_hosts().
"""

from __future__ import annotations

import asyncio
import logging
from typing import Iterable

import aiohttp

log = logging.getLogger("sni.scraper")

HACKERTARGET_API = "https://api.hackertarget.com/hostsearch/?q={domain}"
CRT_SH_URL = "https://crt.sh/?q={query}&output=json"

# Primary TLD structures targeted for zero-rated gov/edu infrastructure
TARGET_TLDS = (
    ".gov.zw", ".edu.zw", ".gov.za", ".edu.za", ".gov.ng", ".gov.ke",
)

# Seed org keywords used to drive CT-log queries for network operators
CT_SEED_ORGS = (
    "econet", "netone", "telone", "liquidtelecom", "mtn", "vodafone",
    "safaricom", "airtel", "glo", "9mobile", "telkom", "cellc",
    "ministry", "university", "college", "zimra", "parliament",
)

# Delay between HackerTarget calls (free tier rate limit)
HACKERTARGET_DELAY_S = 15.5

# ---------------------------------------------------------------------------
# Embedded hardcoded fallback pool — global CDN & infra fronts
# ---------------------------------------------------------------------------

FALLBACK_POOL = (
    # --- Cloudflare fronts ---
    "cloudflare.com", "www.cloudflare.com", "workers.dev", "pages.dev",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    # --- Fastly ---
    "fastly.com", "www.fastly.com", "github.io", "githubusercontent.com",
    "githubassets.com", "pypi.org", "files.pythonhosted.org",
    # --- Akamai ---
    "akamai.com", "www.akamai.com", "akamaized.net", "akamaiedge.net",
    "edgesuite.net",
    # --- Google ---
    "google.com", "www.google.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "doubleclick.net", "youtube.com",
    "ytimg.com", "ggpht.com", "appspot.com", "android.com",
    # --- Meta / Facebook fronts ---
    "facebook.com", "www.facebook.com", "fbcdn.net", "cdninstagram.com",
    "instagram.com", "whatsapp.com", "whatsapp.net",
    # --- AWS fronts ---
    "amazonaws.com", "cloudfront.net", "aws.amazon.com",
    "elasticbeanstalk.com", "s3.amazonaws.com",
    # --- Microsoft fronts ---
    "microsoft.com", "windowsupdate.com", "office.com",
    "live.com", "azureedge.net", "azurewebsites.net",
    # --- Regional operator portals (zero-rated by operators themselves) ---
    "econet.co.zw", "netone.co.zw", "telone.co.zw", "potraz.gov.zw",
    "zim.gov.zw", "mtn.co.za", "safaricom.co.ke",
    "mtnonline.com", "glo.com.ng", "9mobile.com.ng",
    # --- Misc global anycast / infra ---
    "wikipedia.org", "w3.org", "iana.org", "verisign.com",
    "quad9.net", "opendns.com",
)


# ---------------------------------------------------------------------------
# Async fetchers
# ---------------------------------------------------------------------------


async def _get_json(session, url: str, timeout: int = 45):
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "sni-scout/2.0 (+ct-logs)"},
        ) as resp:
            if resp.status != 200:
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.debug("fetch failed %s: %s", url, exc)
        return None


async def harvest_hackertarget(session, seed_host: str) -> set:
    """Pull subdomains/hosts from the HackerTarget hostsearch API."""
    url = HACKERTARGET_API.format(domain=seed_host)
    out = set()
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"User-Agent": "sni-scout/2.0"},
        ) as resp:
            if resp.status != 200:
                return out
            text = await resp.text()
        if "API count exceeded" in text:
            log.info("hackertarget quota hit on %s", seed_host)
            return out
        for line in text.splitlines():
            host = line.split(",")[0].strip().lower()
            if host and "." in host and "error" not in host:
                out.add(host)
    except (aiohttp.ClientError, asyncio.TimeoutError):
        pass
    return out


async def harvest_crt_sh(session, query: str, semaphore) -> set:
    """
    Query crt.sh CT logs. `query` may be a domain suffix (e.g. 'gov.zw')
    or an org keyword (e.g. 'econet'). Uses % wildcard matching.
    """
    url = CRT_SH_URL.format(query=f"%.{query}")
    out = set()
    data = await _get_json(session, url, timeout=45)
    if not isinstance(data, list):
        return out
    for entry in data[:500]:  # cap per query to keep runtime bounded
        name = entry.get("name_value", "") or ""
        for candidate in str(name).split("\n"):
            candidate = candidate.strip().lstrip("*.").lower()
            if candidate and "." in candidate and " " not in candidate:
                out.add(candidate)
    return out


# ---------------------------------------------------------------------------
# Merge, dedup, sort
# ---------------------------------------------------------------------------


def merge_and_dedup(*pools) -> list:
    """Merge host pools, normalize (lowercase, strip scheme/port/path),
    deduplicate, and sort."""
    merged = set()
    for pool in pools:
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


# ---------------------------------------------------------------------------
# Public pipeline
# ---------------------------------------------------------------------------


async def harvest_all(concurrency: int = 8,
                      use_hackertarget: bool = True) -> list:
    """
    Full harvest pipeline:
      1. CT logs for gov/edu TLD structures
      2. CT logs for operator seed orgs
      3. HackerTarget API for major infrastructure seeds (throttled)
      4. Embedded fallback CDN/operator pool
    Returns a deduplicated, sorted host array.
    """
    connector = aiohttp.TCPConnector(limit=concurrency)
    sem = asyncio.Semaphore(concurrency)
    all_hosts = set(FALLBACK_POOL)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []

        # 1) Government / educational TLD sweep (core zero-rating vectors)
        for tld in TARGET_TLDS:
            tld_base = tld.lstrip(".")
            tasks.append(harvest_crt_sh(session, tld_base := tld_base, semaphore=sem)
                         if False else harvest_crt_sh(session, tld_base, sem))

        # 2) Operator CT-log sweep
        for org in CT_SEED_ORGS:
            tasks.append(harvest_crt_sh(session, org, sem))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for item in results:
            if isinstance(item, set):
                all_hosts |= item

        # 3) HackerTarget enrichment — throttled, quota-aware, best-effort
        ht_seeds = ("cloudflare.com", "google.com", "facebook.com",
                    "microsoft.com", "gov.zw", "gov.ng")
        for seed in ht_seeds:
            found = await harvest_hackertarget(session, seed)
            all_hosts |= found
            await asyncio.sleep(HACKERTARGET_DELAY_S)

    final = merge_and_dedup(all_hosts)
    log.info("harvest complete: %d unique hosts", len(final))
    return final
