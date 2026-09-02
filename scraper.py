"""
scraper.py — Luphahla Bugscan deep domain harvester.

Sources:
  - crt.sh CT logs: gov/edu TLDs + regional ISPs + operator portals
  - HackerTarget host search API (throttled, quota-aware)
  - Community bug-host lists on GitHub
  - Embedded fallback pool: global CDNs + zero-rated services
Output: deduplicated, sorted array, cached to harvest_cache.json.
"""

from __future__ import annotations

import asyncio
import json
import logging

import aiohttp

log = logging.getLogger("luphahla.scraper")

HACKERTARGET_API = "https://api.hackertarget.com/hostsearch/?q={domain}"
CRT_SH_URL = "https://crt.sh/?q={query}&output=json"
CACHE_FILE = "harvest_cache.json"

TARGET_TLDS = (
    ".gov.zw", ".edu.zw", ".gov.za", ".edu.za", ".gov.ng", ".gov.ke",
)

CT_SEED_ORGS = (
    "econet", "netone", "telone", "liquidtelecom", "mtn", "vodafone",
    "safaricom", "airtel", "glo", "9mobile", "telkom", "cellc",
    "ministry", "university", "college", "zimra", "parliament",
)

# --- NEW: dedicated regional ISP harvesting (your request) -------------
OPERATOR_DOMAINS = (
    # Zimbabwe
    "econet.co.zw", "netone.co.zw", "telone.co.zw", "zol.co.zw",
    "liquidtelecom.co.zw", "utande.co.zw", "telecel.co.zw",
    # South Africa
    "mtn.co.za", "vodacom.co.za", "cellc.co.za", "telkom.co.za",
    "rain.co.za", "openserve.co.za",
    # Kenya
    "safaricom.co.ke", "airtel.co.ke", "telkom.co.ke",
    # Nigeria
    "mtnonline.com", "airtel.com.ng", "glo.com.ng", "9mobile.com.ng",
)

# Known zero-rated product endpoints — classic free vectors on
# African carriers (Facebook Free Basics, WhatsApp, speedtest...)
ZERO_RATED_SERVICES = (
    "0.facebook.com", "free.facebook.com", "m.facebook.com",
    "freebasics.com", "web.whatsapp.com", "whatsapp.com",
    "whatsapp.net", "zero.wikipedia.org", "speedtest.net",
    "www.speedtest.net", "api.weather.com", "weather.com",
)

HACKERTARGET_DELAY_S = 15.5

# Community-maintained bug-host lists (add more repo URLs as found)
GITHUB_BUG_LISTS = (
    "https://raw.githubusercontent.com/SpeedxPz/bug-host/main/bug_host.txt",
    "https://raw.githubusercontent.com/mkalah/bossni/main/bughost.txt",
)

# ---------------------------------------------------------------------------
# Embedded fallback pool — global CDN & infra fronts
# ---------------------------------------------------------------------------

FALLBACK_POOL = (
    # Cloudflare
    "cloudflare.com", "www.cloudflare.com", "workers.dev", "pages.dev",
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com",
    # Fastly
    "fastly.com", "www.fastly.com", "github.io", "githubusercontent.com",
    "githubassets.com", "pypi.org", "files.pythonhosted.org",
    # Akamai
    "akamai.com", "www.akamai.com", "akamaized.net", "akamaiedge.net",
    "edgesuite.net",
    # Google
    "google.com", "www.google.com", "googleapis.com", "gstatic.com",
    "googleusercontent.com", "doubleclick.net", "youtube.com",
    "ytimg.com", "ggpht.com", "appspot.com", "android.com",
    # Meta / Facebook
    "facebook.com", "www.facebook.com", "fbcdn.net", "cdninstagram.com",
    "instagram.com",
    # AWS
    "amazonaws.com", "cloudfront.net", "aws.amazon.com",
    "elasticbeanstalk.com", "s3.amazonaws.com",
    # Microsoft
    "microsoft.com", "windowsupdate.com", "office.com",
    "live.com", "azureedge.net", "azurewebsites.net",
    # Regional operator portals (self-zero-rated)
    "econet.co.zw", "netone.co.zw", "telone.co.zw", "potraz.gov.zw",
    "zim.gov.zw", "mtn.co.za", "safaricom.co.ke",
    "mtnonline.com", "glo.com.ng", "9mobile.com.ng",
    # Global infra
    "wikipedia.org", "w3.org", "iana.org", "verisign.com",
    "quad9.net", "opendns.com",
) + ZERO_RATED_SERVICES


# ---------------------------------------------------------------------------
# Async fetchers
# ---------------------------------------------------------------------------


async def _get_json(session, url, timeout=45):
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=timeout),
            headers={"User-Agent": "luphahla-bugscan/3.0"},
        ) as resp:
            if resp.status != 200:
                return None
            return await resp.json(content_type=None)
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError) as exc:
        log.debug("fetch failed %s: %s", url, exc)
        return None


async def harvest_hackertarget(session, seed_host):
    url = HACKERTARGET_API.format(domain=seed_host)
    out = set()
    try:
        async with session.get(
            url,
            timeout=aiohttp.ClientTimeout(total=20),
            headers={"User-Agent": "luphahla-bugscan/3.0"},
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


async def harvest_crt_sh(session, query, semaphore):
    url = CRT_SH_URL.format(query=f"%.{query}")
    out = set()
    async with semaphore:
        data = await _get_json(session, url, timeout=45)
    if not isinstance(data, list):
        return out
    for entry in data[:500]:
        name = entry.get("name_value", "") or ""
        for candidate in str(name).split("\n"):
            candidate = candidate.strip().lstrip("*.").lower()
            if candidate and "." in candidate and " " not in candidate:
                out.add(candidate)
    return out


async def harvest_github_lists(session):
    """Pull community-maintained SNI bug-host lists."""
    out = set()
    for url in GITHUB_BUG_LISTS:
        try:
            async with session.get(
                url, timeout=aiohttp.ClientTimeout(total=20)
            ) as r:
                if r.status != 200:
                    continue
                for line in (await r.text()).splitlines():
                    h = line.strip().split("#")[0].strip()
                    if h and "." in h and " " not in h:
                        out.add(h)
        except (aiohttp.ClientError, asyncio.TimeoutError):
            pass
    log.info("github bug-lists: %d hosts", len(out))
    return out


# ---------------------------------------------------------------------------
# Merge, dedup, sort
# ---------------------------------------------------------------------------


def merge_and_dedup(*pools):
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
# Cache
# ---------------------------------------------------------------------------


def save_cache(hosts, path=CACHE_FILE):
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(sorted(hosts), fh)
        log.info("harvest cached -> %s (%d hosts)", path, len(hosts))
    except OSError as exc:
        log.warning("cache write failed: %s", exc)


def load_cache(path=CACHE_FILE):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        if isinstance(data, list) and data:
            return data
    except (OSError, ValueError):
        pass
    return None


# ---------------------------------------------------------------------------
# Public pipeline
# ---------------------------------------------------------------------------


async def harvest_all(concurrency=8, use_hackertarget=True):
    connector = aiohttp.TCPConnector(limit=concurrency)
    sem = asyncio.Semaphore(concurrency)
    all_hosts = set(FALLBACK_POOL)

    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = []

        # 1) Government / educational TLD sweep
        for tld in TARGET_TLDS:
            tasks.append(harvest_crt_sh(session, tld.lstrip("."), sem))

        # 2) Operator org CT sweep
        for org in CT_SEED_ORGS:
            tasks.append(harvest_crt_sh(session, org, sem))

        # 3) NEW: dedicated regional ISP domain sweep
        for op in OPERATOR_DOMAINS:
            tasks.append(harvest_crt_sh(session, op, sem))

        # 4) Community bug-host lists
        tasks.append(harvest_github_lists(session))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for item in results:
            if isinstance(item, set):
                all_hosts |= item

        # 5) HackerTarget enrichment (throttled, best-effort)
        if use_hackertarget:
            for seed in ("cloudflare.com", "google.com", "facebook.com",
                         "microsoft.com", "gov.zw", "gov.ng"):
                found = await harvest_hackertarget(session, seed)
                all_hosts |= found
                await asyncio.sleep(HACKERTARGET_DELAY_S)

    final = merge_and_dedup(all_hosts)
    log.info("harvest complete: %d unique hosts", len(final))
    save_cache(final)
    return final
