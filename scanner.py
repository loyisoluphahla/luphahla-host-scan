"""
scanner.py — Luphahla Bugscan async verification engine.

Multi-layer ISP-block detection:
  1. SSL certificate issuer-name MITM detection (FortiGate, Sophos, Zscaler…)
  2. Deep redirect chain + captive portal signature analysis
  3. Body HTML block-signature sweep
  4. Content-Length / tiny-response interception checks
  5. Throughput classification: fast / usable / throttled
Plus: zero-rating probe mode — the TRUE bug-host test, run on the
zero-balance SIM (handshake completes for free = carrier allows it).
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import ssl
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

log = logging.getLogger("luphahla.scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORTS = (443, 8080, 80)

CONNECT_TIMEOUT = 8
TOTAL_TIMEOUT = 15
DOWNLOAD_SAMPLE = 128 * 1024

FAST_THRESHOLD_KBPS = 10.0
USABLE_THRESHOLD_KBPS = 0.2
TINY_RESPONSE_BYTES = 200

VERDICT_FAST = "fast"
VERDICT_USABLE = "usable"
VERDICT_THROTTLED = "throttled"
VERDICT_TLS_BLOCKED = "tls-blocked"
VERDICT_PROXY_MITM = "proxy-mitm"
VERDICT_BLOCKED = "blocked"

# ---------------------------------------------------------------------------
# Block signatures
# ---------------------------------------------------------------------------

BLOCK_SIGNATURES = tuple(
    re.compile(sig, re.IGNORECASE)
    for sig in (
        r"\brecharge\b",
        r"\bbalance\b",
        r"\btop\s?up\b",
        r"\btopup\b",
        r"\bcaptive\b",
        r"\bonestfunds\b",
        r"\bbuy\s+data\b",
        r"\binsufficient\s+balance\b",
        r"\bairtime\b",
        r"\bbundle\b.*\bexpired\b",
        r"\bdata\s+bundle\b",
        r"\bplease\s+dial\b",
        r"\bzero\s+balance\b",
        r"\bportal\b.*\blogin\b",
        r"\bwifi\s+login\b",
        r"\bhotspot\s+login\b",
        r"\binternet\s+blocked\b",
        r"\bpaywall\b",
        r"\bpurchase\s+data\b",
        r"\bdial\s+\*?\d+#\b",
    )
)

REDIRECT_SIGNATURES = tuple(
    re.compile(sig, re.IGNORECASE)
    for sig in (
        r"recharge", r"topup", r"top-up", r"captive", r"portal",
        r"billing", r"paywall", r"payment", r"subscribe", r"airtime",
        r"onestfunds", r"balance", r"buydata",
    )
)

# ---------------------------------------------------------------------------
# MITM detection via certificate ISSUER names — works with zero setup.
# Any leaf cert whose issuer organization matches these is an interception
# middlebox, not the real server.
# ---------------------------------------------------------------------------

MITM_ISSUER_SIGNATURES = (
    "fortigate", "fortinet", "sophos", "zscaler", "cyberoam",
    "palo alto", "sonicwall", "ssl inspection", "webfilter",
    "ssl-inspection", "contentgate", "barracuda", "watchguard",
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    host: str
    port: int
    verdict: str = "blocked"
    status_code: Optional[int] = None
    server_header: str = ""
    latency_ms: Optional[float] = None
    speed_kbps: Optional[float] = None
    content_length: Optional[int] = None
    body_bytes: int = 0
    final_url: str = ""
    cert_fingerprint: str = ""
    cert_issuer: str = ""
    reason: str = ""
    redirect_chain: list = field(default_factory=list)

    def to_row(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "verdict": self.verdict,
            "status": self.status_code,
            "server": self.server_header,
            "latency_ms": self.latency_ms,
            "speed_kbps": self.speed_kbps,
            "content_length": self.content_length,
            "body_bytes": self.body_bytes,
            "cert_fp": self.cert_fingerprint,
            "cert_issuer": self.cert_issuer,
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------


def _match_signatures(text, sigs):
    for sig in sigs:
        if sig.search(text):
            return sig.pattern
    return None


def _is_captive_or_blocked(headers, body, final_url, chain):
    # Layer 1 — every redirect hop + final URL
    for url in chain + [final_url]:
        if url:
            hit = _match_signatures(url, REDIRECT_SIGNATURES)
            if hit:
                return f"redirect-signature:{hit}"

    # Layer 2 — key headers
    for key, value in headers.items():
        if key.lower() in ("location", "warning", "x-captive", "realm"):
            hit = _match_signatures(value, BLOCK_SIGNATURES)
            if hit:
                return f"header-signature:{hit}"

    # Layer 3 — body HTML
    hit = _match_signatures(body[:32768], BLOCK_SIGNATURES)
    if hit:
        return f"body-signature:{hit}"
    return None


async def _fetch_cert_fingerprint(host, port):
    """TLS handshake returning (sha256_fingerprint, issuer_org)."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=CONNECT_TIMEOUT,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            if ssl_obj is None:
                return "", ""
            der = ssl_obj.getpeercert(binary_form=True)
            if not der:
                return "", ""
            fp = hashlib.sha256(der).hexdigest()
            issuer = ""
            try:
                cert = ssl_obj.getpeercert()
                rdn = dict(x[0] for x in cert.get("issuer", ()))
                issuer = rdn.get("organizationName", "")
            except Exception:
                pass
            return fp, issuer
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (asyncio.TimeoutError, ssl.SSLError, OSError, ConnectionError):
        return "", ""


def _classify(result):
    if result.speed_kbps is not None and result.speed_kbps >= FAST_THRESHOLD_KBPS:
        return VERDICT_FAST
    if result.speed_kbps is not None and result.speed_kbps > USABLE_THRESHOLD_KBPS:
        return VERDICT_USABLE
    return VERDICT_THROTTLED


_BAD_VERDICTS = (VERDICT_BLOCKED, VERDICT_TLS_BLOCKED, VERDICT_PROXY_MITM)

# ---------------------------------------------------------------------------
# Core worker
# ---------------------------------------------------------------------------


async def scan_target(session, host, semaphore):
    async with semaphore:
        best = None
        for port in PORTS:
            res = await _scan_single_port(session, host, port)
            if best is None or (best.verdict in _BAD_VERDICTS
                                and res.verdict not in _BAD_VERDICTS):
                best = res
            if res.verdict in (VERDICT_FAST, VERDICT_USABLE):
                return res
        return best


async def _scan_single_port(session, host, port):
    result = ScanResult(host=host, port=port)
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"

    if port == 443:
        result.cert_fingerprint, result.cert_issuer = (
            await _fetch_cert_fingerprint(host, port)
        )
        # --- MITM issuer check (real interception detection) ---
        if result.cert_issuer and any(sig in result.cert_issuer.lower()
                                      for sig in MITM_ISSUER_SIGNATURES):
            result.verdict = VERDICT_PROXY_MITM
            result.reason = f"mitm-issuer-detected:{result.cert_issuer}"
            return result

    timeout = aiohttp.ClientTimeout(total=TOTAL_TIMEOUT, connect=CONNECT_TIMEOUT)

    try:
        async with session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            max_redirects=6,
            ssl=_tolerant_ssl_context(),
            headers={
                "User-Agent": ("Mozilla/5.0 (Linux; Android 13; SM-A536B) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0 Mobile Safari/537.36"),
                "Accept": "*/*",
                "Connection": "close",
            },
        ) as resp:
            result.status_code = resp.status
            result.final_url = str(resp.url)
            result.server_header = resp.headers.get("Server", "")
            result.redirect_chain = [str(h.url) for h in resp.history]

            loop = asyncio.get_running_loop()
            start = loop.time()
            raw = await resp.content.read(DOWNLOAD_SAMPLE)
            elapsed = max(loop.time() - start, 1e-6)

            result.body_bytes = len(raw)
            cl = resp.headers.get("Content-Length")
            result.content_length = int(cl) if cl and cl.isdigit() else None

            if raw:
                result.speed_kbps = round(len(raw) / elapsed / 1024, 2)

            # Captive portal / deep redirect check
            body_text = raw.decode("utf-8", errors="replace")
            block_hit = _is_captive_or_blocked(
                resp.headers, body_text, result.final_url, result.redirect_chain
            )
            if block_hit:
                result.verdict = VERDICT_BLOCKED
                result.reason = block_hit
                return result

            # Tiny-response interception check
            effective_size = result.content_length or result.body_bytes
            if 0 < effective_size < TINY_RESPONSE_BYTES:
                sig = _match_signatures(body_text, BLOCK_SIGNATURES)
                if sig or resp.status in (301, 302, 303, 307, 308):
                    result.verdict = VERDICT_BLOCKED
                    result.reason = f"tiny-intercept-response:{sig or 'redirect'}"
                elif raw.strip() == b"" and effective_size > 0:
                    result.verdict = VERDICT_BLOCKED
                    result.reason = "whitespace-padded-empty-response"
                else:
                    result.verdict = VERDICT_THROTTLED
                    result.reason = f"tiny-response-{effective_size}b-inspected"
                return result

            result.verdict = _classify(result)
            return result

    except aiohttp.ClientSSLError as exc:
        result.verdict = VERDICT_TLS_BLOCKED
        result.reason = f"ssl-handshake-rejected:{type(exc).__name__}"
    except aiohttp.TooManyRedirects:
        result.verdict = VERDICT_BLOCKED
        result.reason = "redirect-loop-suspected-captive-portal"
    except asyncio.TimeoutError:
        result.verdict = VERDICT_TLS_BLOCKED
        result.reason = "connect-or-read-timeout"
    except aiohttp.ClientConnectorError as exc:
        msg = str(exc).lower()
        if "certificate" in msg or "ssl" in msg:
            result.verdict = VERDICT_TLS_BLOCKED
            result.reason = f"tls-layer-failure:{type(exc).__name__}"
        else:
            result.verdict = VERDICT_TLS_BLOCKED
            result.reason = f"connection-failed:{type(exc).__name__}"
    except (ConnectionResetError, OSError) as exc:
        result.verdict = VERDICT_TLS_BLOCKED
        result.reason = f"network-drop:{type(exc).__name__}"
    except Exception as exc:
        result.verdict = VERDICT_BLOCKED
        result.reason = f"unexpected:{type(exc).__name__}:{exc}"
    return result


_SSL_CTX = None


def _tolerant_ssl_context():
    global _SSL_CTX
    if _SSL_CTX is None:
        _SSL_CTX = ssl.create_default_context()
        _SSL_CTX.check_hostname = False
        _SSL_CTX.verify_mode = ssl.CERT_NONE
        try:
            _SSL_CTX.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
    return _SSL_CTX


# ---------------------------------------------------------------------------
# Public scan API
# ---------------------------------------------------------------------------


async def scan_hosts(hosts, concurrency=200):
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency * 2,
        limit_per_host=3,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
    )
    async with aiohttp.ClientSession(connector=connector) as session:
        tasks = [scan_target(session, h, semaphore) for h in hosts]
        done = await asyncio.gather(*tasks, return_exceptions=True)
        results = []
        for item in done:
            if isinstance(item, ScanResult):
                results.append(item)
            elif isinstance(item, Exception):
                log.warning("worker exception swallowed: %s", item)
        return results


def filter_working(results):
    keep = [r for r in results if r.verdict in (VERDICT_FAST, VERDICT_USABLE)]
    keep.sort(key=lambda r: (r.verdict != VERDICT_FAST,
                             -(r.speed_kbps or 0), r.latency_ms or 9999))
    return keep


def working_hosts_text(results):
    return "\n".join(f"{r.host}:{r.port}" for r in filter_working(results))


# ---------------------------------------------------------------------------
# ZERO-RATING PROBE — the true bug-host test.
# Run ONLY on the target zero-balance SIM (mobile data ON, Wi-Fi OFF,
# no airtime). If the TLS handshake completes with zero balance, the
# carrier's billing/DPI treats this host as free -> valid bug host.
# ---------------------------------------------------------------------------


async def zero_rating_probe(host, port=443, timeout=6.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    res = {"host": host, "port": port, "zero_rated": False, "reason": ""}
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx),
            timeout=timeout,
        )
        try:
            ssl_obj = writer.get_extra_info("ssl_object")
            der = ssl_obj.getpeercert(binary_form=True) if ssl_obj else None
            if der:
                res.update(zero_rated=True, reason="handshake-completed-free")
            else:
                res["reason"] = "connected-no-cert"
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    except (asyncio.TimeoutError, ssl.SSLError, OSError, ConnectionError) as exc:
        res["reason"] = f"carrier-blocked:{type(exc).__name__}"
    return res


async def probe_hosts(hosts, concurrency=20):
    sem = asyncio.Semaphore(concurrency)

    async def guarded(h):
        async with sem:
            r = await zero_rating_probe(h)
            log.info("PROBE %-42s %s (%s)", h,
                     "FREE" if r["zero_rated"] else "blocked", r["reason"])
            return r

    return await asyncio.gather(*[guarded(h) for h in hosts])
