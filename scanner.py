"""
scanner.py - Luphahla Bugscan async verification engine (v4).

Zero-rating / tunnel-compat reality check.
The old scanner only told you "this host answers fast from the internet".
That is NOT the same as "this host tunnels free internet".

v4 answers the actual question a HA Tunnel / Stark VPN / HTTP Custom
user cares about:

  1. SNI-FLEX TEST
     Tunnel apps do their magic by completing a TLS handshake while
     sending an ARBITRARY or ABSENT SNI. Whether the endpoint accepts
     that is the single strongest predictor that a host will tunnel.

       random-sni : handshake OK with ANY bogus SNI  -> best anchor
       no-sni     : handshake OK with NO SNI field    -> good anchor
       strict     : rejects mismatched/absent SNI     -> weak anchor

  2. ALPN / h2 DETECTION  (h2 edges multiplex better under tunnel apps)

  3. KEEPALIVE STABILITY  (carrier DPI drops long-lived idle sockets;
     that is the #1 reason a "verified" host kills a tunnel 30s in)

  4. REAL LATENCY (connect + TLS + first byte)

  5. MEDIAN-OF-3 SPEED + JITTER

  6. CLOUDFLARE ALT PORTS  2053/2083/2087/2096/8443 scanned alongside
     443/8080/80.

  7. TUNNEL SCORE (0-100)  - one number = how good this host:port is as
     a free-internet tunnel anchor. /hosts and /api/results are sorted
     by it.

Verdicts and MITM/captive signatures are unchanged from working v3.
"""

from __future__ import annotations

import asyncio
import logging
import re
import ssl
import time
from dataclasses import dataclass, field
from typing import Optional

import aiohttp

log = logging.getLogger("luphahla.scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Cloudflare alt-ports are valid TLS entry points on CDN edges and are
# scanned alongside the classic 443/8080/80. Keep 443 first: it is the
# default port every tunnel app tries.
PORTS = (443, 8080, 80, 2053, 2083, 2087, 2096, 8443)

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

VERDICTS_WORKING = (VERDICT_FAST, VERDICT_USABLE)

SNI_TEST_TIMEOUT = 6.0
KEEPALIVE_HOLD_S = 45
SPEED_SAMPLES = 3
SPEED_SAMPLE_GAP_S = 0.5
SCAN_RETRIES = 2
RETRY_BACKOFF_S = 1.0

# Tunnel apps send an arbitrary SNI. Test with a clearly non-existent
# passenger hostname so we KNOW it is not doing hostname matching.
SNI_FLEX_PROBE_NAME = "random-8137f2-probe.invalid"

# ---------------------------------------------------------------------------
# Block / captive / MITM signatures (unchanged from working v3)
# ---------------------------------------------------------------------------

BLOCK_SIGNATURES = tuple(
    re.compile(sig, re.IGNORECASE)
    for sig in (
        r"\brecharge\b", r"\bbalance\b", r"\btop\s?up\b", r"\btopup\b",
        r"\bcaptive\b", r"\bonestfunds\b", r"\bbuy\s+data\b",
        r"\binsufficient\s+balance\b", r"\bairtime\b",
        r"\bbundle\b.*\bexpired\b", r"\bdata\s+bundle\b",
        r"\bplease\s+dial\b", r"\bzero\s+balance\b",
        r"\bportal\b.*\blogin\b", r"\bwifi\s+login\b",
        r"\bhotspot\s+login\b", r"\binternet\s+blocked\b",
        r"\bpaywall\b", r"\bpurchase\s+data\b", r"\bdial\s+\*?\d+#\b",
    )
)

REDIRECT_SIGNATURES = tuple(
    re.compile(sig, re.IGNORECASE)
    for sig in (
        "recharge", "topup", "top-up", "captive", "portal", "billing",
        "paywall", "payment", "subscribe", "airtime", "onestfunds",
        "balance", "buydata",
    )
)

# Interception middleboxes present a leaf cert whose issuer is a DPI
# vendor. Any issuer match means the carrier inspects this TLS stream
# and will likely mess with a tunnel.
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
    verdict: str = VERDICT_BLOCKED
    status_code: Optional[int] = None
    server_header: str = ""
    latency_ms: Optional[float] = None
    speed_kbps: Optional[float] = None
    jitter_pct: Optional[float] = None
    content_length: Optional[int] = None
    body_bytes: int = 0
    final_url: str = ""
    cert_fingerprint: str = ""
    cert_issuer: str = ""
    reason: str = ""
    redirect_chain: list = field(default_factory=list)
    sni_flex: str = "untested"          # random-sni | no-sni | strict | untested
    no_sni_ok: bool = False
    alpn: str = ""                      # h2 | http/1.1 | ""
    stable: Optional[bool] = None       # keepalive test result
    tunnel_score: int = 0

    def to_row(self) -> dict:
        return {
            "host": self.host,
            "port": self.port,
            "verdict": self.verdict,
            "status_code": self.status_code,
            "server_header": self.server_header,
            "latency_ms": self.latency_ms,
            "speed_kbps": self.speed_kbps,
            "jitter_pct": self.jitter_pct,
            "content_length": self.content_length,
            "body_bytes": self.body_bytes,
            "final_url": self.final_url,
            "cert_fp": self.cert_fingerprint,
            "cert_issuer": self.cert_issuer,
            "reason": self.reason,
            "sni_flex": self.sni_flex,
            "no_sni_ok": self.no_sni_ok,
            "alpn": self.alpn,
            "stable": self.stable,
            "tunnel_score": self.tunnel_score,
        }


# ---------------------------------------------------------------------------
# Low-level detection helpers
# ---------------------------------------------------------------------------


def _match_signatures(text, sigs):
    for sig in sigs:
        if sig.search(text):
            return sig.pattern
    return None


def _is_captive_or_blocked(headers, body, final_url, chain):
    all_urls = list(chain) + [final_url]
    for url in all_urls:
        if url:
            hit = _match_signatures(url, REDIRECT_SIGNATURES)
            if hit:
                return f"redirect-signature:{hit}"
    for key, value in headers.items():
        if key.lower() in ("location", "warning", "x-captive", "realm"):
            hit = _match_signatures(value, BLOCK_SIGNATURES)
            if hit:
                return f"header-signature:{hit}"
    hit = _match_signatures(body, BLOCK_SIGNATURES)
    if hit:
        return f"body-signature:{hit}"
    return None


def _classify_speed(speed_kbps):
    if speed_kbps is None:
        return VERDICT_THROTTLED
    if speed_kbps >= FAST_THRESHOLD_KBPS:
        return VERDICT_FAST
    if speed_kbps >= USABLE_THRESHOLD_KBPS:
        return VERDICT_USABLE
    return VERDICT_THROTTLED


# ---------------------------------------------------------------------------
# Tolerant SSL context
# ---------------------------------------------------------------------------

_SSL_CTX = None


def _tolerant_ssl_context():
    global _SSL_CTX
    if _SSL_CTX is None:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            ctx.set_ciphers("DEFAULT:@SECLEVEL=1")
        except ssl.SSLError:
            pass
        _SSL_CTX = ctx
    return _SSL_CTX


# ---------------------------------------------------------------------------
# Raw TLS open with/without a real hostname
# ---------------------------------------------------------------------------


async def _open_tls_raw(host, port, cert_hostname=None, timeout=SNI_TEST_TIMEOUT,
                        semaphore=None):
    """
    Open a raw TLS connection WITHOUT any HTTP request. Passing
    cert_hostname=None sends NO SNI extension at all. A completed
    handshake here means the edge/carrier accepted a non-standard SNI.
    """
    async def _do():
        ctx = _tolerant_ssl_context()
        if cert_hostname is None:
            coro = asyncio.open_connection(host, port, ssl=ctx)
        else:
            coro = asyncio.open_connection(host, port, ssl=ctx,
                                           server_hostname=cert_hostname)
        reader, writer = await asyncio.wait_for(coro, timeout=timeout)
        return reader, writer

    if semaphore is None:
        return await _do()
    async with semaphore:
        return await _do()


# ---------------------------------------------------------------------------
# SNI-FLEX + ALPN test  (the v4 core)
# ---------------------------------------------------------------------------


async def sni_flex_test(result, semaphore=None):
    """
    Determine how permissive this endpoint is about the SNI it receives:
      random-sni -> passes the strictest tunnel requirement
      no-sni     -> accepts missing SNI but not a bogus one
      strict     -> neither passes; the app MUST use the real hostname
    Records the negotiated ALPN protocol (h2 vs http/1.1).

    Plain-HTTP ports are skipped (SNI flexibility is irrelevant without
    TLS). They remain scannable as CONNECT-proxy candidates but get no
    SNI bonus.
    """
    if result.port == 80 or result.port == 8080:
        result.sni_flex = "untested"
        return result

    alpn = ""

    # Pass 1 - arbitrary / bogus SNI.
    ok_random = False
    try:
        reader, writer = await _open_tls_raw(
            result.host, result.port,
            cert_hostname=SNI_FLEX_PROBE_NAME,
            semaphore=semaphore)
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            found = ssl_obj.selected_alpn_protocol()
            if found:
                alpn = found
        ok_random = True
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        ok_random = False

    if ok_random:
        result.sni_flex = "random-sni"
        result.alpn = alpn
        return result

    # Pass 2 - no SNI extension at all.
    ok_nosni = False
    try:
        reader, writer = await _open_tls_raw(
            result.host, result.port,
            cert_hostname=None,
            semaphore=semaphore)
        ssl_obj = writer.get_extra_info("ssl_object")
        if ssl_obj is not None:
            found = ssl_obj.selected_alpn_protocol()
            if found:
                alpn = found
        ok_nosni = True
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    except Exception:
        ok_nosni = False

    if ok_nosni:
        result.sni_flex = "no-sni"
        result.no_sni_ok = True
        result.alpn = alpn
    else:
        result.sni_flex = "strict"
    return result


# ---------------------------------------------------------------------------
# Keepalive stability test
# ---------------------------------------------------------------------------


async def keepalive_test(result, semaphore=None):
    """
    Hold the TLS socket KEEPALIVE_HOLD_S seconds. If it survives, the
    carrier edge is unlikely to kill long-lived tunnel connections to
    this host.
    """
    if result.port == 80 or result.port == 8080:
        result.stable = None
        return result
    try:
        reader, writer = await _open_tls_raw(
            result.host, result.port,
            cert_hostname=result.host,
            timeout=CONNECT_TIMEOUT,
            semaphore=semaphore)
        await asyncio.sleep(KEEPALIVE_HOLD_S)
        writer.close()
        try:
            await writer.wait_closed()
            result.stable = True
        except Exception:
            result.stable = False
    except Exception:
        result.stable = False
    return result


# ---------------------------------------------------------------------------
# Median-of-3 speed + jitter sampling
# ---------------------------------------------------------------------------


async def _sample_speed_once(session, result):
    scheme = "https" if result.port != 80 else "http"
    url = f"{scheme}://{result.host}:{result.port}/"
    try:
        start = time.monotonic()
        async with session.get(
            url,
            max_redirects=4,
            ssl=_tolerant_ssl_context(),
            timeout=aiohttp.ClientTimeout(
                total=TOTAL_TIMEOUT, sock_connect=CONNECT_TIMEOUT),
            headers={
                "User-Agent": ("Mozilla/5.0 (Linux; Android 13; SM-A536B) "
                               "AppleWebKit/537.36 (KHTML, like Gecko) "
                               "Chrome/120.0 Mobile Safari/537.36"),
                "Accept": "*/*",
                "Connection": "close",
            },
        ) as resp:
            result.status_code = resp.status
            result.server_header = resp.headers.get("Server", "")
            chunk = await resp.content.read(DOWNLOAD_SAMPLE)
        elapsed = max(time.monotonic() - start, 1e-6)
        if not chunk:
            return None
        return round(len(chunk) / elapsed / 1024, 2)
    except Exception:
        return None


def _median_of(vals):
    clean = [v for v in vals if v is not None]
    if not clean:
        return None
    clean.sort()
    mid = len(clean) // 2
    if len(clean) % 2 == 1:
        return clean[mid]
    return round((clean[mid - 1] + clean[mid]) / 2.0, 2)


def _jitter_of(vals, median):
    clean = [v for v in vals if v is not None]
    if not clean or not median:
        return None
    diffs = [abs(v - median) / median * 100.0 for v in clean]
    return round(sum(diffs) / len(diffs), 1)


# ---------------------------------------------------------------------------
# One-shot HTTP verification (capable of real verdicts + latency)
# ---------------------------------------------------------------------------


async def _verify_once(session, result, semaphore):
    scheme = "https" if result.port != 80 else "http"
    url = f"{scheme}://{result.host}:{result.port}/"
    loop = asyncio.get_running_loop()
    t0 = loop.time()

    try:
        async with semaphore:
            async with session.get(
                url,
                max_redirects=6,
                ssl=_tolerant_ssl_context(),
                timeout=aiohttp.ClientTimeout(
                    total=TOTAL_TIMEOUT, sock_connect=CONNECT_TIMEOUT),
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
                result.latency_ms = round((loop.time() - t0) * 1000, 1)

                start = loop.time()
                raw = await resp.content.read(DOWNLOAD_SAMPLE)
                elapsed = max(loop.time() - start, 1e-6)

                result.body_bytes = len(raw)
                result.content_length = (
                    int(cl) if (cl := resp.headers.get("Content-Length"))
                    and cl.isdigit() else None)
                if raw:
                    result.speed_kbps = round(len(raw) / elapsed / 1024, 2)

                body_text = raw.decode("utf-8", errors="replace")

                block_hit = _is_captive_or_blocked(
                    resp.headers, body_text, result.final_url,
                    result.redirect_chain)
                if block_hit:
                    result.verdict = VERDICT_BLOCKED
                    result.reason = block_hit
                    return result

                effective_size = (result.content_length
                                  if result.content_length is not None
                                  else result.body_bytes)
                if 0 < effective_size < TINY_RESPONSE_BYTES:
                    sig = _match_signatures(body_text, BLOCK_SIGNATURES)
                    if sig or resp.status in (301, 302, 303, 307, 308):
                        result.verdict = VERDICT_BLOCKED
                        result.reason = (f"tiny-intercept-response:"
                                         f"{sig or 'redirect'}")
                    elif raw.strip() == b"":
                        result.verdict = VERDICT_BLOCKED
                        result.reason = "whitespace-padded-empty-response"
                    else:
                        result.verdict = VERDICT_THROTTLED
                        result.reason = (f"tiny-response-"
                                         f"{effective_size}b-inspected")
                    return result

                result.verdict = _classify_speed(result.speed_kbps)
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
        result.verdict = VERDICT_TLS_BLOCKED
        result.reason = f"scan-error:{type(exc).__name__}:{exc}"
    return result


# ---------------------------------------------------------------------------
# Retry-aware HTTP verification
# ---------------------------------------------------------------------------


async def _verify_with_retry(session, result, semaphore):
    final = result
    for attempt in range(SCAN_RETRIES + 1):
        probe = ScanResult(host=result.host, port=result.port)
        probe = await _verify_once(session, probe, semaphore)
        if probe.verdict != VERDICT_TLS_BLOCKED or attempt == SCAN_RETRIES:
            final = probe
            break
        await asyncio.sleep(RETRY_BACKOFF_S * (attempt + 1))
    return final


# ---------------------------------------------------------------------------
# TUNNEL SCORE (0-100)
# ---------------------------------------------------------------------------
# Weights were derived from what actually kills/breaks a HA Tunnel /
# Stark VPN tunnel on real African carriers, in rough order of impact:
#   SNI flexibility >= stability > verdict > speed > latency.
_N = dict(FLEX={"random-sni": 40, "no-sni": 30, "strict": 8, "untested": 10},
          ALPN_H2=5,
          STABLE_YES=15, STABLE_NO=-15,
          SPEED_FAST=14, SPEED_USABLE=8,
          LAT_GT400=-6, LAT_150_400=4, LAT_LT150=8,
          JITTER_PENALTY_MAX=6)


def compute_tunnel_score(result) -> int:
    s = 0
    s += _N["FLEX"].get(result.sni_flex, 8)
    if result.alpn == "h2":
        s += _N["ALPN_H2"]
    if result.stable is True:
        s += _N["STABLE_YES"]
    elif result.stable is False:
        s += _N["STABLE_NO"]
    # Verdict
    if result.verdict == VERDICT_FAST:
        s += _N["SPEED_FAST"]
    elif result.verdict == VERDICT_USABLE:
        s += _N["SPEED_USABLE"]
    # Latency
    if result.latency_ms is not None:
        if result.latency_ms < 150:
            s += _N["LAT_LT150"]
        elif result.latency_ms < 400:
            s += _N["LAT_150_400"]
        else:
            s += _N["LAT_GT400"]
    # Jitter penalty: >50% jitter makes a host feel broken.
    if result.jitter_pct is not None and result.jitter_pct > 50:
        s -= _N["JITTER_PENALTY_MAX"]
    return max(0, min(100, int(round(s))))


# ---------------------------------------------------------------------------
# Full per-target verification pipeline
# ---------------------------------------------------------------------------


async def _scan_target_pipeline(session, host, port, semaphore, deep=False):
    """
    Hosts that already proved viable are put through the deep tunnel
    pipeline (flex + keepalive + 3-sample median + score, ~60s each).
    Everything else keeps a single fast HTTP round to classify it.
    """
    result = ScanResult(host=host, port=port)
    result = await _verify_with_retry(session, result, semaphore)

    if not deep or result.verdict not in VERDICTS_WORKING:
        # Even non-working rows get a tunnel attempt on TLS ports - a
        # host that returns 200 fast but refuses bogus SNI is still NOT
        # a useful bug host, so we surface that to the caller.
        if port != 80 and port != 8080:
            result = await sni_flex_test(result, semaphore)
        result.tunnel_score = compute_tunnel_score(result)
        return result

    # Deep mode (proven host) - now rate its tunnel-usability.
    result = await sni_flex_test(result, semaphore)
    result = await keepalive_test(result, semaphore)

    # Median-of-3 speed after the flex/keepalive window.
    samples = []
    for i in range(SPEED_SAMPLES):
        sample = await _sample_speed_once(session, result)
        samples.append(sample)
        if i < SPEED_SAMPLES - 1:
            await asyncio.sleep(SPEED_SAMPLE_GAP_S)
    result.speed_kbps = _median_of(samples)
    result.jitter_pct = _jitter_of(samples, result.speed_kbps)

    # If a slow-but-"usable" host got the time upgrade into
    # VERDICT_FAST from better sampling it will reflect in the score.
    real_verdict = _classify_speed(result.speed_kbps)
    if real_verdict in VERDICTS_WORKING:
        result.verdict = real_verdict

    result.tunnel_score = compute_tunnel_score(result)
    return result


# ---------------------------------------------------------------------------
# Public scan API  (unchanged signature - callers use scanner.scan_hosts)
# ---------------------------------------------------------------------------


async def scan_hosts(hosts, concurrency=200, deep_probe=True):
    """
    hosts: iterable of "host" or "host:port" strings.
    Returns: list[ScanResult], sorted by tunnel_score desc, then fast
    verdicts first.
    """
    semaphore = asyncio.Semaphore(concurrency)
    connector = aiohttp.TCPConnector(
        limit=concurrency * 2,
        limit_per_host=2,
        ttl_dns_cache=600,
        enable_cleanup_closed=True,
    )

    # Expand hosts into (host, port) targets across the configured ports.
    targets = []
    for item in hosts:
        item = str(item).strip()
        if not item:
            continue
        if ":" in item:
            host, _, port = item.rpartition(":")
            try:
                port = int(port)
            except ValueError:
                continue
            targets.append((host, port))
        else:
            for port in PORTS:
                targets.append((item, port))

    results = []
    async with aiohttp.ClientSession(connector=connector) as session:
        # 1) Fast pass - classify every target on 443 (and 80/8080).
        primary = [(h, 443) for h, p in targets if p == 443]
        fallback = [(h, p) for h, p in targets if p != 443]
        primary += fallback
        work = [asyncio.ensure_future(
            _scan_target_pipeline(session, h, p, semaphore,
                                  deep=False))
            for h, p in primary]
        done = await asyncio.gather(*work, return_exceptions=True)
        for r in done:
            if isinstance(r, ScanResult):
                results.append(r)
            elif isinstance(r, Exception):
                log.warning("target worker error: %s", r)

        # 2) Deep pass (deep_probe) on working targets only.
        if deep_probe:
            deep_targets = [(r.host, r.port) for r in results
                            if r.verdict in VERDICTS_WORKING]
            if deep_targets:
                log.info("deep probe %d working targets "
                         "(flex+keepalive+median3)", len(deep_targets))
                work2 = [asyncio.ensure_future(
                    _scan_target_pipeline(session, h, p, semaphore,
                                          deep=True))
                    for h, p in deep_targets]
                done2 = await asyncio.gather(*work2, return_exceptions=True)
                merged = {}
                for r in results:
                    merged[(r.host, r.port)] = r
                for r in done2:
                    if isinstance(r, ScanResult) and r.verdict in VERDICTS_WORKING:
                        merged[(r.host, r.port)] = r
                results = list(merged.values())

    # Sort: tunnel_score desc, then fast verdict first, then by name.
    results.sort(
        key=lambda r: (r.tunnel_score, r.verdict == VERDICT_USABLE,
                       r.host),
        reverse=False)
    results.sort(key=lambda r: (r.tunnel_score,
                                0 if r.verdict == VERDICT_FAST else 1),
                 reverse=True)
    log.info("scan complete: %d rows, %d working",
             len(results),
             len([r for r in results if r.verdict in VERDICTS_WORKING]))
    return results


def filter_working(results):
    keep = [r for r in results if r.verdict in VERDICTS_WORKING]
    keep.sort(key=lambda r: (r.tunnel_score,
                             0 if r.verdict == VERDICT_FAST else 1),
              reverse=True)
    return keep


def working_hosts_text(results):
    return "\n".join(
        f"{r.host}:{r.port}  #{r.tunnel_score} v={r.verdict} "
        f"sni={r.sni_flex} kbps={r.speed_kbps}"
        for r in filter_working(results))


def working_hosts_plain(results):
    """Machine-parseable: host:port per line, score-ordered top 300."""
    top = filter_working(results)[:300]
    return "\n".join(f"{r.host}:{r.port}" for r in top)


# ---------------------------------------------------------------------------
# ZERO-RATING PROBE - the true SIM-side test. Run on the target
# carrier with mobile data ON + Wi-Fi OFF + zero or real balance as the
# user intends to test. A completed handshake there = carrier lets it
# through on that data plan.
# ---------------------------------------------------------------------------


async def zero_rating_probe(host, port=443, timeout=6.0):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    res = {"host": host, "port": port,
           "handshake_ok": False, "flex": "untested", "reason": ""}
    # Default SNI probe first: arbitrary SNI via bogus name.
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=SNI_FLEX_PROBE_NAME),
            timeout=timeout)
        ssl_obj = w.get_extra_info("ssl_object")
        if ssl_obj is not None:
            # If even a cert came back we reached a real edge.
            if ssl_obj.getpeercert(binary_form=True):
                res.update(handshake_ok=True, flex="random-sni",
                           reason="handshake-completed-with-bogus-sni")
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        if res["handshake_ok"]:
            return res
    except (asyncio.TimeoutError, ssl.SSLError, OSError, ConnectionError):
        pass
    # Real-SNI pass (what a non-tunnel browser would do).
    try:
        r, w = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx,
                                    server_hostname=host),
            timeout=timeout)
        ssl_obj = w.get_extra_info("ssl_object")
        if ssl_obj is not None and ssl_obj.getpeercert(binary_form=True):
            res.update(handshake_ok=True, flex="strict",
                       reason="only-real-sni-works")
        w.close()
        try:
            await w.wait_closed()
        except Exception:
            pass
        if res["handshake_ok"]:
            return res
    except (asyncio.TimeoutError, ssl.SSLError, OSError, ConnectionError) as exc:
        res["reason"] = f"network-blocked:{type(exc).__name__}"
    return res


async def probe_hosts(hosts, concurrency=20):
    sem = asyncio.Semaphore(concurrency)

    async def guarded(item):
        host, _, port_str = str(item).rpartition(":")
        port = int(port_str) if port_str and port_str.isdigit() else 443
        host = host or item
        async with sem:
            r = await zero_rating_probe(host, port=port)
            log.info("PROBE %-40s %s (%s)", f"{host}:{port}",
                     "FREE" if r["handshake_ok"] else "blocked",
                     r["reason"])
            return r

    return await asyncio.gather(*[guarded(h) for h in hosts])
