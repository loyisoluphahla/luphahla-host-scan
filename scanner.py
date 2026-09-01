"""
scanner.py — Async SNI/Bug Host verification engine.

Multi-layer ISP-block detection:
  1. SSL certificate SHA-256 fingerprint (MITM/interception proxy detection)
  2. Deep redirect chain + captive portal signature analysis
  3. Body HTML block-signature sweep
  4. Content-Length / tiny-response interception checks
  5. Throughput classification: fast / usable / throttled
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

log = logging.getLogger("sni.scanner")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

PORTS: tuple = (443, 8080, 80)

CONNECT_TIMEOUT = 8           # seconds
TOTAL_TIMEOUT = 15            # seconds per request cycle
DOWNLOAD_SAMPLE = 128 * 1024  # bytes sampled for throughput measurement

FAST_THRESHOLD_KBPS = 10.0    # >= 10 KB/s  -> 'fast'
USABLE_THRESHOLD_KBPS = 0.2   # >  0.2 KB/s -> 'usable'
TINY_RESPONSE_BYTES = 200     # < 200 bytes on real pages = interception suspect

VERDICT_FAST = "fast"
VERDICT_USABLE = "usable"
VERDICT_THROTTLED = "throttled"
VERDICT_TLS_BLOCKED = "tls-blocked"
VERDICT_PROXY_MITM = "proxy-mitm"
VERDICT_BLOCKED = "blocked"

# ---------------------------------------------------------------------------
# Block signatures (matched against headers, redirect URLs and body HTML)
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
# Known ISP middlebox / interception proxy certificate SHA-256 fingerprints.
# Replace these placeholder digests with real ones captured from middleboxes
# on your target carrier networks. Any leaf cert matching an entry here is
# flagged PROXY_MITM / BLOCKED.
# ---------------------------------------------------------------------------

MITM_CERT_FINGERPRINTS = frozenset(
    fp.lower().replace(":", "").replace(" ", "")
    for fp in (
        "a3b3981f3d5c8e0d2f1a4b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e",
        "9f1c3a7b5d2e8f0a4c6b1d3e5f7a9b0c2d4e6f8a0b2c4d6e8f0a2b4c6d8e0f2a",
        "7a5c3e1f9d7b5a3c1e9f7d5b3a1c9e7f5d3b1a9c7e5f3d1b9a7c5e3f1d9b7a5c",
        "5e3f1d9b7a5c3e1f9d7b5a3c1e9f7d5b3a1c9e7f5d3b1a9c7e5f3d1b9a7c5e3f",
        "3c1e9f7d5b3a1c9e7f5d3b1a9c7e5f3d1b9a7c5e3f1d9b7a5c3e1f9d7b5a3c1e",
    )
)

# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Outcome of scanning one host on one port."""

    host: str
    port: int
    verdict: str = VERDICT_BLOCKED if False else "blocked"
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
    error: str = ""

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
            "reason": self.reason,
        }


# ---------------------------------------------------------------------------
# Verification helpers
# ---------------------------------------------------------------------------


def _match_signatures(text: str, sigs) -> Optional[str]:
    for sig in sigs:
        if sig.search(text):
            return sig.pattern
    return None


def _is_captive_or_blocked(headers, body: str, final_url: str,
                           chain: list) -> Optional[str]:
    """Multi-layer block detection across redirects, headers and body."""

    # Layer 1 — every hop in the redirect chain + final URL
    for url in chain + [final_url]:
        if url:
            hit = _match_signatures(url, REDIRECT_SIGNATURES)
            if hit:
                return f"redirect-signature:{hit}"

    # Layer 2 — key header values (Location, Warning, custom portal headers)
    for key, value in headers.items():
        if key.lower() in ("location", "warning", "x-captive", "realm"):
            hit = _match_signatures(value, BLOCK_SIGNATURES)
            if hit:
                return f"header-signature:{hit}"

    # Layer 3 — body HTML content (first 32 KB is enough)
    hit = _match_signatures(body[:32768], BLOCK_SIGNATURES)
    if hit:
        return f"body-signature:{hit}"

    return None


async def _fetch_cert_fingerprint(host: str, port: int):
    """
    Independent TLS handshake to extract the leaf certificate SHA-256
    fingerprint and issuer. Returns ('', '') on any failure.
    """
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
                issuer_rdns = dict(x[0] for x in cert.get("issuer", ()))
                issuer = issuer_rdns.get("organizationName", "")
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


def _classify(result: "ScanResult") -> str:
    if result.speed_kbps is not None and result.speed_kbps >= FAST_THRESHOLD_KBPS:
        return VERDICT_FAST
    if result.speed_kbps is not None and result.speed_kbps > USABLE_THRESHOLD_KBPS:
        return VERDICT_USABLE
    return VERDICT_THROTTLED


_BAD_VERDICTS = (VERDICT_BLOCKED, VERDICT_TLS_BLOCKED, VERDICT_PROXY_MITM)


# ---------------------------------------------------------------------------
# Core worker
# ---------------------------------------------------------------------------


async def scan_target(session, host: str, semaphore) -> ScanResult:
    """
    Scan a single host across all configured ports with strict verification.
    The first port yielding a non-blocked verdict wins.
    """
    async with semaphore:
        best: Optional[ScanResult] = None

        for port in PORTS:
            res = await _scan_single_port(session, host, port)
            if best is None or (best.verdict in _BAD_VERDICTS
                                and res.verdict not in _BAD_VERDICTS):
                best = res
            if res.verdict in (VERDICT_FAST, VERDICT_USABLE):
                return res

        return best  # type: ignore[return-value]


async def _scan_single_port(session, host: str, port: int) -> ScanResult:
    
    result = ScanResult(host=host, port=port)
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{host}:{port}/"

    if port == 443:
        result.cert_fingerprint, result.cert_issuer = (
            await _fetch_cert_fingerprint(host, port)
        )
        # SSL fingerprint integrity check — ISP middlebox detection
        if result.cert_fingerprint and result.cert_fingerprint in MITM_CERT_FINGERPRINTS:
            result.verdict = VERDICT_PROXY_MITM
            result.reason = "cert-fingerprint-matches-mitm-profile"
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

            # ---- THROUGHPUT ------------------------------------------
            if raw:
                result.speed_kbps = round(len(raw) / elapsed / 1024, 2)

            # ---- CAPTIVE PORTAL / DEEP REDIRECT CHECK -----------------
            body_text = raw.decode("utf-8", errors="replace")
            block_hit = _is_captive_or_blocked(
                resp.headers, body_text, result.final_url, result.redirect_chain
            )
            if block_hit:
                result.verdict = VERDICT_BLOCKED
                result.reason = block_hit
                return result

            # ---- CONTENT-LENGTH / TINY RESPONSE CHECK ------------------
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

            # ---- FINAL CLASSIFICATION ----------------------------------
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
    except Exception as exc:  # defensive — never kill the worker loop
        result.verdict = VERDICT_BLOCKED
        result.reason = f"unexpected:{type(exc).__name__}:{exc}"
    return result


_SSL_CTX = None


def _tolerant_ssl_context() -> ssl.SSLContext:
    """Shared permissive TLS context: verify off, legacy cipher compat."""
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
# Public API
# ---------------------------------------------------------------------------


async def scan_hosts(hosts: list, concurrency: int = 200) -> list:
    """Scan hosts concurrently. Returns all ScanResults; filter as needed."""
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


def filter_working(results: list) -> list:
    """Keep only 'fast' and 'usable' verdicts, sorted best-first."""
    keep = [r for r in results if r.verdict in (VERDICT_FAST, VERDICT_USABLE)]
    keep.sort(key=lambda r: (r.verdict != VERDICT_FAST,
                             -(r.speed_kbps or 0), r.latency_ms or 9999))
    return keep


def working_hosts_text(results: list) -> str:
    """Plain-text array of working SNI hosts in host:port form."""
    return "\n".join(f"{r.host}:{r.port}" for r in filter_working(results))
