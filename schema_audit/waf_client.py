"""
WAFSafeClient  (the brief's "WAFClient" + "RateLimiter")
=========================================================
A polite, defensive async fetcher for sensitive domains (banking, finance...).

What "WAF-proof" means here: give the WAF no reason to fire, and back off the
moment it does.  It is NOT an anti-bot bypass, and this is intentional:

  * NO TLS/JA3/HTTP2 fingerprint impersonation (curl_cffi etc.), NO rotating
    pool of browser User-Agents, NO forged sec-ch-ua / sec-fetch-* headers.
    Those exist only to make automated traffic look like a human browser so it
    slips past a bank's bot/fraud controls.  Tooling built for that is out of
    scope; if a site's owner wants you to audit it, they can allowlist you.
  * NO "retry with a different fingerprint" after a block.

What it does instead
  * global RPS cap (`throttler.Throttler`) + global concurrency cap
  * per-host pacing (2-5 s + jitter, 1 request at a time) on sensitive hosts
  * robots.txt obeyed incl. Crawl-delay; unreachable / 5xx robots => don't crawl
  * ONE honest, identifiable User-Agent (override with --user-agent; add
    --contact so the site owner can reach you or allowlist you)
  * 429 / 5xx  => bounded retries honouring Retry-After / exponential backoff
  * 403 / 406 / 451 / challenge page => logged to errors.log, NEVER retried;
    a per-host circuit breaker stops hitting the host after a few strikes
  * URLs with embedded credentials, and (sensitive hosts) login / account /
    online-banking paths, are never fetched
"""
from __future__ import annotations

import asyncio
import gzip
import io
import logging
import random
import re
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from urllib import robotparser
from urllib.parse import urlparse

import aiohttp
from throttler import Throttler

log = logging.getLogger("schema_audit")
err_log = logging.getLogger("schema_audit.errors")

TOOL, VERSION = "SchemaAudit", "1.0"
MAX_BODY = 5 * 1024 * 1024
MAX_RETRIES = 2

SENSITIVE_HOST_RE = re.compile(
    r"(bank|banking|finance|financial|fintech|credit|loan|mortgage|insur|invest|wealth|brokerage|"
    r"trading|forex|payments?|paypal|swift|treasury|capital|fcu|savings|pension|\.bank$|\.gov(\.|$)|\.mil$)",
    re.I)
AUTH_PATH_RE = re.compile(
    r"/(log-?in|sign-?in|sign-?on|logon|logout|auth|oauth|sso|account|accounts|my-?account|online-?banking|"
    r"net-?banking|internet-?banking|ebanking|e-banking|secure|portal|dashboard|customer|otp|verify|"
    r"password|reset|register|checkout|cart)(/|$|\.|\?)", re.I)
WAF_BODY_MARKERS = (
    "access denied", "request blocked", "request unsuccessful", "attention required", "just a moment",
    "checking your browser", "captcha", "pardon our interruption", "_incapsula_resource",
    "the requested url was rejected", "reference #", "unusual traffic", "you have been blocked",
    "datadome", "perimeterx", "bot detection", "web application firewall", "support id")


def detect_waf(headers, body_lc: str = "") -> str:
    """Name the WAF vendor from response headers/body - for the log only."""
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    server, cookies = h.get("server", ""), h.get("set-cookie", "")
    if "cloudflare" in server or "cf-ray" in h:
        return "cloudflare"
    if "akamai" in server or "reference #" in body_lc:
        return "akamai"
    if "x-iinfo" in h or "incap_ses" in cookies or "_incapsula_" in body_lc:
        return "imperva/incapsula"
    if "x-amzn-waf-action" in h or "awselb" in server:
        return "aws-waf"
    if "bigip" in server or "the requested url was rejected" in body_lc:
        return "f5"
    if "perimeterx" in body_lc:
        return "perimeterx"
    if "datadome" in body_lc or "datadome" in cookies:
        return "datadome"
    return ""


@dataclass
class FetchResult:
    url: str
    status: str            # ok | blocked_waf | circuit_open | robots_disallowed | skipped_sensitive_path |
    http_status: int = 0   # http_error | timeout | network_error | invalid_url
    raw: bytes = b""
    text: str = ""
    waf: str = ""
    remark: str = ""
    elapsed: float = 0.0


class HostGate:
    """Per-host pacing + concurrency + robots cache + circuit breaker."""

    def __init__(self, sensitive: bool):
        self.sensitive = sensitive
        self.sem = asyncio.Semaphore(1 if sensitive else 4)
        self._lock = asyncio.Lock()
        self._next = 0.0
        self.min_gap = random.uniform(2.0, 5.0) if sensitive else 0.0   # fixed per host: 2-5 s
        self.crawl_delay = 0.0
        self.max_strikes = 2 if sensitive else 4
        self.strikes = 0
        self.tripped = False
        self.robots = None                       # None | "allow" | "deny" | RobotFileParser
        self.robots_lock = asyncio.Lock()

    async def wait_slot(self):
        async with self._lock:
            now = time.monotonic()
            start = max(now, self._next)
            gap = max(self.min_gap, self.crawl_delay)
            self._next = start + gap + (random.uniform(0, 1.0) if self.sensitive else 0.0)
        if start > now:
            await asyncio.sleep(start - now)

    def strike(self, host: str):
        self.strikes += 1
        if self.strikes >= self.max_strikes and not self.tripped:
            self.tripped = True
            log.warning("Circuit breaker OPEN for %s after %d block responses - host skipped from now on",
                        host, self.strikes)


class WAFSafeClient:
    def __init__(self, args):
        self.args = args
        self.sensitive_domains = {d.strip().lower().lstrip(".")
                                  for d in (args.sensitive_domains or "").split(",") if d.strip()}
        # RateLimiter: strict global requests-per-second cap (every attempt, incl. retries, counts).
        self.throttler = Throttler(rate_limit=max(1, int(args.rps)) if args.rps >= 1 else 1,
                                   period=1.0 if args.rps >= 1 else 1.0 / args.rps)
        self.global_sem = asyncio.Semaphore(max(1, args.concurrency))      # concurrency cap
        self.gates: dict[str, HostGate] = {}
        self.session: aiohttp.ClientSession | None = None
        contact = f" (+{args.contact})" if getattr(args, "contact", None) else ""
        self.ua = args.user_agent or f"{TOOL}/{VERSION}{contact}"

    async def __aenter__(self):
        self.session = aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=self.args.timeout),
            headers={"User-Agent": self.ua, "Accept-Language": "en-US,en;q=0.8"})
        return self

    async def __aexit__(self, *exc):
        await self.session.close()

    # ---- policy ------------------------------------------------------------ #
    def is_sensitive(self, host: str) -> bool:
        host = host.split(":")[0].lower()
        if any(host == d or host.endswith("." + d) for d in self.sensitive_domains):
            return True
        return bool(self.args.waf_mode and SENSITIVE_HOST_RE.search(host))

    def gate(self, host: str) -> HostGate:
        host = host.lower()
        g = self.gates.get(host)
        if g is None:
            g = self.gates[host] = HostGate(self.is_sensitive(host))
        return g

    # ---- robots.txt -------------------------------------------------------- #
    async def _load_robots(self, scheme: str, host: str, g: HostGate):
        try:
            async with self.session.get(f"{scheme}://{host}/robots.txt",
                                        timeout=aiohttp.ClientTimeout(total=10)) as r:
                body = (await r.content.read(512 * 1024)).decode(r.charset or "utf-8", "replace")
                status = r.status
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return "deny"
        if status == 200:
            rp = robotparser.RobotFileParser()
            rp.parse(body.splitlines())
            cd = rp.crawl_delay(TOOL)
            if cd:
                g.crawl_delay = min(float(cd), 60.0)
            return rp
        if status in (401, 403):
            return "deny" if g.sensitive else "allow"
        return "deny" if status >= 500 else "allow"

    async def _robots_ok(self, url: str, g: HostGate) -> bool:
        p = urlparse(url)
        async with g.robots_lock:
            if g.robots is None:
                g.robots = await self._load_robots(p.scheme, p.netloc, g)
        if g.robots == "allow":
            return True
        if g.robots == "deny":
            return False
        return g.robots.can_fetch(TOOL, url)

    # ---- fetch ------------------------------------------------------------- #
    async def fetch(self, url: str) -> FetchResult:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            return FetchResult(url, "invalid_url", remark="only http/https URLs are supported")
        if p.username or p.password:
            return FetchResult(url, "skipped_sensitive_path", remark="URL contains credentials; not fetched")
        g = self.gate(p.netloc)
        is_map = bool(re.search(r"\.xml(\.gz)?$|robots\.txt$", p.path.lower()))
        if g.sensitive and not is_map and AUTH_PATH_RE.search(p.path or "/"):
            return FetchResult(url, "skipped_sensitive_path", remark="login/account-type path skipped on sensitive host")
        if g.tripped:
            return FetchResult(url, "circuit_open", remark=f"host stopped after {g.strikes} block responses")
        if not await self._robots_ok(url, g):
            return FetchResult(url, "robots_disallowed", remark="blocked by robots.txt (or robots.txt unavailable)")

        attempt = 0
        while True:
            if g.tripped:
                return FetchResult(url, "circuit_open", remark=f"host stopped after {g.strikes} block responses")
            t0 = time.monotonic()
            try:
                async with self.throttler, self.global_sem, g.sem:
                    if g.tripped:
                        return FetchResult(url, "circuit_open", remark="breaker opened while queued")
                    await g.wait_slot()
                    t0 = time.monotonic()
                    async with self.session.get(url, allow_redirects=True, max_redirects=5) as r:
                        raw = await r.content.read(MAX_BODY + 1)
                        status, headers, charset = r.status, r.headers, r.charset
            except asyncio.TimeoutError:
                elapsed = time.monotonic() - t0
                log.info("%s | TIMEOUT after %.1fs (attempt %d)", url, elapsed, attempt + 1)
                if attempt < MAX_RETRIES:
                    attempt += 1
                    await asyncio.sleep(2 ** attempt)
                    continue
                err_log.error("TIMEOUT %s after %d attempts", url, attempt + 1)
                return FetchResult(url, "timeout", remark="request timed out", elapsed=elapsed)
            except (aiohttp.ClientError, OSError) as e:      # DNS failure, refused, TLS, too many redirects...
                elapsed = time.monotonic() - t0
                if attempt < MAX_RETRIES and not isinstance(e, aiohttp.ClientSSLError):
                    attempt += 1
                    await asyncio.sleep(2 ** attempt)
                    continue
                err_log.error("NETWORK %s: %s", url, str(e)[:200])
                return FetchResult(url, "network_error", remark=str(e)[:200], elapsed=elapsed)

            elapsed = time.monotonic() - t0
            truncated = len(raw) > MAX_BODY
            raw = raw[:MAX_BODY]
            text = raw.decode(charset or "utf-8", errors="replace")
            body_lc = text[:60000].lower()
            waf = detect_waf(headers, body_lc)

            if status == 429 or 500 <= status < 600:
                if attempt < MAX_RETRIES:                     # polite backoff, honour Retry-After
                    ra = headers.get("Retry-After", "")
                    wait = float(ra) if ra.isdigit() else 3 * 2 ** attempt
                    attempt += 1
                    await asyncio.sleep(min(60.0, max(wait, 3.0)))
                    continue
                if status in (429, 503):
                    g.strike(p.netloc)
                    err_log.error("BLOCK/THROTTLE %s HTTP %d%s", url, status, f" [{waf}]" if waf else "")
                    return FetchResult(url, "blocked_waf", status, waf=waf,
                                       remark=f"HTTP {status} throttled after retries", elapsed=elapsed)
                err_log.error("HTTP %d %s", status, url)
                return FetchResult(url, "http_error", status, waf=waf, remark=f"HTTP {status}", elapsed=elapsed)

            if status in (403, 406, 451):                     # blocked: never retry, never disguise
                g.strike(p.netloc)
                err_log.error("WAF BLOCK %s HTTP %d%s - not retried, fingerprint NOT changed",
                              url, status, f" [{waf}]" if waf else "")
                return FetchResult(url, "blocked_waf", status, waf=waf,
                                   remark=f"HTTP {status} - request blocked" + (f" ({waf})" if waf else ""),
                                   elapsed=elapsed)
            if status == 401:
                return FetchResult(url, "http_error", status, remark="HTTP 401 - authentication required", elapsed=elapsed)
            if not 200 <= status < 300:
                return FetchResult(url, "http_error", status, waf=waf, remark=f"HTTP {status}", elapsed=elapsed)

            if len(raw) < 50000 and any(m in body_lc for m in WAF_BODY_MARKERS) \
                    and "ld+json" not in body_lc and "itemscope" not in body_lc and not is_map:
                g.strike(p.netloc)
                err_log.error("CHALLENGE PAGE %s HTTP %d looks like a bot challenge%s", url, status,
                              f" [{waf}]" if waf else "")
                return FetchResult(url, "blocked_waf", status, waf=waf,
                                   remark="HTTP 200 but body looks like a WAF/bot-challenge page", elapsed=elapsed)
            return FetchResult(url, "ok", status, raw=raw, text=text, waf=waf, elapsed=elapsed,
                               remark="response truncated at 5MB" if truncated else "")


# --------------------------------------------------------------------------- #
# Sitemaps (URLSource, network half)
# --------------------------------------------------------------------------- #

def looks_like_sitemap(u: str) -> bool:
    path = urlparse(u).path.lower()
    return bool(re.search(r"\.xml(\.gz)?$", path)) or path.endswith("robots.txt")


def _bare(netloc: str) -> str:
    h = netloc.lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def parse_sitemap(raw: bytes) -> tuple[str, list[str]]:
    """-> ('index' | 'urls', locs). Stdlib xml.etree only, hardened against entity bombs."""
    if raw[:2] == b"\x1f\x8b":                                      # .xml.gz
        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(100 * 1024 * 1024 + 1)
        if len(raw) > 100 * 1024 * 1024:
            raise ValueError("decompressed sitemap larger than 100MB")
    if re.search(rb"<!(DOCTYPE|ENTITY)", raw[:4096] + raw[-1024:], re.I):
        raise ValueError("sitemap contains DOCTYPE/ENTITY - refusing (XML entity-expansion risk)")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:                                           # plain-text sitemap
        urls = [l.strip() for l in raw.decode("utf-8", "ignore").splitlines() if re.match(r"^\s*https?://\S+\s*$", l)]
        if urls:
            return "urls", urls
        raise ValueError("not valid XML and not a plain-text URL list")
    kind = "index" if root.tag.split("}")[-1].lower() == "sitemapindex" else "urls"
    locs = [(e.text or "").strip() for e in root.iter() if e.tag.split("}")[-1].lower() == "loc" and e.text]
    return kind, locs


async def expand_sitemap(client: WAFSafeClient, url: str, allow_cross_host: bool, limit: int,
                         depth: int = 0, seen: set | None = None, root_host: str | None = None) -> list[str]:
    """Fetch a sitemap / sitemap index / robots.txt and return page URLs, recursing into child sitemaps."""
    from .url_source import norm_url
    seen = set() if seen is None else seen
    root_host = root_host or _bare(urlparse(url).netloc)
    if url in seen or depth > 3:
        return []
    seen.add(url)
    r = await client.fetch(url)
    if r.status != "ok":
        log.error("Could not read %s: %s %s", url, r.status, r.remark)
        return []
    if urlparse(url).path.lower().endswith("robots.txt"):
        out: list[str] = []
        for m in re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r.text):
            out += await expand_sitemap(client, m, allow_cross_host, limit, depth + 1, seen, root_host)
            if len(out) >= limit:
                break
        return out
    try:
        kind, locs = parse_sitemap(r.raw)
    except ValueError as e:
        log.error("Sitemap unparsable %s: %s", url, e)
        return []
    log.info("Sitemap %s -> %s with %d entries", url, kind, len(locs))
    urls: list[str] = []
    for loc in locs:
        n = norm_url(loc)
        if not n or (not allow_cross_host and _bare(urlparse(n).netloc) != root_host):
            continue
        if kind == "index":
            urls += await expand_sitemap(client, n, allow_cross_host, limit, depth + 1, seen, root_host)
        else:
            urls.append(n)
        if len(urls) >= limit:
            break
    return urls
