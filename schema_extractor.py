from __future__ import annotations

import argparse
import csv
import gzip
import html
import io
import json
import logging
import random
import re
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from urllib import robotparser
from urllib.parse import urldefrag, urljoin, urlparse

import requests

VERSION = "1.0"
ROBOTS_TOKEN = "SchemaExtractor"
log = logging.getLogger("schema_extractor")

# --------------------------------------------------------------------------- #
# Policies (per-domain politeness)
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Policy:
    name: str
    delay: float          # min seconds between requests to one host
    jitter: float         # + random(0, jitter)
    concurrency: int      # simultaneous requests per host
    retries: int          # retries on 429 / 5xx / timeout
    max_strikes: int      # WAF blocks before circuit breaker opens
    obey_robots: bool
    skip_auth_paths: bool
    timeout: float


POLICIES = {
    "normal": Policy("normal", 0.5, 0.5, 2, 2, 5, True, False, 20),
    "safe": Policy("safe", 3.0, 2.0, 1, 2, 3, True, False, 30),
    "sensitive": Policy("sensitive", 8.0, 4.0, 1, 1, 2, True, True, 30),
}

# Heuristic only - pass --sensitive-domain / --sensitive-file for certainty.
SENSITIVE_HOST_RE = re.compile(
    r"(bank|banking|finance|financial|fintech|credit|loan|mortgage|insur|invest|"
    r"wealth|brokerage|trading|forex|payments?|paypal|swift|treasury|capital|"
    r"fcu|savings|pension|\.bank$|\.gov(\.|$)|\.mil$)",
    re.I,
)
AUTH_PATH_RE = re.compile(
    r"/(log-?in|sign-?in|sign-?on|logon|logout|auth|oauth|sso|account|accounts|my-?account|"
    r"online-?banking|net-?banking|internet-?banking|ebanking|e-banking|secure|portal|"
    r"dashboard|customer|otp|verify|password|reset|register|checkout|cart)(/|$|\.|\?)",
    re.I,
)

# --------------------------------------------------------------------------- #
# Fetching
# --------------------------------------------------------------------------- #

WAF_BODY_MARKERS = (
    "access denied", "request blocked", "request unsuccessful", "attention required",
    "just a moment", "checking your browser", "enable javascript and cookies",
    "captcha", "px-captcha", "pardon our interruption", "_incapsula_resource",
    "the requested url was rejected", "reference #", "unusual traffic",
    "you have been blocked", "datadome", "perimeterx", "bot detection",
    "web application firewall", "request id:", "support id",
)


def detect_waf(headers, body_lc: str = "") -> str:
    h = {k.lower(): str(v).lower() for k, v in headers.items()}
    server = h.get("server", "")
    cookies = h.get("set-cookie", "")
    if "cloudflare" in server or "cf-ray" in h or "cf-mitigated" in h:
        return "cloudflare"
    if "akamai" in server or any(k.startswith("x-akamai") for k in h) or "reference #" in body_lc:
        return "akamai"
    if "x-iinfo" in h or "incap_ses" in cookies or "_incapsula_" in body_lc or "visid_incap" in cookies:
        return "imperva/incapsula"
    if "x-sucuri-id" in h or "sucuri" in server:
        return "sucuri"
    if "x-amzn-waf-action" in h or "awswaf" in body_lc or "awselb" in server:
        return "aws-waf"
    if "bigip" in server or "the requested url was rejected" in body_lc:
        return "f5"
    if "px-captcha" in body_lc or "perimeterx" in body_lc:
        return "perimeterx"
    if "datadome" in body_lc or "datadome" in cookies:
        return "datadome"
    if "barracuda" in server:
        return "barracuda"
    return ""


def decode_bytes(raw: bytes, content_type: str = "") -> str:
    m = re.search(r"charset=([\w\-]+)", content_type or "", re.I)
    enc = m.group(1) if m else None
    if not enc:
        m = re.search(rb"<meta[^>]+charset=[\"']?([\w\-]+)", raw[:4096], re.I)
        enc = m.group(1).decode("ascii", "ignore") if m else "utf-8"
    try:
        return raw.decode(enc, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")


@dataclass
class RawResp:
    status: int = 0
    headers: dict = field(default_factory=dict)
    raw: bytes = b""
    truncated: bool = False
    error: str = ""          # "timeout" | "network_error" | ""
    error_msg: str = ""


@dataclass
class FetchResult:
    url: str
    status: str                      # see STATUS docs in README
    http_status: int = 0
    final_url: str = ""
    raw: bytes = b""
    content_type: str = ""
    waf: str = ""
    remark: str = ""
    redirect_to: str = ""
    truncated: bool = False

    @property
    def text(self) -> str:
        return decode_bytes(self.raw, self.content_type)


class DomainGate:
    """Per-host pacing, concurrency limit, robots cache and circuit breaker."""

    def __init__(self, host: str, policy: Policy):
        self.host, self.policy = host, policy
        self.sem = threading.BoundedSemaphore(policy.concurrency)
        self._m = threading.Lock()
        self._next = 0.0
        self.strikes = 0
        self.tripped = False
        self.robots = None            # None | "allow" | "deny" | RobotFileParser
        self.robots_lock = threading.Lock()
        self.crawl_delay = 0.0

    def wait_slot(self) -> None:
        with self._m:
            now = time.monotonic()
            t = max(now, self._next)
            gap = max(self.policy.delay, self.crawl_delay) + random.uniform(0, self.policy.jitter)
            self._next = t + gap
        if t > now:
            time.sleep(t - now)

    def penalize(self, seconds: float) -> None:
        with self._m:
            self._next = max(self._next, time.monotonic() + seconds)

    def strike(self) -> None:
        with self._m:
            self.strikes += 1
            if self.strikes >= self.policy.max_strikes and not self.tripped:
                self.tripped = True
                log.warning("Circuit breaker OPEN for %s after %d block responses", self.host, self.strikes)


class Fetcher:
    MAX_REDIRECTS = 5

    def __init__(self, args):
        self.args = args
        self.sensitive_hosts = {d.lower().lstrip(".") for d in (args.sensitive_domain or [])}
        if args.sensitive_file:
            for line in Path(args.sensitive_file).read_text(encoding="utf-8").splitlines():
                line = line.strip().lower()
                if line and not line.startswith("#"):
                    self.sensitive_hosts.add(line.lstrip("."))
        self._gates: dict[str, DomainGate] = {}
        self._gl = threading.Lock()
        self._local = threading.local()
        contact = f" (+{args.contact})" if args.contact else ""
        self.ua = args.user_agent or f"{ROBOTS_TOKEN}/{VERSION}{contact}"
        self.extra_headers = {}
        for h in args.header or []:
            k, _, v = h.partition(":")
            if k.strip() and v.strip():
                self.extra_headers[k.strip()] = v.strip()

    # ---- policy / gate -------------------------------------------------- #
    def is_sensitive(self, host: str) -> bool:
        host = host.split(":")[0].lower()
        if any(host == d or host.endswith("." + d) for d in self.sensitive_hosts):
            return True
        return bool(SENSITIVE_HOST_RE.search(host))

    def policy_for(self, host: str) -> Policy:
        if self.args.profile != "auto":
            p = POLICIES[self.args.profile]
        else:
            p = POLICIES["sensitive"] if self.is_sensitive(host) else POLICIES["safe"]
        if p.name == "normal" and self.args.ignore_robots:
            p = Policy(**{**p.__dict__, "obey_robots": False})
        if self.args.delay is not None and p.name != "sensitive":
            p = Policy(**{**p.__dict__, "delay": self.args.delay})
        elif self.args.delay is not None:
            p = Policy(**{**p.__dict__, "delay": max(self.args.delay, p.delay)})  # never faster than sensitive floor
        return p

    def gate(self, host: str) -> DomainGate:
        host = host.lower()
        with self._gl:
            g = self._gates.get(host)
            if g is None:
                g = self._gates[host] = DomainGate(host, self.policy_for(host))
            return g

    def session(self) -> requests.Session:
        s = getattr(self._local, "s", None)
        if s is None:
            s = requests.Session()
            s.headers.update({
                "User-Agent": self.ua,
                "Accept-Language": "en-US,en;q=0.8",
                **self.extra_headers,
            })
            self._local.s = s
        return s

    # ---- one low-level request ------------------------------------------ #
    def _http(self, gate: DomainGate, url: str, accept: str, cap: int) -> RawResp:
        out = RawResp()
        with gate.sem:
            if gate.tripped and not url.endswith("/robots.txt"):
                out.error = "circuit_open"       # breaker opened while this request was queued
                return out
            gate.wait_slot()
            if gate.tripped and not url.endswith("/robots.txt"):
                out.error = "circuit_open"
                return out
            try:
                r = self.session().get(
                    url, headers={"Accept": accept}, timeout=gate.policy.timeout,
                    allow_redirects=False, stream=True,
                )
                out.status, out.headers = r.status_code, dict(r.headers)
                buf = bytearray()
                for chunk in r.iter_content(65536):
                    buf += chunk
                    if len(buf) > cap:
                        del buf[cap:]
                        out.truncated = True
                        break
                r.close()
                out.raw = bytes(buf)
            except requests.Timeout as e:
                out.error, out.error_msg = "timeout", str(e)[:200]
            except requests.exceptions.SSLError as e:
                out.error, out.error_msg = "ssl_error", str(e)[:200]
            except (requests.RequestException, OSError) as e:
                out.error, out.error_msg = "network_error", str(e)[:200]
        return out

    # ---- robots.txt ------------------------------------------------------ #
    def _load_robots(self, gate: DomainGate, scheme: str):
        url = f"{scheme}://{gate.host}/robots.txt"
        r = self._http(gate, url, "text/plain,*/*", 512 * 1024)
        if r.error:
            log.info("robots.txt unreachable for %s (%s) -> treating as disallow", gate.host, r.error)
            return "deny"
        if r.status == 200:
            rp = robotparser.RobotFileParser()
            rp.parse(decode_bytes(r.raw, r.headers.get("Content-Type", "")).splitlines())
            cd = rp.crawl_delay(ROBOTS_TOKEN)
            if cd:
                gate.crawl_delay = min(float(cd), 60.0)
            return rp
        if r.status in (401, 403):
            # Could be a WAF; be conservative on sensitive hosts.
            gate.strike()
            return "deny" if gate.policy.name == "sensitive" else "allow"
        if r.status >= 500:
            return "deny"          # RFC 9309: server error => assume complete disallow
        return "allow"             # 404 etc. => no restrictions

    def _robots_ok(self, gate: DomainGate, url: str) -> bool:
        if not gate.policy.obey_robots:
            return True
        with gate.robots_lock:
            if gate.robots is None:
                gate.robots = self._load_robots(gate, urlparse(url).scheme)
        r = gate.robots
        if r == "allow":
            return True
        if r == "deny":
            return False
        return r.can_fetch(ROBOTS_TOKEN, url)

    # ---- public GET (follows redirects politely) ------------------------- #
    def get(self, url: str, want: str = "html", cap: int | None = None) -> FetchResult:
        cap = cap or (50 * 1024 * 1024 if want == "xml" else 5 * 1024 * 1024)
        current, hops = url, 0
        while True:
            res = self._get_once(current, want, cap)
            if res.redirect_to and hops < self.MAX_REDIRECTS:
                current, hops = res.redirect_to, hops + 1
                continue
            if res.redirect_to:
                res.status, res.remark = "http_error", f"too many redirects (>{self.MAX_REDIRECTS})"
            res.url, res.final_url = url, current
            return res

    def _get_once(self, url: str, want: str, cap: int) -> FetchResult:
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.netloc:
            return FetchResult(url, "invalid_url", remark="only http/https URLs are supported")
        if p.username or p.password:
            return FetchResult(url, "skipped_sensitive_path", remark="URL contains credentials; not fetched")
        gate = self.gate(p.netloc)
        if gate.policy.skip_auth_paths and AUTH_PATH_RE.search(p.path or "/") and want == "html":
            return FetchResult(url, "skipped_sensitive_path", remark="login/account-type path skipped on sensitive host")
        if gate.tripped:
            return FetchResult(url, "circuit_open", remark=f"host stopped after {gate.strikes} WAF/block responses")
        if not self._robots_ok(gate, url):
            return FetchResult(url, "robots_disallowed", remark="blocked by robots.txt (or robots.txt unavailable)")

        accept = ("text/html,application/xhtml+xml;q=0.9,*/*;q=0.5" if want == "html"
                  else "application/xml,text/xml,text/plain,application/gzip,*/*;q=0.5")
        attempt = 0
        while True:
            if gate.tripped:
                return FetchResult(url, "circuit_open", remark=f"host stopped after {gate.strikes} WAF/block responses")
            r = self._http(gate, url, accept, cap)
            ctype = r.headers.get("Content-Type", "")

            if r.error == "circuit_open":
                return FetchResult(url, "circuit_open", remark=f"host stopped after {gate.strikes} WAF/block responses")
            if r.error:
                retryable = r.error in ("timeout", "network_error")
                if retryable and attempt < gate.policy.retries:
                    gate.penalize(min(120, 5 * 2 ** attempt))
                    attempt += 1
                    continue
                return FetchResult(url, "timeout" if r.error == "timeout" else "network_error", remark=r.error_msg)

            st = r.status
            if st in (301, 302, 303, 307, 308) and r.headers.get("Location"):
                nxt = urljoin(url, r.headers["Location"])
                return FetchResult(url, "redirect", st, redirect_to=urldefrag(nxt)[0])

            body_lc = r.raw[:60000].decode("utf-8", "ignore").lower() if st >= 400 or len(r.raw) < 30000 else ""
            waf = detect_waf(r.headers, body_lc)

            if st in (429, 503) or (500 <= st < 600):
                if attempt < gate.policy.retries:
                    ra = r.headers.get("Retry-After", "")
                    wait = float(ra) if ra.isdigit() else 5 * 2 ** attempt
                    gate.penalize(min(120, max(wait, 5)))
                    attempt += 1
                    continue
                if st in (429, 503) and (waf or st == 429):
                    gate.strike()
                    return FetchResult(url, "blocked_waf", st, waf=waf, remark=f"HTTP {st} rate-limited/throttled after retries")
                return FetchResult(url, "http_error", st, waf=waf, remark=f"HTTP {st}")

            if st in (403, 406, 451):
                gate.strike()          # never retried, never bypassed
                return FetchResult(url, "blocked_waf", st, waf=waf, remark=f"HTTP {st} - request blocked" + (f" ({waf})" if waf else ""))
            if st == 401:
                return FetchResult(url, "auth_required", st, remark="HTTP 401 - authentication required")
            if not (200 <= st < 300):
                return FetchResult(url, "http_error", st, waf=waf, remark=f"HTTP {st}")

            # 2xx: challenge page served with 200?
            if want == "html" and len(r.raw) < 50000:
                low = r.raw.decode("utf-8", "ignore").lower()
                if any(m in low for m in WAF_BODY_MARKERS) and "ld+json" not in low and "itemscope" not in low:
                    gate.strike()
                    return FetchResult(url, "blocked_waf", st, waf=waf or detect_waf(r.headers, low),
                                       remark="HTTP 200 but body looks like a WAF/bot challenge page")
            if want == "html" and ctype and not re.search(r"html|xml", ctype, re.I):
                return FetchResult(url, "non_html", st, content_type=ctype, remark=f"content-type {ctype}")
            return FetchResult(url, "ok", st, raw=r.raw, content_type=ctype, waf=waf, truncated=r.truncated,
                               remark="response truncated at size cap" if r.truncated else "")


# --------------------------------------------------------------------------- #
# Schema extraction
# --------------------------------------------------------------------------- #

VOID = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param",
        "source", "track", "wbr"}
URL_ATTR = {"a": "href", "area": "href", "link": "href", "img": "src", "audio": "src", "video": "src",
            "source": "src", "embed": "src", "iframe": "src", "track": "src", "object": "data"}


class _Frame:
    __slots__ = ("tag", "item", "prop", "scope", "owner", "text", "has_value")

    def __init__(self, tag, scope, owner):
        self.tag, self.scope, self.owner = tag, scope, owner
        self.item = None
        self.prop = None
        self.text = []
        self.has_value = False


class SchemaParser(HTMLParser):
    """Collects <script type=ld+json> text plus Microdata / RDFa items in one pass."""

    def __init__(self, base_url: str):
        super().__init__(convert_charrefs=True)
        self.base = base_url
        self.ld: list[tuple[str, bool]] = []      # (raw text, closed properly)
        self._ld_buf: list[str] | None = None
        self.stack: list[_Frame] = []
        self.items: list[dict] = []               # top-level micro/RDFa items
        self._text_frames: list[_Frame] = []

    # ---- helpers --------------------------------------------------------- #
    @staticmethod
    def _add(item: dict, name: str, value) -> None:
        for n in name.split():
            item["props"].setdefault(n, []).append(value)

    def handle_starttag(self, tag, attrs):
        a = {k: (v or "") for k, v in attrs}
        if tag == "script":
            if "ld+json" in a.get("type", "").lower():
                self._ld_buf = []
            return
        parent = self.stack[-1] if self.stack else None
        scope = parent.scope if parent else None
        f = _Frame(tag, scope, scope)

        is_scope = "itemscope" in a or "typeof" in a
        prop = a.get("itemprop") or a.get("property")
        if prop and scope is None:
            prop = None                      # e.g. <meta property="og:title"> outside an item
        if is_scope:
            types = (a.get("itemtype") or a.get("typeof") or "").split()
            item = {"syntax": "microdata" if "itemscope" in a else "rdfa",
                    "types": types, "props": {}, "id": a.get("itemid") or a.get("resource") or ""}
            f.item, f.scope = item, item
            if prop:
                self._add(scope, prop, item)
            else:
                self.items.append(item)
        elif prop:
            f.prop = prop
            val = None
            if "content" in a:
                val = a["content"]
            elif tag in URL_ATTR and URL_ATTR[tag] in a:
                val = urljoin(self.base, a[URL_ATTR[tag]])
            elif "resource" in a:
                val = urljoin(self.base, a["resource"])
            elif tag == "time" and "datetime" in a:
                val = a["datetime"]
            elif tag in ("data", "meter") and "value" in a:
                val = a["value"]
            if val is not None:
                f.has_value = True
                self._add(scope, prop, val.strip())
            else:
                self._text_frames.append(f)
        if tag not in VOID:
            self.stack.append(f)

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag not in VOID and tag != "script":
            self.handle_endtag(tag)

    def handle_endtag(self, tag):
        if tag == "script":
            if self._ld_buf is not None:
                self.ld.append(("".join(self._ld_buf), True))
                self._ld_buf = None
            return
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i].tag == tag:
                for f in reversed(self.stack[i:]):
                    self._close(f)
                del self.stack[i:]
                return

    def _close(self, f: _Frame):
        if f in self._text_frames:
            self._text_frames.remove(f)
            if f.prop and not f.has_value and f.item is None:
                text = " ".join("".join(f.text).split())
                self._add(f.owner, f.prop, text)

    def handle_data(self, data):
        if self._ld_buf is not None:
            self._ld_buf.append(data)
        else:
            for f in self._text_frames:
                f.text.append(data)

    def finish(self):
        self.close()
        if self._ld_buf is not None:                      # unterminated <script>
            self.ld.append(("".join(self._ld_buf), False))
            self._ld_buf = None
        for f in reversed(self.stack):
            self._close(f)


def short_type(t: str) -> str:
    t = t.strip()
    t = re.sub(r"^https?://(www\.)?schema\.org/", "", t, flags=re.I)
    t = re.sub(r"^schema:", "", t, flags=re.I)
    return t


def type_vocab(t: str, ctx_ok: bool) -> str:
    m = re.match(r"^https?://([^/]+)/", t.strip(), re.I)
    if m:
        host = m.group(1).lower()
        return "schema.org" if host.endswith("schema.org") else host
    if t.lower().startswith("schema:"):
        return "schema.org"
    return "schema.org" if ctx_ok else "unknown"


def ctx_is_schema(ctx) -> bool:
    if isinstance(ctx, str):
        return "schema.org" in ctx.lower()
    if isinstance(ctx, list):
        return any(ctx_is_schema(c) for c in ctx)
    if isinstance(ctx, dict):
        return any(ctx_is_schema(v) for v in ctx.values())
    return False


def _jsonld_try(s: str):
    return json.loads(s, strict=False)


def parse_jsonld(raw: str):
    """-> (data, status, remark, error). status: parsable | parsable_repaired | unparsable"""
    text = raw.strip().lstrip("﻿")
    if not text:
        return None, "unparsable", "empty <script type=application/ld+json>", "empty block"
    try:
        return json.loads(text), "parsable", "", ""
    except json.JSONDecodeError as e:
        first_err = e
    steps = []
    s = text
    lead = r"^\s*(?:/\*\s*)?(?://\s*)?(?:<!--|<!\[CDATA\[)(?:\s*\*/)?"
    trail = r"(?:/\*\s*)?(?://\s*)?(?:-->|\]\]>)(?:\s*\*/)?\s*$"
    s2 = re.sub(trail, "", re.sub(lead, "", s))
    if s2 != s:
        s, steps = s2, steps + ["stripped CDATA/HTML-comment wrapper"]
    transforms = [
        ("allowed control characters in strings", lambda x: x),
        ("removed trailing commas", lambda x: re.sub(r",(\s*[}\]])", r"\1", x)),
        ("unescaped HTML entities", lambda x: html.unescape(x) if re.search(r"&(quot|#34|amp|#39);", x) else x),
    ]
    tried = list(steps)
    for label, fn in [("", lambda x: x)] + transforms:
        prev, s = s, fn(s)
        if label and s != prev:
            tried.append(label)
        try:
            data = _jsonld_try(s)
            return data, "parsable_repaired", "auto-repaired: " + "; ".join(tried or ["raw control characters in strings"]), ""
        except json.JSONDecodeError:
            continue
    e = first_err
    pos = max(0, e.pos - 40)
    snippet = text[pos:e.pos + 40].replace("\n", " ")
    return None, "unparsable", f"invalid JSON: {e.msg} (line {e.lineno}, col {e.colno})", \
        f"{e.msg} @ line {e.lineno} col {e.colno} | ...{snippet}..."


def _norm_types(node_type) -> list[str]:
    if isinstance(node_type, str):
        return [node_type]
    if isinstance(node_type, list):
        return [t for t in node_type if isinstance(t, str)]
    return []


def flatten_entities(node, ctx_ok: bool, top_level_only: bool, nested=False, parent_type=None, out=None):
    """Walk parsed JSON-LD (or converted micro/RDFa) and emit one record per typed entity."""
    out = [] if out is None else out
    if isinstance(node, list):
        for n in node:
            flatten_entities(n, ctx_ok, top_level_only, nested, parent_type, out)
        return out
    if not isinstance(node, dict):
        return out
    if "@context" in node:
        ctx_ok = ctx_is_schema(node["@context"]) or ctx_ok
    types = _norm_types(node.get("@type"))
    if "@graph" in node:
        flatten_entities(node["@graph"], ctx_ok, top_level_only, nested, parent_type, out)
    primary = None
    if types:
        primary = short_type(types[0])
        remarks = []
        for t in types:
            if short_type(t) and short_type(t)[0].islower() and not re.match(r"^https?://", t):
                remarks.append(f"type '{t}' is not PascalCase")
        vocab = type_vocab(types[0], ctx_ok)
        if vocab not in ("schema.org",):
            remarks.append(f"vocabulary: {vocab}")
        if not (top_level_only and nested):
            out.append({
                "type": primary,
                "types": [short_type(t) for t in types],
                "vocab": vocab,
                "nesting": "nested" if nested else "top",
                "parent_type": parent_type or "",
                "property_count": sum(1 for k in node if not k.startswith("@")),
                "remark": "; ".join(remarks),
                "data": node,
            })
    for k, v in node.items():
        if k in ("@context", "@graph") or (k.startswith("@") and k != "@reverse"):
            continue
        flatten_entities(v, ctx_ok, top_level_only, True, primary or parent_type, out)
    return out


def micro_to_jsonld(item: dict) -> dict:
    d: dict = {}
    if item["types"]:
        d["@type"] = item["types"] if len(item["types"]) > 1 else item["types"][0]
    if item["id"]:
        d["@id"] = item["id"]
    for k, vals in item["props"].items():
        conv = [micro_to_jsonld(v) if isinstance(v, dict) and "props" in v else v for v in vals]
        d[k] = conv[0] if len(conv) == 1 else conv
    return d


def extract_page(html_text: str, page_url: str, top_level_only: bool = False) -> dict:
    parser = SchemaParser(page_url)
    try:
        parser.feed(html_text)
        parser.finish()
    except Exception as e:  # malformed HTML must never kill the run
        log.debug("HTML parser error on %s: %s", page_url, e)
    blocks = []
    for i, (raw, closed) in enumerate(parser.ld):
        data, status, remark, error = parse_jsonld(raw)
        block = {"syntax": "json-ld", "index": i, "status": status, "remark": remark, "error": error,
                 "snippet": raw.strip()[:300] if status == "unparsable" else "", "entities": []}
        if not closed:
            block["remark"] = (block["remark"] + "; " if block["remark"] else "") + "script tag not closed"
        if data is not None:
            if not isinstance(data, (dict, list)):
                block.update(status="unparsable", remark="JSON-LD root is not an object/array",
                             error="root is " + type(data).__name__, snippet=raw.strip()[:300])
            else:
                roots = data if isinstance(data, list) else [data]
                has_ctx = any(isinstance(r, dict) and "@context" in r for r in roots)
                ctx_ok = any(isinstance(r, dict) and ctx_is_schema(r.get("@context")) for r in roots)
                block["entities"] = flatten_entities(data, ctx_ok, top_level_only)
                notes = []
                if not has_ctx:
                    notes.append("missing @context")
                if not block["entities"]:
                    notes.append("no typed (@type) entity found")
                if notes:
                    block["remark"] = "; ".join(filter(None, [block["remark"]] + notes))
        blocks.append(block)
    for i, item in enumerate(parser.items):
        ents = flatten_entities(micro_to_jsonld(item), item["syntax"] == "microdata" or
                                any("schema.org" in t for t in item["types"]), top_level_only)
        for e in ents:
            e["remark"] = "; ".join(filter(None, [e["remark"], "" if item["types"] else "item has no itemtype/typeof"]))
        blocks.append({"syntax": item["syntax"], "index": i, "status": "parsable",
                       "remark": "" if item["types"] else "scope without itemtype/typeof (untyped)",
                       "error": "", "snippet": "", "entities": ents})
    return {"blocks": blocks}


def schema_status(blocks: list[dict]) -> str:
    if not blocks:
        return "no_schema"
    bad = sum(1 for b in blocks if b["status"] == "unparsable")
    if bad == 0:
        return "parsable_repaired" if any(b["status"] == "parsable_repaired" for b in blocks) else "parsable"
    return "unparsable" if bad == len(blocks) else "partial"


# --------------------------------------------------------------------------- #
# URL collection (list + sitemaps)
# --------------------------------------------------------------------------- #

def norm_url(u: str) -> str | None:
    u = u.strip().split(",")[0].strip().strip("\"'")
    if not u or u.startswith("#"):
        return None
    if not re.match(r"^[a-z][a-z0-9+.\-]*://", u, re.I):
        u = "https://" + u
    u = urldefrag(u)[0]
    p = urlparse(u)
    return u if p.scheme in ("http", "https") and p.netloc else None


def parse_sitemap(raw: bytes) -> tuple[str, list[str]]:
    """-> (kind, locs). kind: 'index' | 'urls'. Raises ValueError on garbage."""
    if raw[:2] == b"\x1f\x8b":
        raw = gzip.GzipFile(fileobj=io.BytesIO(raw)).read(100 * 1024 * 1024 + 1)
        if len(raw) > 100 * 1024 * 1024:
            raise ValueError("decompressed sitemap larger than 100MB")
    if re.search(rb"<!(DOCTYPE|ENTITY)", raw[:4096] + raw[-1024:], re.I):
        raise ValueError("sitemap contains DOCTYPE/ENTITY (refusing: XML entity expansion risk)")
    try:
        root = ET.fromstring(raw)
    except ET.ParseError:
        lines = [l.strip() for l in raw.decode("utf-8", "ignore").splitlines()]
        urls = [l for l in lines if re.match(r"^https?://\S+$", l)]
        if urls:
            return "urls", urls
        raise ValueError("not valid XML and not a plain-text URL list")
    rtag = root.tag.split("}")[-1].lower()
    locs = [(e.text or "").strip() for e in root.iter() if e.tag.split("}")[-1].lower() == "loc" and e.text]
    return ("index" if rtag == "sitemapindex" else "urls"), locs


def bare_host(netloc: str) -> str:
    h = netloc.lower().split(":")[0]
    return h[4:] if h.startswith("www.") else h


def expand_sitemap(fetcher: Fetcher, url: str, allow_cross_host: bool, limit: int,
                   depth: int = 0, seen: set | None = None, root_host: str | None = None) -> list[str]:
    seen = set() if seen is None else seen
    root_host = root_host or bare_host(urlparse(url).netloc)
    if url in seen or depth > 3:
        return []
    seen.add(url)
    if urlparse(url).path.lower().endswith("robots.txt"):
        r = fetcher.get(url, want="xml", cap=512 * 1024)
        if r.status != "ok":
            log.error("Could not read %s: %s %s", url, r.status, r.remark)
            return []
        maps = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", r.text)
        out: list[str] = []
        for m in maps:
            out += expand_sitemap(fetcher, m, allow_cross_host, limit, depth + 1, seen, root_host)
            if len(out) >= limit:
                break
        return out
    r = fetcher.get(url, want="xml")
    if r.status != "ok":
        log.error("Sitemap fetch failed %s: %s %s", url, r.status, r.remark)
        return []
    try:
        kind, locs = parse_sitemap(r.raw)
    except ValueError as e:
        log.error("Sitemap unparsable %s: %s", url, e)
        return []
    log.info("Sitemap %s -> %s with %d entries", url, kind, len(locs))
    urls: list[str] = []
    for loc in locs:
        n = norm_url(loc)
        if not n:
            continue
        if not allow_cross_host and bare_host(urlparse(n).netloc) != root_host:
            continue
        if kind == "index":
            urls += expand_sitemap(fetcher, n, allow_cross_host, limit, depth + 1, seen, root_host)
        else:
            urls.append(n)
        if len(urls) >= limit:
            break
    return urls


def interleave(urls: list[str]) -> list[str]:
    buckets: dict[str, deque] = {}
    for u in urls:
        buckets.setdefault(urlparse(u).netloc.lower(), deque()).append(u)
    out = []
    while buckets:
        for h in list(buckets):
            out.append(buckets[h].popleft())
            if not buckets[h]:
                del buckets[h]
    return out


# --------------------------------------------------------------------------- #
# Processing + reporting
# --------------------------------------------------------------------------- #

RETRY_ON_RESUME = {"timeout", "network_error", "circuit_open"}


def process(fetcher: Fetcher, url: str) -> dict:
    host = urlparse(url).netloc
    rec = {"url": url, "final_url": url, "policy": fetcher.policy_for(host).name,
           "fetched_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
           "fetch_status": "", "http_status": 0, "waf": "", "fetch_remark": "",
           "schema_status": "not_checked", "counts": {}, "blocks": []}
    try:
        res = fetcher.get(url)
    except Exception as e:  # never let one URL kill the batch
        rec.update(fetch_status="network_error", fetch_remark=f"unexpected: {e!r}"[:300])
        return rec
    rec.update(fetch_status=res.status, http_status=res.http_status, waf=res.waf,
               fetch_remark=res.remark, final_url=res.final_url)
    if res.status != "ok":
        return rec
    try:
        page = extract_page(res.text, res.final_url, not fetcher.args.include_nested)
    except Exception as e:
        rec.update(schema_status="extraction_error", fetch_remark=f"extractor error: {e!r}"[:300])
        return rec
    rec["blocks"] = page["blocks"]
    rec["schema_status"] = schema_status(page["blocks"])
    rec["counts"] = dict(Counter(b["syntax"] for b in page["blocks"]))
    return rec


def load_journal(path: Path) -> dict[str, dict]:
    recs: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                r = json.loads(line)
                recs[r["url"]] = r          # last write wins
            except (json.JSONDecodeError, KeyError):
                continue
    return recs


def safe_name(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:80] or "untyped"


PARSE_FLAG = {"parsable": "PARSABLE", "parsable_repaired": "PARSABLE (REPAIRED)", "partial": "PARTIAL",
              "unparsable": "UNPARSABLE", "no_schema": "NO SCHEMA", "not_checked": "NOT CHECKED",
              "extraction_error": "UNPARSABLE"}


URL_HEADER = ["URL", "Final URL", "Policy", "Fetch Status", "HTTP", "WAF Detected", "Parse Flag",
              "JSON-LD Blocks", "Microdata Items", "RDFa Items", "Types Found", "Unparsable Blocks", "Remark"]
ITEM_HEADER = ["URL", "Syntax", "Block #", "Parse Status", "Type", "All Types", "Vocabulary",
               "Nesting", "Parent Type", "Properties", "Remark", "Data (JSON)"]
BAD_HEADER = ["URL", "Syntax", "Block #", "Error", "Snippet"]
TYPE_HEADER = ["Type", "Entities", "URLs", "Parsable", "Parsable (Repaired)"]
XL_CELL_MAX = 32000
XL_MAX_ROWS = 1_048_575


def build_tables(out: Path, recs: dict[str, dict]) -> dict:
    """Flatten journal records into report tables; also writes by_type/<Type>.jsonl."""
    (out / "by_type").mkdir(exist_ok=True)
    for old in (out / "by_type").glob("*.jsonl"):
        old.unlink()
    type_ents: Counter = Counter()
    type_urls: dict[str, set] = defaultdict(set)
    type_status: dict[str, Counter] = defaultdict(Counter)
    handles: dict[str, io.TextIOBase] = {}
    urls_rows, item_rows, bad_rows = [], [], []

    for url, r in recs.items():
        types = sorted({e["type"] for b in r["blocks"] for e in b["entities"]})
        bad = [b for b in r["blocks"] if b["status"] == "unparsable"]
        remarks = [r["fetch_remark"]] + sorted({b["remark"] for b in r["blocks"] if b["remark"]})
        c = r["counts"]
        urls_rows.append([url, r["final_url"], r["policy"], r["fetch_status"], r["http_status"] or "", r["waf"],
                          PARSE_FLAG.get(r["schema_status"], r["schema_status"]),
                          c.get("json-ld", 0), c.get("microdata", 0), c.get("rdfa", 0),
                          "; ".join(types), len(bad), " | ".join(x for x in remarks if x)[:1000]])
        for b in r["blocks"]:
            if b["status"] == "unparsable":
                bad_rows.append([url, b["syntax"], b["index"], b["error"], b["snippet"]])
            for e in b["entities"]:
                dj = json.dumps(e["data"], ensure_ascii=False, separators=(",", ":"))
                item_rows.append([url, b["syntax"], b["index"], PARSE_FLAG.get(b["status"], b["status"]),
                                  e["type"], "; ".join(e["types"]), e["vocab"], e["nesting"], e["parent_type"],
                                  e["property_count"], "; ".join(filter(None, [b["remark"], e["remark"]])),
                                  dj if len(dj) <= XL_CELL_MAX else dj[:XL_CELL_MAX] + "...[truncated - see by_type/]"])
                type_ents[e["type"]] += 1
                type_urls[e["type"]].add(url)
                type_status[e["type"]][b["status"]] += 1
                fh = handles.get(e["type"])
                if fh is None:
                    fh = handles[e["type"]] = open(out / "by_type" / f"{safe_name(e['type'])}.jsonl",
                                                   "a", encoding="utf-8")
                fh.write(json.dumps({"url": url, "syntax": b["syntax"], "parse_status": b["status"],
                                     "nesting": e["nesting"], "parent_type": e["parent_type"],
                                     "types": e["types"], "data": e["data"]}, ensure_ascii=False) + "\n")
    for fh in handles.values():
        fh.close()
    item_rows.sort(key=lambda x: (x[4], x[0]))            # segregate by type, then URL
    type_rows = [[t, n, len(type_urls[t]), type_status[t]["parsable"], type_status[t]["parsable_repaired"]]
                 for t, n in type_ents.most_common()]
    return {"urls": urls_rows, "items": item_rows, "bad": bad_rows, "types": type_rows, "type_counts": type_ents}


def write_csvs(out: Path, t: dict) -> None:
    for name, header, rows in (("urls", URL_HEADER, t["urls"]), ("schema_items", ITEM_HEADER, t["items"]),
                               ("unparsable", BAD_HEADER, t["bad"]), ("types_summary", TYPE_HEADER, t["types"])):
        with open(out / f"{name}.csv", "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(header)
            w.writerows(rows)


def write_excel(path: Path, t: dict, recs: dict[str, dict], per_type_sheets: int = 25) -> Path:
    from openpyxl import Workbook
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    from openpyxl.styles import Alignment, Font, PatternFill

    fills = {k: PatternFill("solid", fgColor=v) for k, v in {
        "PARSABLE": "C6EFCE", "PARSABLE (REPAIRED)": "FFEB9C", "PARTIAL": "FFD8A8",
        "UNPARSABLE": "FFC7CE", "NO SCHEMA": "E7E6E6", "NOT CHECKED": "E7E6E6"}.items()}
    head_fill, head_font = PatternFill("solid", fgColor="1F3864"), Font(bold=True, color="FFFFFF")

    def clean(v):
        return ILLEGAL_CHARACTERS_RE.sub("", v)[:XL_CELL_MAX + 100] if isinstance(v, str) else v

    def sheet(wb, title, header, rows, widths, flag_col=None):
        ws = wb.create_sheet(title[:31])
        ws.append(header)
        for c in ws[1]:
            c.fill, c.font, c.alignment = head_fill, head_font, Alignment(vertical="center")
        for row in rows[:XL_MAX_ROWS]:
            row = [clean(v) for v in row]
            ws.append(row)
            if any(isinstance(v, str) and v[:1] == "=" for v in row):   # never let web data become a formula
                for c in ws[ws.max_row]:
                    if c.data_type == "f":
                        c.data_type = "s"
            if flag_col is not None and row[flag_col] in fills:
                ws.cell(row=ws.max_row, column=flag_col + 1).fill = fills[row[flag_col]]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w
        ws.freeze_panes = "A2"
        ws.auto_filter.ref = ws.dimensions
        return ws

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    fs = Counter(r["fetch_status"] for r in recs.values())
    pf = Counter(PARSE_FLAG.get(r["schema_status"], r["schema_status"])
                 for r in recs.values() if r["fetch_status"] == "ok")
    ws.append(["Schema Tag Extractor report"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    ws.append(["URLs processed", len(recs)])
    ws.append(["Schema entities found", len(t["items"])])
    ws.append(["Distinct types", len(t["types"])])
    ws.append(["Unparsable blocks", len(t["bad"])])
    for title, counter in (("Fetch status", fs), ("Parse flag (fetched pages)", pf)):
        ws.append([])
        ws.append([title, "Count"])
        for c in ws[ws.max_row]:
            c.font = Font(bold=True)
        for k, v in counter.most_common():
            ws.append([k, v])
            if k in fills:
                ws.cell(row=ws.max_row, column=1).fill = fills[k]
    blocked = sorted({urlparse(r["url"]).netloc for r in recs.values() if r["fetch_status"] in ("blocked_waf", "circuit_open")})
    if blocked:
        ws.append([])
        ws.append(["WAF-blocked / stopped hosts (not bypassed - ask owner to allowlist, then re-run)"])
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True, color="C00000")
        for h in blocked:
            ws.append([h])
    ws.column_dimensions["A"].width = 46
    ws.column_dimensions["B"].width = 22

    sheet(wb, "URLs", URL_HEADER, t["urls"], [55, 40, 10, 20, 7, 14, 20, 9, 9, 9, 40, 10, 70], flag_col=6)
    sheet(wb, "Schema Items", ITEM_HEADER, t["items"], [50, 10, 8, 20, 22, 26, 14, 9, 18, 10, 40, 80], flag_col=3)
    sheet(wb, "Unparsable", BAD_HEADER, t["bad"], [55, 10, 8, 50, 90])
    sheet(wb, "Types Summary", TYPE_HEADER, t["types"], [28, 10, 8, 10, 18])

    by_type: dict[str, list] = defaultdict(list)
    for row in t["items"]:
        by_type[row[4]].append(row)
    used = {"summary", "urls", "schema items", "unparsable", "types summary"}
    for typ, _ in t["type_counts"].most_common(per_type_sheets):
        base = "T_" + re.sub(r"[\[\]:*?/\\]", "", typ)[:27]
        name, n = base, 2
        while name.lower() in used:
            name = f"{base[:28]}_{n}"
            n += 1
        used.add(name.lower())
        sheet(wb, name, ITEM_HEADER, by_type[typ], [50, 10, 8, 20, 22, 26, 14, 9, 18, 10, 40, 80], flag_col=3)
    wb.save(path)
    return path


def write_reports(out: Path, recs: dict[str, dict], write_csv: bool = False) -> dict:
    tables = build_tables(out, recs)
    if write_csv:
        write_csvs(out, tables)
    xlsx = write_excel(out / f"schema_report_{datetime.now():%Y%m%d_%H%M%S}.xlsx", tables, recs)
    return {"types": tables["type_counts"], "xlsx": xlsx}


def print_summary(recs: dict[str, dict], stats: dict) -> None:
    fs = Counter(r["fetch_status"] for r in recs.values())
    ss = Counter(r["schema_status"] for r in recs.values() if r["fetch_status"] == "ok")
    print("\n=== Summary ===")
    print(f"URLs processed : {len(recs)}")
    print("Fetch status   : " + ", ".join(f"{k}={v}" for k, v in fs.most_common()))
    print("Schema status  : " + (", ".join(f"{k}={v}" for k, v in ss.most_common()) or "-"))
    if stats["types"]:
        print("Top types      : " + ", ".join(f"{t}={n}" for t, n in stats["types"].most_common(12)))
    blocked = [r for r in recs.values() if r["fetch_status"] in ("blocked_waf", "circuit_open")]
    if blocked:
        hosts = sorted({urlparse(r["url"]).netloc for r in blocked})
        print(f"WAF-blocked/stopped hosts ({len(hosts)}): {', '.join(hosts[:10])}")
        print("  -> not bypassed. Ask the site owner to allowlist your IP/User-Agent, then --resume.")


# --------------------------------------------------------------------------- #
# Interactive input (dialog box; console fallback)
# --------------------------------------------------------------------------- #

def is_sitemap_url(u: str) -> bool:
    path = urlparse(u).path.lower()
    return bool(re.search(r"\.xml(\.gz)?$", path)) or path.endswith("robots.txt")


def prompt_console(default_out: Path) -> dict | None:
    print("Schema Tag Extractor - no dialog available, using console.")
    kind = input("Input type: [1] Sitemap URL  [2] URL list file  (1/2): ").strip()
    if kind == "2":
        p = input("Path to URL list file: ").strip().strip('"')
        entries = Path(p).read_text(encoding="utf-8-sig").splitlines() if p else []
    else:
        entries = [input("Sitemap URL: ").strip()]
    if not any(e.strip() for e in entries):
        return None
    sens = input("Banking/sensitive site - force strict WAF-safe mode? (y/N): ").strip().lower() == "y"
    limit = input("Max URLs (blank = all): ").strip()
    contact = input("Contact email/URL for User-Agent (blank = none): ").strip()
    return {"entries": entries, "sensitive": sens, "limit": int(limit) if limit.isdigit() else 0,
            "contact": contact, "out": str(default_out)}


def prompt_inputs(default_out: Path) -> dict | None:
    """Pop up a dialog asking for a sitemap or a URL list. Returns None if cancelled."""
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
        root = tk.Tk()
    except Exception:                       # no tkinter / no display
        return prompt_console(default_out)

    root.title("Schema Tag Extractor")
    root.resizable(False, False)
    pad = {"padx": 10, "pady": 4}
    mode = tk.StringVar(value="sitemap")
    sens = tk.BooleanVar(value=False)
    limit, contact, outdir = tk.StringVar(), tk.StringVar(), tk.StringVar(value=str(default_out))
    sm_var = tk.StringVar()
    result: dict = {}

    ttk.Label(root, text="What do you want to scan?", font=("Segoe UI", 11, "bold")).grid(
        row=0, column=0, columnspan=2, sticky="w", **pad)
    rb = ttk.Frame(root)
    rb.grid(row=1, column=0, columnspan=2, sticky="w", padx=10)
    ttk.Radiobutton(rb, text="Sitemap", variable=mode, value="sitemap", command=lambda: refresh()).pack(side="left", padx=(0, 20))
    ttk.Radiobutton(rb, text="URL list", variable=mode, value="list", command=lambda: refresh()).pack(side="left")

    sm_frame = ttk.Frame(root)
    ttk.Label(sm_frame, text="Sitemap URL  (sitemap.xml, sitemap index, .xml.gz or robots.txt)").pack(anchor="w")
    sm_entry = ttk.Entry(sm_frame, textvariable=sm_var, width=80)
    sm_entry.pack(fill="x", pady=2)

    list_frame = ttk.Frame(root)
    ttk.Label(list_frame, text="Paste URLs, one per line (sitemap links are detected automatically)").pack(anchor="w")
    text = tk.Text(list_frame, width=80, height=10)
    text.pack(fill="x", pady=2)

    def load_file():
        p = filedialog.askopenfilename(title="Open URL list", filetypes=[("Text / CSV", "*.txt *.csv"), ("All files", "*.*")])
        if p:
            text.delete("1.0", "end")
            text.insert("1.0", Path(p).read_text(encoding="utf-8-sig", errors="replace"))

    ttk.Button(list_frame, text="Load from file (.txt / .csv)...", command=load_file).pack(anchor="w")

    def refresh():
        sm_frame.grid_remove()
        list_frame.grid_remove()
        (sm_frame if mode.get() == "sitemap" else list_frame).grid(row=2, column=0, columnspan=2, sticky="ew", **pad)

    ttk.Checkbutton(root, variable=sens, text="Banking / sensitive site - force strict WAF-safe mode\n"
                    "(auto-enabled for bank/finance-looking domains; 1 request per ~10s, skips login pages)"
                    ).grid(row=3, column=0, columnspan=2, sticky="w", **pad)
    opts = ttk.Frame(root)
    opts.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10)
    ttk.Label(opts, text="Max URLs (blank = all):").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Entry(opts, textvariable=limit, width=10).grid(row=0, column=1, sticky="w", padx=6)
    ttk.Label(opts, text="Contact email/URL (optional, shown to site owner in User-Agent):").grid(row=1, column=0, sticky="w", pady=3)
    ttk.Entry(opts, textvariable=contact, width=32).grid(row=1, column=1, sticky="w", padx=6)
    ttk.Label(opts, text="Save Excel report in:").grid(row=2, column=0, sticky="w", pady=3)
    of = ttk.Frame(opts)
    of.grid(row=2, column=1, sticky="w", padx=6)
    ttk.Entry(of, textvariable=outdir, width=32).pack(side="left")
    ttk.Button(of, text="Browse...", command=lambda: outdir.set(filedialog.askdirectory(initialdir=outdir.get()) or outdir.get())).pack(side="left", padx=4)

    def start():
        entries = [sm_var.get()] if mode.get() == "sitemap" else text.get("1.0", "end").splitlines()
        entries = [e.strip() for e in entries if e.strip() and not e.strip().startswith("#")]
        if not entries:
            messagebox.showwarning("Schema Tag Extractor", "Please enter a sitemap URL or at least one URL.")
            return
        if limit.get().strip() and not limit.get().strip().isdigit():
            messagebox.showwarning("Schema Tag Extractor", "Max URLs must be a number (or blank).")
            return
        result.update(entries=entries, sensitive=sens.get(), limit=int(limit.get() or 0),
                      contact=contact.get().strip(), out=outdir.get().strip() or str(default_out))
        root.destroy()

    bf = ttk.Frame(root)
    bf.grid(row=5, column=0, columnspan=2, sticky="e", padx=10, pady=10)
    ttk.Button(bf, text="Start", command=start).pack(side="left", padx=4)
    ttk.Button(bf, text="Cancel", command=root.destroy).pack(side="left")
    root.bind("<Return>", lambda e: start() if mode.get() == "sitemap" else None)
    refresh()
    root.attributes("-topmost", True)
    root.after(300, lambda: root.attributes("-topmost", False))
    sm_entry.focus_set()
    root.mainloop()
    return result or None


def apply_selection(args, sel: dict) -> None:
    for e in sel["entries"]:
        n = norm_url(e)
        if n:
            (args.sitemap if is_sitemap_url(n) else args.url).append(n)
    if sel["sensitive"]:
        args.profile = "sensitive"
    args.limit = sel["limit"] or args.limit
    args.contact = sel["contact"] or args.contact
    args.out = sel["out"]


def show_done(xlsx: Path | None, recs: dict) -> None:
    try:
        import os
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        msg = f"Finished: {len(recs)} URLs processed."
        if xlsx:
            msg += f"\n\nExcel report:\n{xlsx}\n\nOpen it now?"
            if messagebox.askyesno("Schema Tag Extractor", msg, parent=root):
                os.startfile(xlsx)          # Windows
        else:
            messagebox.showinfo("Schema Tag Extractor", msg, parent=root)
        root.destroy()
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Extract & classify JSON-LD / Microdata / RDFa from URL lists or sitemaps (WAF-friendly).",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    src = p.add_argument_group("input")
    src.add_argument("--urls", metavar="FILE", help="text/CSV file, one URL per line (first column used)")
    src.add_argument("--url", action="append", default=[], help="single URL (repeatable)")
    src.add_argument("--sitemap", action="append", default=[],
                     help="sitemap.xml / sitemap index / .xml.gz / robots.txt URL (repeatable)")
    src.add_argument("--allow-cross-host", action="store_true", help="keep sitemap URLs on other hosts")
    src.add_argument("--include", help="regex: only keep URLs matching")
    src.add_argument("--exclude", help="regex: drop URLs matching")
    src.add_argument("--limit", type=int, default=0, help="max total URLs (0 = no limit)")
    src.add_argument("--max-per-domain", type=int, default=0, help="max URLs per host (0 = no limit)")
    out = p.add_argument_group("output")
    out.add_argument("--out", default="output", help="output directory")
    out.add_argument("--resume", action="store_true", help="skip URLs already in journal.jsonl")
    out.add_argument("--include-nested", action="store_true",
                     help="also list entities reached only via a property (Offer inside Product, "
                          "Answer inside FAQPage's Question, ...) as their own rows. Off by default: "
                          "those are detail on the main entity, not a main schema type in their own right.")
    out.add_argument("--dry-run", action="store_true", help="list URLs and the policy each host gets; fetch nothing")
    out.add_argument("--csv", action="store_true", help="also write CSV copies next to the Excel report")
    out.add_argument("--no-gui", action="store_true", help="never show the input dialog (fail if no input given)")
    pol = p.add_argument_group("politeness / WAF safety")
    pol.add_argument("--profile", choices=["auto", "normal", "safe", "sensitive"], default="auto",
                     help="auto = 'sensitive' for banking/finance-like hosts, else 'safe'")
    pol.add_argument("--sensitive-domain", action="append", default=[], help="force sensitive profile (repeatable)")
    pol.add_argument("--sensitive-file", help="file with one sensitive domain per line")
    pol.add_argument("--delay", type=float, help="min seconds between requests per host (sensitive keeps its floor)")
    pol.add_argument("--workers", type=int, default=8, help="total threads (per-host limits still apply)")
    pol.add_argument("--ignore-robots", action="store_true", help="only honoured with --profile normal, own sites only")
    pol.add_argument("--user-agent", help="override UA (default identifies this tool)")
    pol.add_argument("--contact", help="URL/email appended to the UA so site owners can reach you")
    pol.add_argument("--header", action="append", default=[],
                     help='extra header, e.g. "X-Scan-Token: abc" supplied by the site owner (repeatable)')
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    gui_used = False
    if not (args.urls or args.url or args.sitemap):
        if args.no_gui:
            print("Provide --urls, --url or --sitemap. See --help.", file=sys.stderr)
            return 2
        sel = prompt_inputs(Path(__file__).resolve().parent / "output")
        if not sel:
            print("Cancelled - nothing to do.")
            return 1
        apply_selection(args, sel)
        gui_used = True
        if not (args.url or args.sitemap):
            print("No valid http(s) URLs were entered.", file=sys.stderr)
            return 2
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    fetcher = Fetcher(args)

    # ---- collect URLs ---------------------------------------------------- #
    urls: list[str] = []
    if args.urls:
        for line in Path(args.urls).read_text(encoding="utf-8-sig").splitlines():
            n = norm_url(line)
            if n:
                urls.append(n)
    urls += [n for n in map(norm_url, args.url) if n]
    for sm in args.sitemap:
        n = norm_url(sm)
        if n:
            urls += expand_sitemap(fetcher, n, args.allow_cross_host, args.limit or 10**9)
    if args.include:
        urls = [u for u in urls if re.search(args.include, u)]
    if args.exclude:
        urls = [u for u in urls if not re.search(args.exclude, u)]
    urls = list(dict.fromkeys(urls))
    if args.max_per_domain:
        cnt: Counter = Counter()
        kept = []
        for u in urls:
            h = urlparse(u).netloc.lower()
            if cnt[h] < args.max_per_domain:
                cnt[h] += 1
                kept.append(u)
        urls = kept
    if args.limit:
        urls = urls[:args.limit]
    (out / "urls_discovered.txt").write_text("\n".join(urls), encoding="utf-8")
    log.info("%d URLs to process", len(urls))

    if args.dry_run:
        for h in sorted({urlparse(u).netloc.lower() for u in urls}):
            p = fetcher.policy_for(h)
            print(f"{h:45s} policy={p.name:9s} delay={p.delay}s+{p.jitter}s conc={p.concurrency} "
                  f"retries={p.retries} strikes={p.max_strikes}")
        return 0

    # ---- run ------------------------------------------------------------- #
    journal_path = out / "journal.jsonl"
    prior = load_journal(journal_path) if args.resume else {}
    if not args.resume and journal_path.exists():
        journal_path.rename(out / f"journal.{datetime.now():%Y%m%d-%H%M%S}.bak.jsonl")
    todo = [u for u in urls if not (u in prior and prior[u]["fetch_status"] not in RETRY_ON_RESUME)]
    log.info("%d already done, %d to fetch", len(urls) - len(todo), len(todo))
    todo = interleave(todo)

    jl, done = threading.Lock(), [0]
    jf = open(journal_path, "a", encoding="utf-8")

    def work(u: str):
        rec = process(fetcher, u)
        with jl:
            jf.write(json.dumps(rec, ensure_ascii=False) + "\n")
            jf.flush()
            done[0] += 1
            log.info("[%d/%d] %-18s %-18s %s", done[0], len(todo), rec["fetch_status"],
                     PARSE_FLAG.get(rec["schema_status"], rec["schema_status"]), u)

    ex = ThreadPoolExecutor(max_workers=max(1, args.workers))
    try:
        for f in [ex.submit(work, u) for u in todo]:
            f.result()
    except KeyboardInterrupt:
        log.warning("Interrupted - progress saved. Re-run with --resume to continue.")
        ex.shutdown(wait=False, cancel_futures=True)
    else:
        ex.shutdown()
    finally:
        jf.close()

    recs = {u: r for u, r in load_journal(journal_path).items() if u in set(urls)}
    if args.resume:
        for u, r in prior.items():
            recs.setdefault(u, r)
    recs = {u: recs[u] for u in urls if u in recs}
    stats = write_reports(out, recs, write_csv=args.csv)
    print_summary(recs, stats)
    print(f"\nExcel report: {stats['xlsx'].resolve()}")
    if gui_used:
        show_done(stats["xlsx"].resolve(), recs)
    return 0


if __name__ == "__main__":
    sys.exit(main())
