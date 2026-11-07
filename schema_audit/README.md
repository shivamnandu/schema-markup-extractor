# schema_audit

Async, rate-limited schema.org auditor: bulk-extracts JSON-LD / Microdata / RDFa from a URL
list, CSV, or sitemap; resolves every entity to its **main type**; classifies each as
`parsable` / `unparsable` with a specific reason; fetches politely, with a stricter,
defensive profile for banking/finance-type domains.

## Install & run

```powershell
pip install -r ../requirements.txt        # aiohttp, beautifulsoup4, lxml, throttler

python -m schema_audit --input urls.txt --output-dir out
python -m schema_audit --input urls.csv  --output-dir out          # needs a 'url' column
python -m schema_audit --input https://example.com/sitemap.xml --output-dir out

# Banking / finance site: strict profile, identify yourself, cap what you touch
python -m schema_audit --input https://www.examplebank.com/sitemap.xml ^
    --sensitive-domains examplebank.com --contact security-team@yourco.com ^
    --rps 0.3 --concurrency 1 --limit 200

python -m schema_audit --input urls.txt --dry-run                  # just resolve & count URLs
```

(`python schema_audit_run.py ...` from the project root is equivalent to `python -m schema_audit ...`.)

## Output (`--output-dir`, default `./schema_audit_output`)

| File | Contents |
|---|---|
| `schema_audit.csv` / `.json` | one row per schema.org entity: `url, schema_type, format, status, error_reason, raw_schema_snippet, http_status, crawl_timestamp` |
| `requests.log` | every request: URL, HTTP status, response time, schema blocks found |
| `errors.log` | WAF blocks, timeouts, and unrecoverable parse failures only |

One row per **main entity**: a JSON-LD document root, or a sibling inside its `@graph`
(`Organization` + `WebSite` + `BreadcrumbList` as `@graph` siblings produce three rows); for
Microdata/RDFa, a top-level `itemscope`/`typeof` element. Anything reached only by descending
into a *property* - `Question`/`Answer` inside `FAQPage`'s `mainEntity`, `Offer` inside
`Product`, `PostalAddress` inside an `Organization`'s `address`, `ListItem` inside a
`BreadcrumbList` - is detail describing the main entity, not a schema block of its own, and is
never reported as a separate row (an earlier revision of this tool did flatten those in, which
surfaced sub-types like `Answer` as if they were schema types a page implements - that was wrong
and is fixed).

## Main-type resolution

`schema_type` is **the most specific type the page itself declares** (e.g. `BreadcrumbList`
stays `BreadcrumbList` - it is never generalised to its parent `ItemList`). The bundled
`schema_types.json` (~1000 classes, scraped once from schema.org's own vocabulary, no
network call at runtime) is used only to check that a declared type is real, never to
rewrite it into an ancestor - see the docstring in `type_resolver.py` for why the brief's
"walk up the hierarchy" wording and its own worked example are mutually exclusive, and
which one this tool follows.

A node with several `@type`s (`["Product","Vehicle"]`) keeps both: `schema_type` becomes
`Product+Vehicle` and it counts as parsable only if every declared type is real.

## Parsable vs. unparsable (no auto-repair)

`parsable` requires **all** of: valid JSON, an `@context` naming schema.org, an `@type`,
and every declared type being a real schema.org class (Microdata/RDFa: `itemtype`/`typeof`
on the schema.org vocabulary, plus at least one property). Anything else is `unparsable`
with a specific `error_reason` (`JSONDecodeError: ...`, `Missing @context`, `Missing @type`,
`Unknown type: Foo (did you mean 'Foo'?)`, ...). There is **no silent trailing-comma /
CDATA repair** here (unlike `schema_extractor.py` in the project root) - a broken block is
reported broken, because a repair-then-pass would be a false positive: real consumers
(Google, schema.org's own validator) reject it too.

## WAF-safe fetching - what this is, and what it deliberately is not

**This is not a WAF-bypass or anti-bot-evasion tool**, on banking sites or anywhere else,
even though the underlying brief asked for one. Concretely, this build does **not** do:
TLS/JA3/HTTP2 fingerprint impersonation (`curl_cffi`, "impersonate=chrome120", etc.),
a rotating pool of browser User-Agents, forged `sec-ch-ua`/`sec-fetch-*` header sets, or
retrying a block with a different fingerprint. That family of technique exists specifically
to make automated traffic pass as a human browser past a bank's fraud/bot controls, which
is out of scope regardless of the stated purpose - if you need to audit a bank's site,
ask its owner to allowlist your IP/User-Agent (`--contact`, `--user-agent`).

What it does instead (`--waf-mode`, or `--sensitive-domains` to force it per host):
- one honest, identifiable `User-Agent` (default `SchemaAudit/1.0`, override with `--user-agent`)
- global rate limiting (`--rps`, enforced with the `throttler` library) and concurrency cap (`--concurrency`)
- an extra 2-5s-apart, one-at-a-time pace per sensitive host, on top of the global cap
- robots.txt obeyed, including `Crawl-delay`; unreachable/5xx robots.txt = that host isn't crawled
- `429`/`5xx` -> bounded retries honouring `Retry-After` / exponential backoff
- `403`/`406`/`451` or a body that looks like a bot-challenge page -> logged to `errors.log`,
  **never retried**; a per-host circuit breaker stops all further requests to that host after
  a couple of these (`errors.log` names the WAF vendor when detectable, e.g. Cloudflare/Akamai/Imperva)
- URLs with embedded credentials, and login/account/online-banking-shaped paths on sensitive
  hosts, are never fetched
- gzip-bombs and XML entity-expansion in sitemaps are rejected before parsing

## CLI flags

`--input` (file or sitemap URL) `--output-dir` `--rps` (default 2) `--concurrency` (default 5)
`--waf-mode` `--sensitive-domains` `--timeout` (default 15) `--user-agent` `--contact`
`--allow-cross-host` `--limit` `--dry-run` `-v/--verbose`

## Architecture

`url_source.py` (file/CSV input) · `extractor.py` (`SchemaExtractor`, BeautifulSoup) ·
`validator.py` (`SchemaValidator`) · `type_resolver.py` (`MainTypeResolver`) ·
`waf_client.py` (`WAFSafeClient` + `RateLimiter`, aiohttp + throttler) · `cli.py` (wiring, I/O).
