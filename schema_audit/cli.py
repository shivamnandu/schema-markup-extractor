"""
schema_audit CLI
=================
Ties URLSource -> WAFSafeClient -> SchemaExtractor -> SchemaValidator ->
OutputWriter together. See schema_audit/README.md for usage.
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from .extractor import extract_all
from .url_source import read_url_file
from .validator import validate_jsonld_block, validate_microdata_item, validate_rdfa_item
from .waf_client import WAFSafeClient, expand_sitemap, looks_like_sitemap

log = logging.getLogger("schema_audit")

FIELDS = ["url", "schema_type", "format", "status", "error_reason",
          "raw_schema_snippet", "http_status", "crawl_timestamp"]


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="schema_audit",
        description="Bulk schema.org audit: JSON-LD/Microdata/RDFa extraction, main-type "
                    "segregation, parsable/unparsable classification, WAF-safe fetching.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    p.add_argument("--input", required=True,
                   help="file path (.txt one URL/line, or .csv with a 'url' column), OR a sitemap "
                        "URL (.xml / sitemap index / .xml.gz / robots.txt)")
    p.add_argument("--output-dir", default="./schema_audit_output")
    p.add_argument("--rps", type=float, default=2.0, help="global requests-per-second cap (RateLimiter)")
    p.add_argument("--concurrency", type=int, default=5, help="global max simultaneous requests")
    p.add_argument("--waf-mode", action="store_true",
                   help="auto-apply the strict WAF-safe profile to bank/finance-looking hosts")
    p.add_argument("--sensitive-domains", default="",
                   help="comma-separated domains that always get the strict WAF-safe profile")
    p.add_argument("--timeout", type=float, default=15.0, help="per-request timeout, seconds")
    p.add_argument("--user-agent", default=None, help="override the default identifying User-Agent")
    p.add_argument("--contact", default=None, help="email/URL appended to the User-Agent")
    p.add_argument("--allow-cross-host", action="store_true", help="keep sitemap URLs found on other hosts")
    p.add_argument("--limit", type=int, default=0, help="max URLs to process (0 = no limit)")
    p.add_argument("--dry-run", action="store_true", help="resolve --input and print the URL count; fetch nothing")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def setup_logging(out: Path, verbose: bool) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")

    root = logging.getLogger("schema_audit")
    root.setLevel(logging.DEBUG if verbose else logging.INFO)
    sh = logging.StreamHandler()
    sh.setFormatter(fmt)
    root.addHandler(sh)
    fh = logging.FileHandler(out / "requests.log", encoding="utf-8")
    fh.setFormatter(fmt)
    root.addHandler(fh)

    err = logging.getLogger("schema_audit.errors")     # WAF blocks, timeouts, unrecoverable parse failures
    err.setLevel(logging.INFO)
    err.propagate = False
    efh = logging.FileHandler(out / "errors.log", encoding="utf-8")
    efh.setFormatter(fmt)
    err.addHandler(efh)


async def collect_urls(client: WAFSafeClient, args: argparse.Namespace) -> list[str]:
    inp = args.input
    path = Path(inp)
    if path.exists():
        return read_url_file(path)
    if re.match(r"^https?://", inp, re.I) and looks_like_sitemap(inp):
        return await expand_sitemap(client, inp, args.allow_cross_host, args.limit or 10 ** 9)
    if re.match(r"^https?://", inp, re.I):
        return [inp]
    raise SystemExit(f"--input '{inp}': not an existing file and not an http(s) URL")


def _fetch_fail_row(url: str, r, ts: str) -> dict:
    return {"url": url, "schema_type": "", "format": "", "status": "unparsable",
            "error_reason": f"fetch failed: {r.status} - {r.remark}".strip(" -"),
            "raw_schema_snippet": "", "http_status": r.http_status, "crawl_timestamp": ts}


async def process_one(client: WAFSafeClient, url: str) -> list[dict]:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    r = await client.fetch(url)
    if r.status != "ok":
        log.info("%-70s fetch=%-20s blocks=0", url, r.status)
        return [_fetch_fail_row(url, r, ts)]

    try:
        data = extract_all(r.text)
    except Exception as e:                      # a malformed page must never crash the batch
        log.error("%s: extractor error: %r", url, e)
        return [{"url": url, "schema_type": "", "format": "", "status": "unparsable",
                "error_reason": f"extractor error: {e!r}"[:300], "raw_schema_snippet": "",
                "http_status": r.http_status, "crawl_timestamp": ts}]

    rows: list[dict] = []
    for raw in data["jsonld"]:
        for row in validate_jsonld_block(raw):
            rows.append({"url": url, "format": "json-ld", "http_status": r.http_status, "crawl_timestamp": ts, **row})
    for item in data["microdata"]:
        rows.append({"url": url, "format": "microdata", "http_status": r.http_status, "crawl_timestamp": ts,
                    **validate_microdata_item(item)})
    for item in data["rdfa"]:
        rows.append({"url": url, "format": "rdfa", "http_status": r.http_status, "crawl_timestamp": ts,
                    **validate_rdfa_item(item)})
    if not rows:
        rows.append({"url": url, "schema_type": "", "format": "", "status": "unparsable",
                    "error_reason": "no schema found on page", "raw_schema_snippet": "",
                    "http_status": r.http_status, "crawl_timestamp": ts})

    n_bad = sum(1 for x in rows if x["status"] == "unparsable")
    log.info("%-70s HTTP %s  %5.2fs  blocks=%d (unparsable=%d)", url, r.http_status, r.elapsed, len(rows), n_bad)
    return rows


def write_outputs(out: Path, rows: list[dict]) -> None:
    with open(out / "schema_audit.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})
    with open(out / "schema_audit.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


async def run(args: argparse.Namespace) -> int:
    out = Path(args.output_dir)
    setup_logging(out, args.verbose)
    async with WAFSafeClient(args) as client:
        urls = list(dict.fromkeys(await collect_urls(client, args)))
        if args.limit:
            urls = urls[:args.limit]
        log.info("%d URLs to process", len(urls))
        if args.dry_run:
            print(f"{len(urls)} URLs resolved from --input (dry run - nothing fetched).")
            return 0
        if not urls:
            print("No URLs resolved from --input.", file=sys.stderr)
            return 1

        all_rows: list[dict] = []

        async def worker(u: str) -> None:
            all_rows.extend(await process_one(client, u))

        await asyncio.gather(*(worker(u) for u in urls))

    write_outputs(out, all_rows)
    type_counts: dict[str, int] = {}
    for r in all_rows:
        if r["status"] == "parsable":
            type_counts[r["schema_type"]] = type_counts.get(r["schema_type"], 0) + 1
    blocked = sorted({row["url"] for row in all_rows if "blocked_waf" in row.get("error_reason", "")
                      or "circuit_open" in row.get("error_reason", "")})

    print("\n=== Summary ===")
    print(f"URLs processed     : {len(urls)}")
    print(f"Schema blocks found: {len(all_rows)}  (parsable={sum(1 for r in all_rows if r['status']=='parsable')}, "
          f"unparsable={sum(1 for r in all_rows if r['status']=='unparsable')})")
    if type_counts:
        top = sorted(type_counts.items(), key=lambda kv: -kv[1])[:12]
        print("Top main types     : " + ", ".join(f"{t}={n}" for t, n in top))
    if blocked:
        print(f"WAF-blocked/stopped URLs: {len(blocked)} - see errors.log (not bypassed; ask the owner to allowlist you)")
    print(f"\nCSV : {(out / 'schema_audit.csv').resolve()}")
    print(f"JSON: {(out / 'schema_audit.json').resolve()}")
    print(f"Logs: {(out / 'requests.log').resolve()}  |  {(out / 'errors.log').resolve()}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
