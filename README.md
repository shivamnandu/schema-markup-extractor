# Schema Tag Extractor

Bulk schema.org structured-data auditing from a URL list or a sitemap: extracts JSON-LD /
Microdata / RDFa, segregates entities by main type, flags each block parsable/unparsable
with a reason, and fetches politely (defensive WAF-safe mode for banking/finance domains -
never fingerprint spoofing; see below).

Install everything with `pip install -r requirements.txt`. Three ways to run it:

| | `schema_tool.py` (recommended) | `schema_audit/` | `schema_extractor.py` |
|---|---|---|---|
| Run it | `python schema_tool.py` (dialog) or with flags | `python -m schema_audit --input ...` | `python schema_extractor.py` (dialog) |
| Output | CSV + JSON (exact per-entity schema) **and** Excel | CSV + JSON only | Excel only |
| Fetching | `asyncio` + `aiohttp`, strict global RPS cap | same engine | synchronous, threaded |
| Resume | yes (`--resume`, `journal.jsonl`) | no | yes |
| What it is | **the merged tool** - dialog/Excel layered on the `schema_audit` engine | the extraction/validation/fetch engine, CLI-only | the original standalone GUI/Excel tool, kept as-is |

Unless you specifically want the async engine without its GUI/Excel layer (`schema_audit/`)
or the original threaded tool (`schema_extractor.py`), use **`schema_tool.py`** - it does
everything the other two do, from one command.

Both tools extract JSON-LD, Microdata and RDFa; segregate entities by schema.org type; flag
each block parsable/unparsable with a reason; and use a **defensive, non-evasive** fetch
policy on banking/finance-type domains (honest User-Agent, robots.txt, backoff, a circuit
breaker that stops hitting a host after it blocks you - never TLS/browser fingerprint
spoofing). See `schema_audit/README.md` for why that line is drawn where it is.

## `schema_tool.py` (merged - recommended)

```powershell
python schema_tool.py                                              # dialog: sitemap/URL list, sensitive-site tick-box
python schema_tool.py --input https://example.com/sitemap.xml --output-dir out
python schema_tool.py --input urls.csv --output-dir out --no-excel # skip the .xlsx, CSV/JSON only
python schema_tool.py --input urls.txt --dry-run                   # just resolve & count URLs
python schema_tool.py --input urls.txt --resume                    # continue an interrupted/blocked run

# Banking / finance site
python schema_tool.py --input https://www.examplebank.com/sitemap.xml ^
    --sensitive-domains examplebank.com --contact security-team@yourco.com --rps 0.3 --concurrency 1
```

Output, every run: `schema_audit.csv` / `.json` (exact per-entity schema, **main schema types
only** - see [schema_audit/README.md](schema_audit/README.md) for the column list and exactly
what counts as a main type vs. a sub-type like `Answer` or `Offer`) **and**
`schema_report_<timestamp>.xlsx` with:

- `Summary`, `Items`, `Unparsable`, `Types Summary`, one sheet per type
- `URLs` - one row per URL, fetch status and parse flag
- **`URL x Type`** - the pivot you'll usually want: URLs down the rows, every main schema type
  found anywhere in the audit across the columns - each type gets two columns, its extracted
  data (the raw snippet) and its status (parsable/unparsable/partial, colour-coded); blank = that
  type isn't on that page

plus `requests.log`, `errors.log`, `journal.jsonl` (resume state). All flags: `python schema_tool.py --help`.

## `schema_extractor.py` (original standalone tool)

```powershell
python schema_extractor.py                       # dialog: sitemap or URL list, sensitive-site tick-box
python schema_extractor.py --sitemap https://example.com/sitemap.xml --out output
python schema_extractor.py --urls urls.txt --out output --csv     # also write CSV copies
python schema_extractor.py --urls urls.txt --dry-run              # show the policy each host gets
python schema_extractor.py --urls urls.txt --resume               # continue an interrupted run
```

Output: `schema_report_<timestamp>.xlsx` with `Summary` / `URLs` / `Schema Items` /
`Unparsable` / `Types Summary` / one sheet per type, plus `by_type/<Type>.jsonl` (untruncated
JSON) and `journal.jsonl` (resume state).

## `schema_audit` package

```powershell
python -m schema_audit --input https://example.com/sitemap.xml --output-dir out
python -m schema_audit --input urls.csv --sensitive-domains examplebank.com --output-dir out
```

Output: `schema_audit.csv` / `.json` with exactly `url, schema_type, format, status,
error_reason, raw_schema_snippet, http_status, crawl_timestamp`; `requests.log` and a
separate `errors.log`. Full docs, flags and design notes: [schema_audit/README.md](schema_audit/README.md).
