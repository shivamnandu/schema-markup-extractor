#!/usr/bin/env python3
"""
schema_tool.py - Schema Tag Extractor, merged
===============================================
One tool combining:
  * schema_extractor.py's input DIALOG and EXCEL report (ad-hoc / interactive use)
  * schema_audit's async, rate-limited, WAF-safe engine and exact per-entity
    CSV/JSON schema (scripted / repeated / large-sitemap use)

Run with no arguments for the input dialog. Every run writes, into --output-dir:
    schema_audit.csv / schema_audit.json   exact per-entity schema (see FIELDS below)
    schema_report_<timestamp>.xlsx         Summary / URLs / Items / Unparsable /
                                            Types Summary / one sheet per type
    requests.log                           every request: URL, HTTP status, time, block count
    errors.log                             WAF blocks, timeouts, unrecoverable parse failures
    journal.jsonl                          per-URL results, source of truth for --resume

This file is the orchestration + GUI + Excel layer. The extraction, main-type
resolution, validation and WAF-safe fetching are all done by the `schema_audit`
package next to this file - see schema_audit/README.md for those design notes
(in particular: why fetching here is deliberately defensive, not evasive, and
why main-type resolution does not "walk up" the schema.org hierarchy).
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import json
import logging
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from schema_audit.extractor import extract_all
from schema_audit.url_source import norm_url, read_url_file
from schema_audit.validator import validate_jsonld_block, validate_microdata_item, validate_rdfa_item
from schema_audit.waf_client import WAFSafeClient, expand_sitemap, looks_like_sitemap

log = logging.getLogger("schema_tool")

FIELDS = ["url", "schema_type", "format", "status", "error_reason",
          "raw_schema_snippet", "http_status", "crawl_timestamp"]
RETRY_ON_RESUME = {"timeout", "network_error", "circuit_open"}
STATUS_FILL = {"parsable": "PARSABLE", "unparsable": "UNPARSABLE"}


# --------------------------------------------------------------------------- #
# Fetch + extract + validate one URL
# --------------------------------------------------------------------------- #

async def process_one(client: WAFSafeClient, url: str) -> tuple[dict, list[dict]]:
    ts = datetime.now(timezone.utc).isoformat(timespec="seconds")
    r = await client.fetch(url)
    meta = {"fetch_status": r.status, "http_status": r.http_status, "waf": r.waf,
            "remark": r.remark, "elapsed": r.elapsed}
    if r.status != "ok":
        log.info("%-70s fetch=%s", url, r.status)
        return meta, [{"url": url, "schema_type": "", "format": "", "status": "unparsable",
                       "error_reason": f"fetch failed: {r.status} - {r.remark}".strip(" -"),
                       "raw_schema_snippet": "", "http_status": r.http_status, "crawl_timestamp": ts}]
    try:
        data = extract_all(r.text)
    except Exception as e:                       # a malformed page must never crash the batch
        log.error("%s: extractor error: %r", url, e)
        return meta, [{"url": url, "schema_type": "", "format": "", "status": "unparsable",
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
    return meta, rows


# --------------------------------------------------------------------------- #
# URL collection (file / CSV / sitemap / GUI selection) + resume journal
# --------------------------------------------------------------------------- #

async def collect_urls(client: WAFSafeClient, args: argparse.Namespace) -> list[str]:
    urls: list[str] = []
    if args.input:
        p = Path(args.input)
        if p.exists():
            urls += read_url_file(p)
        elif re.match(r"^https?://", args.input, re.I) and looks_like_sitemap(args.input):
            urls += await expand_sitemap(client, args.input, args.allow_cross_host, args.limit or 10 ** 9)
        elif re.match(r"^https?://", args.input, re.I):
            urls.append(args.input)
        else:
            raise SystemExit(f"--input '{args.input}': not an existing file and not an http(s) URL")
    for u in args.url:
        n = norm_url(u)
        if n:
            urls.append(n)
    for sm in args.sitemap:
        n = norm_url(sm)
        if n:
            urls += await expand_sitemap(client, n, args.allow_cross_host, args.limit or 10 ** 9)
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
    return urls


def load_journal(path: Path) -> dict[str, dict]:
    recs: dict[str, dict] = {}
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            try:
                rec = json.loads(line)
                recs[rec["url"]] = rec
            except (json.JSONDecodeError, KeyError):
                continue
    return recs


# --------------------------------------------------------------------------- #
# Excel report
# --------------------------------------------------------------------------- #

URL_HEADER = ["URL", "Fetch Status", "HTTP", "WAF Detected", "Parse Flag", "Blocks",
              "Parsable", "Unparsable", "Types Found", "Remark"]
ITEM_HEADER = ["URL", "Format", "Type", "Status", "Error Reason", "HTTP", "Timestamp", "Snippet"]
BAD_HEADER = ["URL", "Format", "Type", "Error Reason", "Snippet"]
TYPE_HEADER = ["Type", "Entities", "URLs", "Parsable", "Unparsable"]
XL_CELL_MAX, XL_MAX_ROWS = 32000, 1_048_575


def url_flag(fetch_status: str, n_ok: int, n_bad: int) -> str:
    if fetch_status != "ok":
        return "NOT CHECKED"
    if n_ok == 0 and n_bad == 0:
        return "NO SCHEMA"
    if n_bad == 0:
        return "PARSABLE"
    return "UNPARSABLE" if n_ok == 0 else "PARTIAL"


def build_tables(rows: list[dict], url_meta: dict[str, dict]) -> dict:
    type_ents: Counter = Counter()
    type_urls: dict[str, set] = defaultdict(set)
    type_status: dict[str, Counter] = defaultdict(Counter)
    by_url: dict[str, list] = defaultdict(list)
    for r in rows:
        by_url[r["url"]].append(r)
        if r["schema_type"]:
            type_ents[r["schema_type"]] += 1
            type_urls[r["schema_type"]].add(r["url"])
            type_status[r["schema_type"]][r["status"]] += 1

    url_rows = []
    for url, m in url_meta.items():
        ru = by_url.get(url, [])
        n_ok = sum(1 for r in ru if r["status"] == "parsable")
        n_bad = sum(1 for r in ru if r["status"] == "unparsable")
        types_found = sorted({r["schema_type"] for r in ru if r["schema_type"]})
        url_rows.append([url, m["fetch_status"], m["http_status"] or "", m["waf"],
                         url_flag(m["fetch_status"], n_ok, n_bad), len(ru), n_ok, n_bad,
                         "; ".join(types_found), m["remark"]])

    items_sorted = sorted(rows, key=lambda r: (r["schema_type"] or "￿", r["url"]))
    item_rows = [[r["url"], r["format"], r["schema_type"], STATUS_FILL.get(r["status"], r["status"]),
                 r["error_reason"], r["http_status"] or "", r["crawl_timestamp"],
                 (r["raw_schema_snippet"] or "")[:XL_CELL_MAX]] for r in items_sorted]
    bad_rows = [[r["url"], r["format"], r["schema_type"], r["error_reason"], r["raw_schema_snippet"]]
               for r in items_sorted if r["status"] == "unparsable" and r["raw_schema_snippet"]]
    type_rows = [[t, n, len(type_urls[t]), type_status[t]["parsable"], type_status[t]["unparsable"]]
                for t, n in type_ents.most_common()]
    return {"urls": url_rows, "items": item_rows, "bad": bad_rows, "types": type_rows, "type_counts": type_ents}


def build_matrix(rows: list[dict], url_order: list[str]) -> tuple[list[str], list[list]]:
    """URL x main-schema-type pivot. For each (URL, type) pair: the extracted
    data (the raw snippet(s) found - joined if that type occurs more than once
    on the page) and its status (parsable / unparsable / partial across
    occurrences). Columns ordered by how many URLs carry that type (most
    widely used first). Row-wise detail with every other field (format, HTTP
    status, timestamp, error reason, ...) is the separate "Items" sheet."""
    type_urls: dict[str, set] = defaultdict(set)
    cell: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for r in rows:
        ty = r["schema_type"]
        if not ty:
            continue
        cell[(r["url"], ty)].append(r)
        type_urls[ty].add(r["url"])
    types = sorted(type_urls, key=lambda ty: (-len(type_urls[ty]), ty))
    matrix = []
    for url in url_order:
        row_cells = []
        for ty in types:
            matches = cell.get((url, ty), [])
            if not matches:
                row_cells.append(("", ""))
                continue
            data = " || ".join((m["raw_schema_snippet"] or "")[:200] for m in matches)
            statuses = {m["status"] for m in matches}
            status = ("PARSABLE" if statuses == {"parsable"} else
                     "UNPARSABLE" if statuses == {"unparsable"} else "PARTIAL")
            row_cells.append((data, status))
        matrix.append([url] + row_cells)
    return types, matrix


def write_excel(path: Path, t: dict, rows: list[dict], url_meta: dict[str, dict], per_type_sheets: int = 25) -> Path:
    from openpyxl import Workbook
    from openpyxl.cell.cell import ILLEGAL_CHARACTERS_RE
    from openpyxl.styles import Alignment, Font, PatternFill

    fills = {k: PatternFill("solid", fgColor=v) for k, v in {
        "PARSABLE": "C6EFCE", "PARTIAL": "FFD8A8", "UNPARSABLE": "FFC7CE",
        "NO SCHEMA": "E7E6E6", "NOT CHECKED": "E7E6E6"}.items()}
    head_fill, head_font = PatternFill("solid", fgColor="1F3864"), Font(bold=True, color="FFFFFF")

    def clean(v):
        return ILLEGAL_CHARACTERS_RE.sub("", v)[:XL_CELL_MAX + 100] if isinstance(v, str) else v

    def sheet(wb, title, header, data_rows, widths, flag_col=None):
        ws = wb.create_sheet(title[:31])
        ws.append(header)
        for c in ws[1]:
            c.fill, c.font, c.alignment = head_fill, head_font, Alignment(vertical="center")
        for row in data_rows[:XL_MAX_ROWS]:
            row = [clean(v) for v in row]
            ws.append(row)
            for c in ws[ws.max_row]:                # never let scraped text become a live formula
                if c.data_type == "f":
                    c.data_type = "s"
            if flag_col is not None and row[flag_col] in fills:
                ws.cell(row=ws.max_row, column=flag_col + 1).fill = fills[row[flag_col]]
        for i, w in enumerate(widths, 1):
            ws.column_dimensions[ws.cell(row=1, column=i).column_letter].width = w
        ws.freeze_panes, ws.auto_filter.ref = "A2", ws.dimensions
        return ws

    def sheet_matrix(wb, title, types, matrix):
        """URL rows; each type contributes two columns - '<Type>' (the extracted
        data) then '<Type> - Status' (parsable/unparsable/partial), colour-coded."""
        ws = wb.create_sheet(title[:31])
        header = ["URL"]
        for ty in types:
            header += [ty, f"{ty} - Status"]
        ws.append(header)
        for c in ws[1]:
            c.fill, c.font, c.alignment = head_fill, head_font, Alignment(vertical="center")
        for row in matrix[:XL_MAX_ROWS]:
            url, cells = row[0], row[1:]
            flat = [clean(url)]
            for data, status in cells:
                flat += [clean(data), status]
            ws.append(flat)
            r = ws.max_row
            for c in ws[r]:                          # never let scraped text become a live formula
                if c.data_type == "f":
                    c.data_type = "s"
            for i, (data, status) in enumerate(cells):
                if status in fills:
                    data_col, status_col = 2 + i * 2, 3 + i * 2
                    ws.cell(row=r, column=data_col).fill = fills[status]
                    ws.cell(row=r, column=status_col).fill = fills[status]
        ws.column_dimensions["A"].width = 50
        for i in range(len(types)):
            ws.column_dimensions[ws.cell(row=1, column=2 + i * 2).column_letter].width = 45
            ws.column_dimensions[ws.cell(row=1, column=3 + i * 2).column_letter].width = 13
        ws.freeze_panes, ws.auto_filter.ref = "B2", ws.dimensions
        return ws

    wb = Workbook()
    ws = wb.active
    ws.title = "Summary"
    fs = Counter(m["fetch_status"] for m in url_meta.values())
    pf = Counter(url_flag(m["fetch_status"],
                          sum(1 for r in rows if r["url"] == u and r["status"] == "parsable"),
                          sum(1 for r in rows if r["url"] == u and r["status"] == "unparsable"))
                for u, m in url_meta.items())
    ws.append(["Schema Tag Extractor - merged report"])
    ws["A1"].font = Font(bold=True, size=14)
    ws.append(["Generated", datetime.now().strftime("%Y-%m-%d %H:%M:%S")])
    ws.append(["URLs processed", len(url_meta)])
    ws.append(["Schema entities found", len(rows)])
    ws.append(["Distinct main types", len(t["types"])])
    ws.append(["Unparsable blocks", sum(1 for r in rows if r["status"] == "unparsable")])
    for title, counter in (("Fetch status", fs), ("Parse flag", pf)):
        ws.append([]); ws.append([title, "Count"])
        for c in ws[ws.max_row]:
            c.font = Font(bold=True)
        for k, v in counter.most_common():
            ws.append([k, v])
            if k in fills:
                ws.cell(row=ws.max_row, column=1).fill = fills[k]
    blocked = sorted({u for u, m in url_meta.items() if m["fetch_status"] in ("blocked_waf", "circuit_open")})
    if blocked:
        ws.append([])
        ws.append(["WAF-blocked / stopped URLs (not bypassed - ask the owner to allowlist you, then --resume)"])
        ws.cell(row=ws.max_row, column=1).font = Font(bold=True, color="C00000")
        for u in blocked[:200]:
            ws.append([u])
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 46, 22

    sheet(wb, "URLs", URL_HEADER, t["urls"], [55, 18, 7, 14, 14, 8, 9, 10, 40, 60], flag_col=4)
    matrix_types, matrix_rows = build_matrix(rows, list(url_meta.keys()))
    if matrix_types:
        sheet_matrix(wb, "URL x Type", matrix_types, matrix_rows)
    sheet(wb, "Items", ITEM_HEADER, t["items"], [50, 10, 22, 12, 40, 8, 20, 80], flag_col=3)
    sheet(wb, "Unparsable", BAD_HEADER, t["bad"], [50, 10, 22, 50, 90])
    sheet(wb, "Types Summary", TYPE_HEADER, t["types"], [28, 10, 8, 10, 10])

    by_type: dict[str, list] = defaultdict(list)
    for row in t["items"]:
        by_type[row[2]].append(row)
    used = {"summary", "urls", "items", "unparsable", "types summary"}
    for typ, _ in t["type_counts"].most_common(per_type_sheets):
        base = "T_" + re.sub(r"[\[\]:*?/\\]", "", typ)[:27]
        name, n = base, 2
        while name.lower() in used:
            name, n = f"{base[:28]}_{n}", n + 1
        used.add(name.lower())
        sheet(wb, name, ITEM_HEADER, by_type[typ], [50, 10, 22, 12, 40, 8, 20, 80], flag_col=3)
    wb.save(path)
    return path


# --------------------------------------------------------------------------- #
# Input dialog (Tk; console fallback)
# --------------------------------------------------------------------------- #

def is_sitemap_url(u: str) -> bool:
    return looks_like_sitemap(u)


def prompt_console(default_out: Path) -> dict | None:
    print("Schema Tool - no dialog available, using console.")
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
    try:
        import tkinter as tk
        from tkinter import filedialog, messagebox, ttk
        root = tk.Tk()
    except Exception:
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
                    "(auto-enabled for bank/finance-looking domains; ~1 request per few seconds, skips login pages)"
                    ).grid(row=3, column=0, columnspan=2, sticky="w", **pad)
    opts = ttk.Frame(root)
    opts.grid(row=4, column=0, columnspan=2, sticky="ew", padx=10)
    ttk.Label(opts, text="Max URLs (blank = all):").grid(row=0, column=0, sticky="w", pady=3)
    ttk.Entry(opts, textvariable=limit, width=10).grid(row=0, column=1, sticky="w", padx=6)
    ttk.Label(opts, text="Contact email/URL (optional, shown to site owner in User-Agent):").grid(row=1, column=0, sticky="w", pady=3)
    ttk.Entry(opts, textvariable=contact, width=32).grid(row=1, column=1, sticky="w", padx=6)
    ttk.Label(opts, text="Save reports in:").grid(row=2, column=0, sticky="w", pady=3)
    of = ttk.Frame(opts)
    of.grid(row=2, column=1, sticky="w", padx=6)
    ttk.Entry(of, textvariable=outdir, width=32).pack(side="left")
    ttk.Button(of, text="Browse...", command=lambda: outdir.set(filedialog.askdirectory(initialdir=outdir.get()) or outdir.get())).pack(side="left", padx=4)

    def start():
        entries = [sm_var.get()] if mode.get() == "sitemap" else text.get("1.0", "end").splitlines()
        entries = [e.strip() for e in entries if e.strip() and not e.strip().startswith("#")]
        if not entries:
            messagebox.showwarning("Schema Tool", "Please enter a sitemap URL or at least one URL.")
            return
        if limit.get().strip() and not limit.get().strip().isdigit():
            messagebox.showwarning("Schema Tool", "Max URLs must be a number (or blank).")
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


def apply_selection(args: argparse.Namespace, sel: dict) -> None:
    hosts = set()
    for e in sel["entries"]:
        n = norm_url(e)
        if not n:
            continue
        hosts.add(urlparse(n).netloc)
        (args.sitemap if is_sitemap_url(n) else args.url).append(n)
    if sel["sensitive"]:
        args.waf_mode = True
        existing = {d for d in args.sensitive_domains.split(",") if d}
        args.sensitive_domains = ",".join(sorted(existing | hosts))
    args.limit = sel["limit"] or args.limit
    args.contact = sel["contact"] or args.contact
    args.output_dir = sel["out"]


def show_done(xlsx: Path | None, n_urls: int) -> None:
    try:
        import os
        import tkinter as tk
        from tkinter import messagebox
        root = tk.Tk()
        root.withdraw()
        root.attributes("-topmost", True)
        msg = f"Finished: {n_urls} URLs processed."
        if xlsx:
            msg += f"\n\nExcel report:\n{xlsx}\n\nOpen it now?"
            if messagebox.askyesno("Schema Tool", msg, parent=root):
                os.startfile(xlsx)          # Windows
        else:
            messagebox.showinfo("Schema Tool", msg, parent=root)
        root.destroy()
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# CLI + orchestration
# --------------------------------------------------------------------------- #

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="Schema Tag Extractor (merged): bulk JSON-LD/Microdata/RDFa extraction, "
                    "main-type segregation, parsable/unparsable classification, WAF-safe fetching. "
                    "Run with no input arguments for a dialog box.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    src = p.add_argument_group("input")
    src.add_argument("--input", help="file (.txt/.csv) or a sitemap URL (.xml/index/.xml.gz/robots.txt)")
    src.add_argument("--url", action="append", default=[], help="single URL (repeatable)")
    src.add_argument("--sitemap", action="append", default=[], help="sitemap/robots.txt URL (repeatable)")
    src.add_argument("--allow-cross-host", action="store_true", help="keep sitemap URLs found on other hosts")
    src.add_argument("--limit", type=int, default=0, help="max URLs to process (0 = no limit)")
    src.add_argument("--max-per-domain", type=int, default=0, help="max URLs per host (0 = no limit)")
    out = p.add_argument_group("output")
    out.add_argument("--output-dir", "--out", dest="output_dir", default="schema_audit_output")
    out.add_argument("--resume", action="store_true", help="skip URLs already completed in journal.jsonl")
    out.add_argument("--no-excel", action="store_true", help="skip the .xlsx report; still writes CSV/JSON")
    out.add_argument("--no-gui", action="store_true", help="never show the input dialog (fail if no input given)")
    out.add_argument("--dry-run", action="store_true", help="resolve input and print the URL count; fetch nothing")
    pol = p.add_argument_group("politeness / WAF safety")
    pol.add_argument("--rps", type=float, default=2.0, help="global requests-per-second cap")
    pol.add_argument("--concurrency", type=int, default=5, help="global max simultaneous requests")
    pol.add_argument("--waf-mode", action="store_true",
                     help="auto-apply the strict WAF-safe profile to bank/finance-looking hosts")
    pol.add_argument("--sensitive-domains", default="",
                     help="comma-separated domains that always get the strict WAF-safe profile")
    pol.add_argument("--sensitive-domain", dest="sensitive_domain_repeat", action="append", default=[],
                     help="a single sensitive domain (repeatable; merged with --sensitive-domains)")
    pol.add_argument("--timeout", type=float, default=15.0)
    pol.add_argument("--user-agent", default=None)
    pol.add_argument("--contact", default=None, help="email/URL appended to the User-Agent")
    p.add_argument("-v", "--verbose", action="store_true")
    return p


def setup_logging(out: Path, verbose: bool) -> None:
    out.mkdir(parents=True, exist_ok=True)
    fmt = logging.Formatter("%(asctime)s %(levelname)s %(message)s", "%H:%M:%S")
    level = logging.DEBUG if verbose else logging.INFO
    handlers = [logging.StreamHandler(), logging.FileHandler(out / "requests.log", encoding="utf-8")]
    for h in handlers:
        h.setFormatter(fmt)
    for name in ("schema_tool", "schema_audit"):        # both this file's and the fetch-layer's logger
        lg = logging.getLogger(name)
        lg.setLevel(level)
        lg.propagate = False
        for h in handlers:
            lg.addHandler(h)
    err = logging.getLogger("schema_audit.errors")
    err.setLevel(logging.INFO)
    err.propagate = False
    efh = logging.FileHandler(out / "errors.log", encoding="utf-8")
    efh.setFormatter(fmt)
    err.addHandler(efh)


def write_outputs(out: Path, rows: list[dict]) -> None:
    with open(out / "schema_audit.csv", "w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({k: r.get(k, "") for k in FIELDS})
    with open(out / "schema_audit.json", "w", encoding="utf-8") as f:
        json.dump(rows, f, ensure_ascii=False, indent=2)


async def run(args: argparse.Namespace) -> int:
    gui_used = False
    args.sensitive_domains = ",".join(sorted(
        {d for d in args.sensitive_domains.split(",") if d} | set(args.sensitive_domain_repeat)))
    if not (args.input or args.url or args.sitemap):
        if args.no_gui:
            print("Provide --input, --url or --sitemap. See --help.", file=sys.stderr)
            return 2
        sel = prompt_inputs(Path(__file__).resolve().parent / "schema_audit_output")
        if not sel:
            print("Cancelled - nothing to do.")
            return 1
        apply_selection(args, sel)
        gui_used = True
        if not (args.url or args.sitemap):
            print("No valid http(s) URLs were entered.", file=sys.stderr)
            return 2

    out = Path(args.output_dir)
    setup_logging(out, args.verbose)

    async with WAFSafeClient(args) as client:
        urls = await collect_urls(client, args)
        log.info("%d URLs to process", len(urls))
        if args.dry_run:
            print(f"{len(urls)} URLs resolved (dry run - nothing fetched).")
            return 0
        if not urls:
            print("No URLs resolved.", file=sys.stderr)
            return 1

        journal_path = out / "journal.jsonl"
        prior = load_journal(journal_path) if args.resume else {}
        if not args.resume and journal_path.exists():
            journal_path.rename(out / f"journal.{datetime.now():%Y%m%d-%H%M%S}.bak.jsonl")
        todo = [u for u in urls if not (u in prior and prior[u]["meta"]["fetch_status"] not in RETRY_ON_RESUME)]
        log.info("%d already done, %d to fetch", len(urls) - len(todo), len(todo))

        jf = open(journal_path, "a", encoding="utf-8")
        jlock = asyncio.Lock()

        async def worker(u: str):
            meta, rows = await process_one(client, u)
            async with jlock:
                jf.write(json.dumps({"url": u, "meta": meta, "rows": rows}, ensure_ascii=False) + "\n")
                jf.flush()

        try:
            await asyncio.gather(*(worker(u) for u in todo))
        except (KeyboardInterrupt, asyncio.CancelledError):
            log.warning("Interrupted - progress saved. Re-run with --resume to continue.")
        finally:
            jf.close()

    all_recs = load_journal(journal_path)
    all_recs = {u: all_recs[u] for u in urls if u in all_recs}   # in input order, only requested URLs
    url_meta = {u: rec["meta"] for u, rec in all_recs.items()}
    rows = [row for rec in all_recs.values() for row in rec["rows"]]

    write_outputs(out, rows)
    xlsx = None
    if not args.no_excel:
        try:
            tables = build_tables(rows, url_meta)
            xlsx = write_excel(out / f"schema_report_{datetime.now():%Y%m%d_%H%M%S}.xlsx", tables, rows, url_meta)
        except ImportError:
            print("openpyxl not installed - skipped the Excel report (CSV/JSON were still written). "
                  "pip install openpyxl", file=sys.stderr)

    n_ok = sum(1 for r in rows if r["status"] == "parsable")
    n_bad = sum(1 for r in rows if r["status"] == "unparsable")
    blocked = sorted({u for u, m in url_meta.items() if m["fetch_status"] in ("blocked_waf", "circuit_open")})
    print("\n=== Summary ===")
    print(f"URLs processed     : {len(all_recs)} / {len(urls)} requested")
    print(f"Schema blocks found: {len(rows)}  (parsable={n_ok}, unparsable={n_bad})")
    if blocked:
        print(f"WAF-blocked/stopped: {len(blocked)} URLs - see errors.log (not bypassed; ask owner to allowlist, then --resume)")
    print(f"\nCSV  : {(out / 'schema_audit.csv').resolve()}")
    print(f"JSON : {(out / 'schema_audit.json').resolve()}")
    if xlsx:
        print(f"Excel: {xlsx.resolve()}")
    print(f"Logs : {(out / 'requests.log').resolve()}  |  {(out / 'errors.log').resolve()}")

    if gui_used:
        show_done(xlsx.resolve() if xlsx else None, len(all_recs))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return asyncio.run(run(args))


if __name__ == "__main__":
    sys.exit(main())
