"""
URLSource
=========
Local-file input: a flat list (one URL per line, '#' comments ignored) or a CSV
with a 'url' column (header matched case-insensitively).  Sitemap input needs
the network client, so it lives in waf_client.expand_sitemap().
"""
from __future__ import annotations

import csv
from pathlib import Path
from urllib.parse import urldefrag, urlparse


def norm_url(u: str) -> str | None:
    u = u.strip().strip("\"'")
    if not u or u.startswith("#"):
        return None
    if not u.lower().startswith(("http://", "https://")):
        u = "https://" + u
    u = urldefrag(u)[0]
    p = urlparse(u)
    return u if p.scheme in ("http", "https") and p.netloc else None


def read_url_file(path: Path) -> list[str]:
    if path.suffix.lower() == ".csv":
        with open(path, newline="", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            col = next((c for c in (reader.fieldnames or []) if c and c.strip().lower() == "url"), None)
            if not col:
                raise SystemExit(f"{path}: no 'url' column found (columns: {reader.fieldnames})")
            urls = [norm_url(row.get(col) or "") for row in reader]
    else:
        urls = [norm_url(line) for line in path.read_text(encoding="utf-8-sig").splitlines()]
    return [u for u in urls if u]
