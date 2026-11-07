"""
SchemaValidator
===============
Turns extracted blocks into flat rows - ONE ROW PER MAIN SCHEMA ENTITY - each
classified `parsable` or `unparsable` with an error_reason.

"Main entity" = a JSON-LD document root, or a member of its @context/@graph
(a page with Organization + WebSite + BreadcrumbList siblings in one @graph
yields three rows); for Microdata/RDFa, a top-level itemscope/typeof element.

Anything reached only by descending into a PROPERTY - Question/Answer inside
FAQPage's mainEntity, Offer inside Product, PostalAddress inside an
Organization's address, ListItem inside a BreadcrumbList - is detail on the
main entity, not a schema block of its own, and is deliberately NOT walked
into or reported as a separate row. Earlier revisions of this tool flattened
those nested property values into their own rows (e.g. reporting "Answer" as
if it were a schema type a page implements); that produced sub-types dressed
up as main types, which is exactly what this rule now excludes.

Parsability rules (strict - a schema is parsable only if ALL hold)
------------------------------------------------------------------
JSON-LD
  * the script body is not empty
  * it is valid JSON  (json.loads, no leniency)
  * the document declares an @context that points at schema.org
  * the node has an @type
  * every declared @type is a real schema.org entity class

Microdata / RDFa
  * itemtype / typeof is present and on the schema.org vocabulary
  * it is a real schema.org entity class
  * the item carries at least one itemprop / property

There is deliberately NO auto-repair.  A block with a trailing comma is
reported `unparsable` (JSONDecodeError ...) rather than being silently fixed and
called valid: consumers such as Google's parser reject it, and reporting it as
valid would be a false positive.
"""
from __future__ import annotations

import json

from . import type_resolver as tr

SNIPPET_LEN = 500


def _row(schema_type="", status="unparsable", error_reason="", snippet="") -> dict:
    return {"schema_type": schema_type, "status": status, "error_reason": error_reason,
            "raw_schema_snippet": snippet[:SNIPPET_LEN]}


def _ctx_has_schema(ctx) -> bool:
    if isinstance(ctx, str):
        return "schema.org" in ctx.lower()
    if isinstance(ctx, list):
        return any(_ctx_has_schema(c) for c in ctx)
    if isinstance(ctx, dict):
        return any(_ctx_has_schema(v) for v in ctx.values())
    return False


def _dump(node) -> str:
    try:
        return json.dumps(node, ensure_ascii=False)
    except (TypeError, ValueError):
        return str(node)


def validate_jsonld_block(raw_text: str) -> list[dict]:
    text = (raw_text or "").strip().lstrip("﻿")
    if not text:
        return [_row(error_reason="Empty script block")]
    try:
        data = json.loads(text)
    except json.JSONDecodeError as e:
        return [_row(error_reason=f"JSONDecodeError: {e.msg} (line {e.lineno}, col {e.colno})", snippet=text)]

    roots = data if isinstance(data, list) else [data]
    # @context may sit on the root (or, for arrays, on any element) and covers the whole block.
    ctx_ok = any(isinstance(r, dict) and _ctx_has_schema(r.get("@context")) for r in roots)
    has_ctx = any(isinstance(r, dict) and "@context" in r for r in roots)
    rows: list[dict] = []

    def walk(node):
        if isinstance(node, list):
            for n in node:
                walk(n)
            return
        if not isinstance(node, dict):
            return
        if "@graph" in node:
            walk(node["@graph"])
        t = node.get("@type")
        if t is not None:
            types = t if isinstance(t, list) else [t]
            res = tr.resolve_multi([x for x in types if isinstance(x, str)])
            if not res["type"]:
                rows.append(_row("", "unparsable", "Empty or non-string @type", _dump(node)))
            elif not ctx_ok:
                why = "@context does not reference schema.org" if has_ctx else "Missing @context"
                rows.append(_row(res["type"], "unparsable", why, _dump(node)))
            elif not res["recognized"]:
                rows.append(_row(res["type"], "unparsable", tr.unknown_reason(res), _dump(node)))
            else:
                rows.append(_row(res["type"], "parsable", "", _dump(node)))
        # Deliberately do NOT descend into node's other properties (offers, mainEntity,
        # acceptedAnswer, address, ...) - see module docstring: those are detail on this
        # entity, not additional main schema blocks.

    walk(data)
    if not rows:
        rows.append(_row(error_reason="Missing @type", snippet=text))
    return rows


def validate_microdata_item(item: dict) -> dict:
    types, snip = item.get("types") or [], item.get("snippet", "")
    if not types:
        return _row(error_reason="itemscope without itemtype (untyped item)", snippet=snip)
    res = tr.resolve_multi(types)
    if not res["recognized"]:
        return _row(res["type"], "unparsable", tr.unknown_reason(res), snip)
    if not item.get("props"):
        return _row(res["type"], "unparsable", "itemscope has no itemprop values", snip)
    return _row(res["type"], "parsable", "", snip)


def validate_rdfa_item(item: dict) -> dict:
    types, snip, vocab = item.get("types") or [], item.get("snippet", ""), item.get("vocab", "")
    if not types:
        return _row(error_reason="typeof without a value", snippet=snip)
    # A bare typeof="Product" is only schema.org if a vocab attribute says so.
    full = [t if ("://" in t or ":" in t) else (vocab.rstrip("/") + "/" + t if vocab else "?/" + t) for t in types]
    res = tr.resolve_multi(full)
    if not res["recognized"]:
        no_vocab = any(f.startswith("?/") for f in full)
        why = "typeof used without a schema.org vocab attribute" if no_vocab else tr.unknown_reason(res)
        return _row(res["type"].replace("?/", ""), "unparsable", why, snip)
    if not item.get("props"):
        return _row(res["type"], "unparsable", "typeof element has no property values", snip)
    return _row(res["type"], "parsable", "", snip)
