"""
MainTypeResolver
================
Resolves a declared @type / itemtype / typeof string to the entity's *main type*.

Design note - reconciling two instructions in the brief that cannot both be true
-------------------------------------------------------------------------------
The brief says (a) "walk up the schema.org hierarchy to the highest concrete
type" and (b) "a BreadcrumbList must be reported as BreadcrumbList, NOT as its
parent ItemList / CreativeWork".  BreadcrumbList's direct parent (ItemList) is
itself a concrete, recognised schema.org type, so a literal walk-up would
return ItemList - i.e. it would violate the brief's own worked example.

We follow the worked example, because it is the actual acceptance criterion:

    main type  =  the most specific type the page itself declares, verbatim.
                  Never generalised to an ancestor, never split into ancestors.

The bundled hierarchy (schema_types.json - all ~1000 classes from schema.org's
own vocabulary, no network needed at runtime) is used only to VALIDATE that a
declared type is a real schema.org class, never to rewrite it.  Data types
(Text, Number, URL...) are excluded: they are not valid entity types.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

_DATA = json.loads((Path(__file__).parent / "schema_types.json").read_text(encoding="utf-8"))
TYPES: dict[str, list[str]] = _DATA["types"]          # {type: [direct parents]}


def _descendants_of(root: str) -> set[str]:
    out, changed = {root}, True
    while changed:
        changed = False
        for t, parents in TYPES.items():
            if t not in out and any(p in out for p in parents):
                out.add(t)
                changed = True
    return out


_DATATYPES = _descendants_of("DataType")               # Text, Number, Boolean, URL ...
ENTITY_TYPES = {t for t in TYPES if t not in _DATATYPES}
_LOWER = {t.lower(): t for t in ENTITY_TYPES}


def strip_vocab(raw: str) -> tuple[str, str]:
    """-> (bare_name, vocab).  vocab is 'schema.org' or the foreign host."""
    raw = raw.strip()
    m = re.match(r"^https?://([^/]+)/(.*)$", raw)
    if m:
        host, rest = m.group(1).lower(), m.group(2)
        return rest, ("schema.org" if host == "schema.org" or host.endswith(".schema.org") else host)
    if raw.lower().startswith("schema:"):
        return raw.split(":", 1)[1], "schema.org"
    return raw, "schema.org"           # bare 'Product' => JSON-LD default vocab is schema.org


def resolve(raw_type: str) -> dict:
    """Validate ONE declared type. Returns {type, vocab, recognized}.
    A wrong-case spelling ('product') is normalised to the canonical name but
    still counted as recognised only when an exact canonical match exists."""
    name, vocab = strip_vocab(raw_type)
    if vocab != "schema.org":
        return {"type": name, "vocab": vocab, "recognized": False}
    if name in ENTITY_TYPES:
        return {"type": name, "vocab": vocab, "recognized": True}
    # Case-insensitive hit means a real type spelled wrong. Google/schema.org
    # validators treat that as an error, so it is NOT recognised (zero false
    # positives), but we report the canonical name to make the fix obvious.
    canon = _LOWER.get(name.lower())
    return {"type": name, "vocab": vocab, "recognized": False, "did_you_mean": canon}


def resolve_multi(raw_types: list[str]) -> dict:
    """A node may declare several types, e.g. ["Product", "Vehicle"]. schema.org
    multi-typing is deliberate, so none is dropped: the main type is every
    declared type joined with '+', and the node is recognised only if ALL of
    its declared types are real schema.org classes."""
    resolved = [resolve(t) for t in raw_types if isinstance(t, str) and t.strip()]
    if not resolved:
        return {"type": "", "vocab": "schema.org", "recognized": False, "bad": []}
    bad = [r for r in resolved if not r["recognized"]]
    return {
        "type": "+".join(r["type"] for r in resolved),
        "vocab": resolved[0]["vocab"],
        "recognized": not bad,
        "bad": bad,
    }


def unknown_reason(res: dict) -> str:
    parts = []
    for b in res["bad"]:
        hint = f" (did you mean '{b['did_you_mean']}'?)" if b.get("did_you_mean") else ""
        vocab = "" if b["vocab"] == "schema.org" else f" [non-schema.org vocabulary: {b['vocab']}]"
        parts.append(f"Unknown type: {b['type']}{hint}{vocab}")
    return "; ".join(parts)
