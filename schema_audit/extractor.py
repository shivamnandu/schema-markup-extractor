"""
SchemaExtractor
===============
Pulls the raw structured data out of ONE html page and hands it on undecided -
SchemaValidator does all classification.

  * JSON-LD  : every <script type="application/ld+json"> body, via BeautifulSoup
               (html.parser), returned as raw text so JSON errors are still visible.
  * Microdata: itemscope/itemtype/itemprop, built as a tree of items.
  * RDFa     : typeof/property (+ vocab), same shape as microdata.

Microdata/RDFa follow the "item boundary" rule: an element with itemscope/typeof
starts a new item; properties found below it belong to it, not to its parent.
A nested item is reachable only as the value of its parent's property, so it is
never emitted twice.
"""
from __future__ import annotations

import re

from bs4 import BeautifulSoup, Tag

URL_ATTR = {"a": "href", "area": "href", "link": "href", "img": "src", "audio": "src", "video": "src",
            "source": "src", "embed": "src", "iframe": "src", "track": "src", "object": "data"}
SNIPPET_LEN = 500


def _value_of(tag: Tag) -> str:
    if tag.has_attr("content"):
        return tag["content"]
    if tag.name in URL_ATTR and tag.has_attr(URL_ATTR[tag.name]):
        return tag[URL_ATTR[tag.name]]
    if tag.has_attr("resource"):
        return tag["resource"]
    if tag.name == "time" and tag.has_attr("datetime"):
        return tag["datetime"]
    if tag.name in ("data", "meter") and tag.has_attr("value"):
        return tag["value"]
    return tag.get_text(" ", strip=True)


def _has_ancestor_with(tag: Tag, attr: str) -> bool:
    return any(isinstance(p, Tag) and p.has_attr(attr) for p in tag.parents)


def _attr_str(tag: Tag, name: str) -> str:
    v = tag.get(name, "")
    return " ".join(v) if isinstance(v, list) else (v or "")


# ---- Microdata ------------------------------------------------------------- #
def _microdata_item(tag: Tag) -> dict:
    """Build one item. A nested itemscope (e.g. Offer inside Product, Answer
    inside Question) becomes the VALUE of its parent's property, same as a
    JSON-LD sub-object - it is not reported as a schema block of its own; only
    extract_microdata()'s top-level roots are (see validator.py docstring)."""
    props: dict[str, list] = {}

    def walk(node: Tag):
        for child in node.find_all(True, recursive=False):
            if child.has_attr("itemprop"):
                val = _microdata_item(child) if child.has_attr("itemscope") else _value_of(child)
                for name in _attr_str(child, "itemprop").split():
                    props.setdefault(name, []).append(val)
            if not child.has_attr("itemscope"):        # itemscope = item boundary, stop here
                walk(child)

    walk(tag)
    return {"types": _attr_str(tag, "itemtype").split(), "props": props, "snippet": str(tag)[:SNIPPET_LEN]}


def extract_microdata(soup: BeautifulSoup) -> list[dict]:
    roots = [t for t in soup.find_all(attrs={"itemscope": True}) if not _has_ancestor_with(t, "itemscope")]
    return [_microdata_item(t) for t in roots]


# ---- RDFa ------------------------------------------------------------------ #
def _rdfa_item(tag: Tag, vocab: str) -> dict:
    """Same nested-item-as-property-value rule as _microdata_item."""
    props: dict[str, list] = {}

    def walk(node: Tag, inherited_vocab: str):
        for child in node.find_all(True, recursive=False):
            child_vocab = _attr_str(child, "vocab") or inherited_vocab
            if child.has_attr("typeof"):               # new subject = item boundary
                if child.has_attr("property"):
                    for name in _attr_str(child, "property").split():
                        props.setdefault(name, []).append(_rdfa_item(child, child_vocab))
                continue
            if child.has_attr("property"):
                for name in _attr_str(child, "property").split():
                    props.setdefault(name, []).append(_value_of(child))
            walk(child, child_vocab)

    walk(tag, vocab)
    return {"types": _attr_str(tag, "typeof").split(), "props": props, "vocab": vocab,
            "snippet": str(tag)[:SNIPPET_LEN]}


def extract_rdfa(soup: BeautifulSoup) -> list[dict]:
    out = []
    for t in soup.find_all(attrs={"typeof": True}):
        if _has_ancestor_with(t, "typeof"):
            continue
        vocab = next((_attr_str(p, "vocab") for p in [t, *t.parents]
                      if isinstance(p, Tag) and p.has_attr("vocab")), "")
        out.append(_rdfa_item(t, vocab))
    return out


# ---- JSON-LD --------------------------------------------------------------- #
def extract_jsonld(soup: BeautifulSoup) -> list[str]:
    scripts = soup.find_all("script", attrs={"type": re.compile(r"ld\+json", re.I)})
    return [s.string if s.string is not None else s.get_text() for s in scripts]


def extract_all(html_text: str) -> dict:
    soup = BeautifulSoup(html_text, "html.parser")
    return {"jsonld": extract_jsonld(soup), "microdata": extract_microdata(soup), "rdfa": extract_rdfa(soup)}
