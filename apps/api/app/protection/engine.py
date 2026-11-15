"""Email Security and Brand Protection engines (pilot). Deterministic, offline.

DMARC: parses an aggregate (RUA) report. DTDs and entity declarations are refused before parsing (XXE and entity
expansion), size is bounded, and only the documented RFC 7489 elements are read.
Brand: generates lookalike-domain candidates (omission, repetition, adjacent transposition, homoglyphs, hyphenation,
TLD swaps) deterministically. Whether a candidate is REGISTERED is a question for a resolver adapter:
  unconfigured   no lookups are made; a run reports source_unconfigured and creates nothing;
  test_adapter   development/test only: a fixed fixture of "registered" names, labelled source test_adapter.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

FORBIDDEN_XML = re.compile(r"<!\s*(DOCTYPE|ENTITY)", re.I)
HOMOGLYPHS = {"o": "0", "l": "1", "i": "1", "e": "3", "a": "4", "s": "5", "m": "rn"}
TLDS = ("com", "net", "org", "ng", "co", "io", "info")
FIXTURE = Path(__file__).resolve().parent / "fixtures" / "registered_lookalikes.json"


class DmarcError(ValueError):
    pass


def _text(el, path: str) -> str:
    v = el.findtext(path)
    return (v or "").strip()


def parse_dmarc(xml_text: str) -> dict:
    if FORBIDDEN_XML.search(xml_text[:4096]) or "<!ENTITY" in xml_text.upper():
        raise DmarcError("DTDs and entity declarations are not accepted")
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        raise DmarcError("The report is not well-formed XML") from None
    if root.tag != "feedback":
        raise DmarcError("Not a DMARC aggregate report (root element must be <feedback>)")
    meta, pol = root.find("report_metadata"), root.find("policy_published")
    if meta is None or pol is None:
        raise DmarcError("report_metadata and policy_published are required")
    try:
        begin = datetime.fromtimestamp(int(_text(meta, "date_range/begin")), tz=timezone.utc)
        end = datetime.fromtimestamp(int(_text(meta, "date_range/end")), tz=timezone.utc)
    except ValueError:
        raise DmarcError("date_range begin/end must be Unix timestamps") from None
    records, total, failing = [], 0, 0
    for rec in root.findall("record")[:10_000]:
        try:
            count = int(_text(rec, "row/count") or 0)
        except ValueError:
            raise DmarcError("record count must be an integer") from None
        dkim, spf = _text(rec, "row/policy_evaluated/dkim"), _text(rec, "row/policy_evaluated/spf")
        records.append({"source_ip": _text(rec, "row/source_ip")[:64], "count": count,
                        "disposition": _text(rec, "row/policy_evaluated/disposition") or "none", "dkim": dkim or "none",
                        "spf": spf or "none", "header_from": _text(rec, "identifiers/header_from").lower()[:253]})
        total += count
        if dkim != "pass" and spf != "pass":
            failing += count
    return {"reporter": _text(meta, "org_name")[:200] or "unknown", "report_id": _text(meta, "report_id")[:200],
            "domain": _text(pol, "domain").lower(), "policy": _text(pol, "p") or None, "period_start": begin, "period_end": end,
            "records": records, "total": total, "failing": failing}


def lookalikes(domain: str, limit: int = 300) -> list[tuple[str, str]]:
    """(candidate, technique) pairs for a registrable domain; deterministic order, the domain itself excluded."""
    name, _, tld = domain.lower().rpartition(".")
    if not name or "." in name:
        name, tld = domain.lower().split(".", 1)[0], domain.lower().split(".", 1)[1]
    out: dict[str, str] = {}

    def add(n: str, t: str, technique: str) -> None:
        cand = f"{n}.{t}"
        if n and cand != domain and re.match(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$", n) and cand not in out:
            out[cand] = technique
    for i in range(len(name)):
        add(name[:i] + name[i + 1:], tld, "omission")
        add(name[:i] + name[i] + name[i:], tld, "repetition")
        if i < len(name) - 1:
            add(name[:i] + name[i + 1] + name[i] + name[i + 2:], tld, "transposition")
        if name[i] in HOMOGLYPHS:
            add(name[:i] + HOMOGLYPHS[name[i]] + name[i + 1:], tld, "homoglyph")
        if 0 < i < len(name):
            add(name[:i] + "-" + name[i:], tld, "hyphenation")
    for t in TLDS:
        if t != tld:
            add(name, t, "tld_swap")
    return list(out.items())[:limit]


@lru_cache
def _registered_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def resolve_test_adapter(candidates: list[str]) -> dict[str, dict]:
    reg = _registered_fixture()["registered"]
    return {c: reg[c] for c in candidates if c in reg}
