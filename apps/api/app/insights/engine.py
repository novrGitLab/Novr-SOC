"""Threat Insights engine (Phase 5, workstream F). Deterministic and organization-scoped; no model involved.

Reusable parts (also used by NHAI to build and verify evidence):
  * normalize(type, value)              -> canonical value or None (never guesses)
  * extract_observables(alert)          -> observables from known structured fields, then bounded text patterns
  * confidence(indicator, now)          -> MatchConfidence: deterministic score, band and reasons
  * stix_indicator(row) / stix_bundle   -> STIX 2.1 objects (indicator, sighting, marking refs, provenance)
  * parse_stix_bundle(bundle)           -> indicators from single-comparison STIX patterns; everything else skipped
Database operations run under the caller's organization context (RLS); they never take an organization argument.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from urllib.parse import urlsplit

from sqlalchemy import text
from sqlalchemy.engine import Connection

from novrsoc_contracts.v1.insights import Indicator, IndicatorType, MatchConfidence, Observable, Tlp

STIX_NS = uuid.UUID("6ba7b811-9dad-11d1-80b4-00c04fd430c8")  # RFC 4122 URL namespace: stable ids from values
TLP_MARKING = {  # STIX 2.1 TLP v2 marking-definition ids (OASIS)
    "clear": "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487",
    "green": "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb",
    "amber": "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421",
    "amber_strict": "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003",
    "red": "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1",
}
STIX_PATTERN = re.compile(r"^\[(ipv4-addr:value|ipv6-addr:value|domain-name:value|url:value|file:hashes\.'SHA-256'|vulnerability:name)\s*=\s*'([^'\\]{1,2048})'\]$")
STIX_TYPE = {"ipv4-addr:value": "ipv4", "ipv6-addr:value": "ipv6", "domain-name:value": "domain", "url:value": "url",
             "file:hashes.'SHA-256'": "sha256", "vulnerability:name": "cve"}
STIX_PATH = {"ipv4": "ipv4-addr:value", "ipv6": "ipv6-addr:value", "domain": "domain-name:value", "url": "url:value",
             "sha256": "file:hashes.'SHA-256'", "cve": "vulnerability:name"}

DOMAIN = re.compile(r"^(?=.{4,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
CVE = re.compile(r"^CVE-\d{4}-\d{4,7}$")
TEXT_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")  # a trailing full stop still matches
TEXT_SHA256 = re.compile(r"(?<![0-9A-Fa-f])[0-9A-Fa-f]{64}(?![0-9A-Fa-f])")
TEXT_URL = re.compile(r"\bhttps?://[^\s\"'<>]{3,2000}")
TEXT_SCAN_LIMIT = 16_384      # bounded text scanning
MAX_OBSERVABLES = 200

# Known structured fields of Wazuh alerts (decoded data). Order matters only for de-duplication.
FIELDS: list[tuple[str, tuple[str, ...]]] = [
    ("ipv4", ("data.srcip",)), ("ipv4", ("data.dstip",)), ("ipv4", ("data.src_ip",)), ("ipv4", ("data.dest_ip",)),
    ("ipv4", ("data.win.eventdata.ipAddress",)), ("ipv6", ("data.srcip",)), ("ipv6", ("data.dstip",)),
    ("domain", ("data.hostname",)), ("domain", ("data.dns.question.name",)), ("domain", ("data.url_domain",)),
    ("url", ("data.url",)), ("sha256", ("syscheck.sha256_after",)), ("sha256", ("data.virustotal.source.sha256",)),
    ("cve", ("data.vulnerability.cve",)),
]


def normalize(kind: str, value: Any) -> str | None:
    """The canonical form used for matching, or None when the value is not a valid `kind` (never coerced)."""
    if value is None:
        return None
    v = str(value).strip()
    if not v or len(v) > 2048:
        return None
    try:
        if kind == "ipv4":
            ip = ipaddress.ip_address(v)
            return str(ip) if ip.version == 4 else None
        if kind == "ipv6":
            ip = ipaddress.ip_address(v)
            return ip.compressed if ip.version == 6 else None
    except ValueError:
        return None
    if kind == "domain":
        d = v.lower().rstrip(".")
        return d if DOMAIN.match(d) else None
    if kind == "url":
        try:
            parts = urlsplit(v)
        except ValueError:
            return None
        if parts.scheme.lower() not in ("http", "https") or not parts.hostname:
            return None
        netloc = parts.hostname.lower() + (f":{parts.port}" if parts.port else "")
        return f"{parts.scheme.lower()}://{netloc}{parts.path or '/'}" + (f"?{parts.query}" if parts.query else "")
    if kind == "sha256":
        h = v.lower()
        return h if SHA256.match(h) else None
    if kind == "cve":
        c = v.upper()
        return c if CVE.match(c) else None
    return None


def _get(doc: Any, dotted: str) -> Any:
    cur = doc
    for part in dotted.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def extract_observables(raw: dict, *, src_ip: str | None = None) -> list[Observable]:
    """Observables of one alert: the stored source IP, known structured fields, then bounded patterns in full_log.
    Deterministic order; duplicates removed; at most MAX_OBSERVABLES."""
    out: list[Observable] = []
    seen: set[tuple[str, str]] = set()

    def add(kind: str, value: Any, field: str) -> None:
        n = normalize(kind, value)
        if n and (kind, n) not in seen and len(out) < MAX_OBSERVABLES:
            seen.add((kind, n))
            out.append(Observable(type=IndicatorType(kind), value=n, source_field=field))

    if src_ip:
        add("ipv4" if ":" not in src_ip else "ipv6", src_ip, "src_ip")
    raw = raw if isinstance(raw, dict) else {}
    for kind, (field,) in FIELDS:
        v = _get(raw, field)
        for item in (v if isinstance(v, list) else [v]):
            add(kind, item, field)
    log = raw.get("full_log")
    if isinstance(log, str):
        chunk = log[:TEXT_SCAN_LIMIT]
        for m in TEXT_URL.finditer(chunk):
            add("url", m.group(0).rstrip(").,;"), "full_log")
        for m in TEXT_IPV4.finditer(chunk):
            add("ipv4", m.group(0), "full_log")
        for m in TEXT_SHA256.finditer(chunk):
            add("sha256", m.group(0), "full_log")
    return out


def confidence(indicator_confidence: int, valid_from: datetime, valid_until: datetime | None, tlp: str,
               source_field: str, now: datetime) -> MatchConfidence:
    """Deterministic, conservative confidence policy:
      start at the indicator's own confidence; -30 when the indicator is older than 180 days; -50 and capped at 30
      when it is past valid_until; -15 when the observable came from free text (full_log) instead of a decoded
      field. Bands: high >= 70, medium >= 40, else low."""
    score, reasons = indicator_confidence, [f"indicator confidence {indicator_confidence}"]
    if now - valid_from > timedelta(days=180):
        score -= 30
        reasons.append("indicator older than 180 days (-30)")
    if valid_until is not None and valid_until < now:
        score = min(score - 50, 30)
        reasons.append("indicator past its valid_until (-50, capped at 30)")
    if source_field == "full_log":
        score -= 15
        reasons.append("observable taken from free text, not a decoded field (-15)")
    score = max(0, min(100, score))
    band = "high" if score >= 70 else "medium" if score >= 40 else "low"
    return MatchConfidence(score=score, band=band, reasons=reasons)


# ---------------------------------------------------------------- STIX 2.1
def stix_id_for(kind: str, value: str) -> str:
    return f"indicator--{uuid.uuid5(STIX_NS, f'novrsoc:{kind}:{value}')}"


def _ts(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")[:-4] + "Z"


def stix_indicator(row: Any) -> dict:
    value = row.value.replace("\\", "\\\\").replace("'", "\\'")
    obj = {"type": "indicator", "spec_version": "2.1", "id": row.stix_id, "created": _ts(row.imported_at),
           "modified": _ts(row.imported_at), "name": f"{row.type}: {row.value}"[:200],
           "pattern": f"[{STIX_PATH[row.type]} = '{value}']", "pattern_type": "stix", "valid_from": _ts(row.valid_from),
           "confidence": row.confidence, "object_marking_refs": [TLP_MARKING[row.tlp]],
           "external_references": [{"source_name": row.source, **({"external_id": row.source_ref} if row.source_ref else {})}]}
    if row.valid_until is not None:
        obj["valid_until"] = _ts(row.valid_until)
    return obj


def stix_bundle(objects: list[dict]) -> dict:
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


def parse_stix_bundle(bundle: Any, default_confidence: int = 50) -> tuple[list[tuple[Indicator, str, datetime | None]], list[str]]:
    """Indicators from a STIX 2.1 bundle: (indicator, source_ref, valid_until). Only `indicator` objects whose
    pattern is ONE equality comparison on a supported observable are accepted; the rest are listed as skipped."""
    found, skipped = [], []
    if not isinstance(bundle, dict) or bundle.get("type") != "bundle" or not isinstance(bundle.get("objects"), list):
        return [], ["not a STIX 2.1 bundle"]
    for obj in bundle["objects"][:5000]:
        if not isinstance(obj, dict) or obj.get("type") != "indicator":
            continue
        sid = str(obj.get("id", ""))[:120]
        if obj.get("spec_version") not in (None, "2.1") or obj.get("pattern_type", "stix") != "stix":
            skipped.append(f"{sid}: not a STIX 2.1 stix-pattern indicator")
            continue
        m = STIX_PATTERN.match(str(obj.get("pattern", "")).strip())
        if not m:
            skipped.append(f"{sid}: pattern is not a single supported equality comparison")
            continue
        kind = STIX_TYPE[m.group(1)]
        value = normalize(kind, m.group(2))
        if value is None:
            skipped.append(f"{sid}: value is not a valid {kind}")
            continue
        try:
            valid_from = datetime.fromisoformat(str(obj.get("valid_from") or obj.get("created")).replace("Z", "+00:00"))
            valid_until = (datetime.fromisoformat(str(obj["valid_until"]).replace("Z", "+00:00")) if obj.get("valid_until") else None)
        except (ValueError, TypeError):
            skipped.append(f"{sid}: invalid valid_from/valid_until")
            continue
        conf = obj.get("confidence")
        conf = conf if isinstance(conf, int) and 0 <= conf <= 100 else default_confidence
        tlp = next((k for k, v in TLP_MARKING.items() if v in (obj.get("object_marking_refs") or [])), None)
        ind = Indicator(type=IndicatorType(kind), value=value, tlp=Tlp(tlp) if tlp else Tlp.AMBER, source="stix",
                        first_seen_at=valid_from, confidence=conf)
        found.append((ind, sid, valid_until))
    return found, skipped


# ---------------------------------------------------------------- database (caller's organization context)
@dataclass
class ImportCounts:
    imported: int = 0
    unchanged: int = 0


def upsert_indicators(conn: Connection, org_id: uuid.UUID, items: Iterable[tuple[Indicator, str, datetime | None]], *,
                      source: str, tlp: str, user_id: uuid.UUID | None, label: str) -> ImportCounts:
    c = ImportCounts()
    for ind, ref, until in items:
        value = normalize(ind.type.value, ind.value)
        if value is None:
            continue
        r = conn.execute(text("""
            INSERT INTO novrsoc.ti_indicators (org_id, type, value, tlp, confidence, valid_from, valid_until, stix_id, source,
                                               source_ref, imported_by, imported_label)
            VALUES (:o, :t, :v, :tlp, :c, :vf, :vu, :sid, :src, :ref, :u, :l)
            ON CONFLICT (org_id, type, value, source) DO NOTHING RETURNING id"""),
            {"o": org_id, "t": ind.type.value, "v": value, "tlp": ind.tlp.value if ind.tlp else tlp, "c": ind.confidence,
             "vf": ind.first_seen_at, "vu": until, "sid": stix_id_for(ind.type.value, value), "src": source, "ref": ref[:300],
             "u": user_id, "l": label}).first()
        if r:
            c.imported += 1
        else:
            c.unchanged += 1
    return c


def match_alerts(conn: Connection, *, since: datetime, now: datetime | None = None, limit: int = 5000) -> tuple[int, int, int]:
    """Match the organization's indicators against its alerts observed since `since`. Returns
    (alerts scanned, observables, new matches). Idempotent: an existing match is not duplicated."""
    now = now or datetime.now(timezone.utc)
    rows = conn.execute(text("""SELECT id, host(src_ip) AS src_ip, raw FROM novrsoc.alerts
                                WHERE observed_at >= :s ORDER BY observed_at LIMIT :n"""), {"s": since, "n": limit}).all()
    scanned, n_obs, new = 0, 0, 0
    for r in rows:
        scanned += 1
        obs = extract_observables(r.raw or {}, src_ip=r.src_ip)
        n_obs += len(obs)
        if not obs:
            continue
        hits = conn.execute(text("""SELECT id, type, value, confidence, valid_from, valid_until, tlp FROM novrsoc.ti_indicators
                                    WHERE (type, value) IN (SELECT * FROM unnest(CAST(:t AS text[]), CAST(:v AS text[])))"""),
                            {"t": [o.type.value for o in obs], "v": [o.value for o in obs]}).all()
        for h in hits:
            for o in obs:
                if o.type.value != h.type or o.value != h.value:
                    continue
                conf = confidence(h.confidence, h.valid_from, h.valid_until, h.tlp, o.source_field, now)
                ins = conn.execute(text("""
                    INSERT INTO novrsoc.ti_matches (org_id, indicator_id, alert_id, observable_type, observable_value, source_field,
                                                    confidence, confidence_band, confidence_reasons)
                    VALUES (novrsoc.app_org(), :i, :a, :t, :v, :f, :c, :b, :rs)
                    ON CONFLICT (org_id, indicator_id, alert_id, source_field) DO NOTHING RETURNING id"""),
                    {"i": h.id, "a": r.id, "t": o.type.value, "v": o.value, "f": o.source_field, "c": conf.score,
                     "b": conf.band, "rs": conf.reasons}).first()
                new += 1 if ins else 0
    return scanned, n_obs, new


SEV_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


def correlate(conn: Connection, *, since: datetime, limit: int = 5000) -> list[dict]:
    """Groups of 2+ of the organization's alerts that share an observable, or the same agent and rule, since `since`."""
    rows = conn.execute(text("""SELECT id, agent_id, rule_id, severity, observed_at, host(src_ip) AS src_ip, raw
                                FROM novrsoc.alerts WHERE observed_at >= :s ORDER BY observed_at LIMIT :n"""),
                        {"s": since, "n": limit}).all()
    groups: dict[tuple[str, str], list] = {}
    for r in rows:
        keys = {("same_agent_and_rule", f"agent {r.agent_id} / rule {r.rule_id}")}
        for o in extract_observables(r.raw or {}, src_ip=r.src_ip):
            keys.add(("shared_observable", f"{o.type.value}:{o.value}"))
        for k in keys:
            groups.setdefault(k, []).append(r)
    out = []
    for (basis, key), members in sorted(groups.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        if len(members) < 2:
            continue
        out.append({"key": key, "basis": basis, "alert_ids": [m.id for m in members],
                    "first_seen_at": min(m.observed_at for m in members), "last_seen_at": max(m.observed_at for m in members),
                    "max_severity": max((m.severity for m in members), key=lambda s: SEV_RANK.get(s, 0))})
    return out[:200]
