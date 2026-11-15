"""Asset reconciliation: every source reports observations; each becomes (or updates) ONE canonical asset.

Rules (deterministic, tested in tests/modules/assets):
  1. Identifiers are normalized (lower-case names, canonical IP/MAC text, Wazuh agent ids as digits).
  2. Addresses are site-scoped: an IP's site_key is the site that contains it (or the site the source named), else ''.
  3. STRONG identifiers (Wazuh agent, MAC, cloud id, serial, FQDN, domain, URL) decide first. If they point at more
     than one asset, the oldest wins and every other binding is recorded as an `identifier_conflict` (never moved).
  4. Only when no strong identifier matches do WEAK identifiers (hostname, IP) match, and a weak candidate is refused
     when it already holds a DIFFERENT strong identifier of a kind the observation also has (e.g. another Wazuh agent
     id on a reused DHCP address): that observation is a different asset.
  5. A new identifier is bound to the chosen asset; an identifier already bound to another asset is a conflict.
  6. Attributes fill gaps; Wazuh is authoritative for the operating system of its own agents.
Runs inside the caller's transaction and organization context (RLS); no organization argument is ever trusted.
"""
from __future__ import annotations

import ipaddress
import json
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

STRONG = ("wazuh_agent", "mac", "cloud_id", "serial", "fqdn", "domain", "url")
WEAK = ("hostname", "ip")
_HOST = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")
_FQDN = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$")
_MAC = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$")


@dataclass
class Observation:
    source: str
    kind: str
    display_name: str
    identifiers: list[tuple[str, str]]
    site_id: uuid.UUID | None = None
    attributes: dict = field(default_factory=dict)
    services: list[dict] = field(default_factory=list)


@dataclass
class Outcome:
    asset_id: uuid.UUID
    created: bool = False
    updated: bool = False
    conflicts: int = 0


def normalize(kind: str, value: str | None) -> str | None:
    v = (value or "").strip().lower().rstrip(".")
    if not v:
        return None
    if kind == "wazuh_agent":
        return v if re.fullmatch(r"\d{3,6}", v) else None
    if kind == "ip":
        try:
            return str(ipaddress.ip_address(v))
        except ValueError:
            return None
    if kind == "mac":
        return v.replace("-", ":") if _MAC.match(v) else None
    if kind == "hostname":
        short = v.split(".", 1)[0]
        return short if _HOST.match(short) else None
    if kind in ("fqdn", "domain"):
        return v if _FQDN.match(v) and len(v) <= 253 else None
    if kind == "url":
        return v[:300] if v.startswith(("http://", "https://")) else None
    return v[:300]


def host_identifiers(value: str) -> list[tuple[str, str]]:
    """Identifiers for a scanner or alert 'host' string: an IP, or an FQDN plus its short hostname."""
    v = (value or "").strip().lower()
    try:
        return [("ip", str(ipaddress.ip_address(v)))]
    except ValueError:
        pass
    out = []
    if normalize("fqdn", v):
        out.append(("fqdn", v))
    if normalize("hostname", v):
        out.append(("hostname", v.split(".", 1)[0]))
    return out


def _site_key(conn: Connection, kind: str, value: str, site_id: uuid.UUID | None) -> str:
    if kind != "ip":
        return ""
    if site_id is not None:
        return str(site_id)
    hit = conn.execute(text("""SELECT id FROM novrsoc.sites WHERE CAST(:ip AS inet) <<= ANY(network_cidrs)
                               ORDER BY created_at LIMIT 1"""), {"ip": value}).scalar()
    return str(hit) if hit else ""


def _event(conn: Connection, asset_id: uuid.UUID, kind: str, source: str, actor: str, details: dict) -> None:
    conn.execute(text("""INSERT INTO novrsoc.asset_events (org_id, asset_id, kind, source, actor_label, details)
                         VALUES (novrsoc.app_org(), :a, :k, :s, :l, CAST(:d AS jsonb))"""),
                 {"a": asset_id, "k": kind, "s": source, "l": actor[:200], "d": json.dumps(details, default=str)})


def _resolve(conn: Connection, asset_id: uuid.UUID) -> uuid.UUID:
    """Follow merges to the surviving asset (bounded)."""
    for _ in range(10):
        nxt = conn.execute(text("SELECT merged_into FROM novrsoc.assets WHERE id = :i"), {"i": asset_id}).scalar()
        if nxt is None:
            return asset_id
        asset_id = nxt
    return asset_id


def upsert(conn: Connection, obs: Observation, actor: str = "") -> Outcome:
    now = datetime.now(timezone.utc)
    ids: list[tuple[str, str, str]] = []
    for kind, value in obs.identifiers:
        n = normalize(kind, value)
        if n is not None:
            key = (kind, n, _site_key(conn, kind, n, obs.site_id))
            if key not in ids:
                ids.append(key)
    if not ids:
        raise ValueError("an observation needs at least one valid identifier")
    rows = conn.execute(text("""SELECT i.kind, i.value, i.site_key, i.asset_id, a.first_seen_at FROM novrsoc.asset_identifiers i
                                JOIN novrsoc.assets a ON a.id = i.asset_id
                                WHERE (i.kind, i.value, i.site_key) IN (SELECT * FROM unnest(CAST(:k AS text[]), CAST(:v AS text[]), CAST(:s AS text[])))"""),
                        {"k": [i[0] for i in ids], "v": [i[1] for i in ids], "s": [i[2] for i in ids]}).all()
    bound = {(r.kind, r.value, r.site_key): _resolve(conn, r.asset_id) for r in rows}
    first_seen = {}
    for r in rows:
        first_seen[bound[(r.kind, r.value, r.site_key)]] = r.first_seen_at

    strong = sorted({bound[k] for k in bound if k[0] in STRONG}, key=lambda a: first_seen.get(a, now))
    target = strong[0] if strong else None
    if target is None:
        weak = [bound[k] for k in ids if k in bound and k[0] in WEAK]
        obs_strong = {(k, v) for k, v, _ in ids if k in STRONG}
        for cand in sorted(dict.fromkeys(weak), key=lambda a: (0 if any(k[0] == "hostname" and bound.get(k) == a for k in ids) else 1,
                                                                first_seen.get(a, now))):
            held = conn.execute(text(f"SELECT kind, value FROM novrsoc.asset_identifiers WHERE asset_id = :a AND kind IN ({', '.join(repr(s) for s in STRONG)})"),
                                {"a": cand}).all()
            clash = any(k == hk and v != hv for k, v in obs_strong for hk, hv in held)
            if not clash:
                target = cand
                break

    out = Outcome(asset_id=target) if target else None
    a = obs.attributes
    if target is None:
        target = conn.execute(text("""
            INSERT INTO novrsoc.assets (org_id, site_id, kind, display_name, hostname, fqdn, primary_ip, mac_address, os_platform,
                                        os_name, os_version, classification, criticality, exposure, owner, tags)
            VALUES (novrsoc.app_org(), :site, :kind, :name, :host, :fqdn, CAST(:ip AS inet), CAST(:mac AS macaddr), :osp, :osn, :osv,
                    :cls, :crit, :exp, :owner, :tags) RETURNING id"""),
            {"site": obs.site_id, "kind": obs.kind, "name": obs.display_name[:200] or ids[0][1], "host": a.get("hostname"),
             "fqdn": a.get("fqdn"), "ip": a.get("primary_ip"), "mac": a.get("mac_address"), "osp": a.get("os_platform"),
             "osn": a.get("os_name"), "osv": a.get("os_version"), "cls": a.get("classification", "unclassified"),
             "crit": a.get("criticality", "medium"), "exp": a.get("exposure", "unknown"), "owner": a.get("owner", ""),
             "tags": a.get("tags", [])}).scalar()
        out = Outcome(asset_id=target, created=True)
        _event(conn, target, "discovered", obs.source, actor, {"identifiers": [f"{k}={v}" for k, v, _ in ids]})
    else:
        wazuh = obs.source == "wazuh"
        conn.execute(text("""
            UPDATE novrsoc.assets SET last_seen_at = greatest(last_seen_at, now()), updated_at = now(),
              hostname = coalesce(hostname, :host), fqdn = coalesce(fqdn, :fqdn),
              primary_ip = coalesce(primary_ip, CAST(:ip AS inet)), mac_address = coalesce(mac_address, CAST(:mac AS macaddr)),
              os_platform = CASE WHEN :wazuh AND CAST(:osp AS text) IS NOT NULL THEN :osp ELSE coalesce(os_platform, :osp) END,
              os_name = CASE WHEN :wazuh AND CAST(:osn AS text) IS NOT NULL THEN :osn ELSE coalesce(os_name, :osn) END,
              os_version = CASE WHEN :wazuh AND CAST(:osv AS text) IS NOT NULL THEN :osv ELSE coalesce(os_version, :osv) END,
              site_id = coalesce(site_id, :site)
            WHERE id = :id"""),
            {"id": target, "host": a.get("hostname"), "fqdn": a.get("fqdn"), "ip": a.get("primary_ip"), "mac": a.get("mac_address"),
             "osp": a.get("os_platform"), "osn": a.get("os_name"), "osv": a.get("os_version"), "wazuh": wazuh, "site": obs.site_id})
        out.updated = True

    added = []
    for key in ids:
        owner = bound.get(key)
        if owner is None:
            r = conn.execute(text("""INSERT INTO novrsoc.asset_identifiers (org_id, asset_id, kind, value, site_key, sources)
                                     VALUES (novrsoc.app_org(), :a, :k, :v, :s, ARRAY[CAST(:src AS text)])
                                     ON CONFLICT (org_id, kind, value, site_key) DO NOTHING RETURNING id"""),
                             {"a": target, "k": key[0], "v": key[1], "s": key[2], "src": obs.source}).first()
            if r is not None:
                if not out.created:
                    added.append(f"{key[0]}={key[1]}")
                continue
            owner = _resolve(conn, conn.execute(text("""SELECT asset_id FROM novrsoc.asset_identifiers
                                                        WHERE kind = :k AND value = :v AND site_key = :s"""),
                                                {"k": key[0], "v": key[1], "s": key[2]}).scalar())
        if owner == target:
            conn.execute(text("""UPDATE novrsoc.asset_identifiers SET last_seen_at = now(),
                                   sources = CASE WHEN :src = ANY(sources) THEN sources ELSE sources || CAST(:src AS text) END
                                 WHERE kind = :k AND value = :v AND site_key = :s"""),
                         {"k": key[0], "v": key[1], "s": key[2], "src": obs.source})
        else:
            out.conflicts += 1
            _event(conn, target, "identifier_conflict", obs.source, actor,
                   {"identifier_kind": key[0], "identifier_value": key[1], "site_key": key[2], "bound_to": str(owner)})
    if added:
        _event(conn, target, "identifier_added", obs.source, actor, {"identifiers": added})

    for s in obs.services:
        r = conn.execute(text("""
            INSERT INTO novrsoc.asset_services (org_id, asset_id, port, protocol, name, product, version, source)
            VALUES (novrsoc.app_org(), :a, :port, :proto, :name, :product, :version, :src)
            ON CONFLICT (asset_id, port, protocol, product) DO UPDATE SET last_seen_at = now(),
              version = CASE WHEN EXCLUDED.version <> '' THEN EXCLUDED.version ELSE asset_services.version END,
              name = CASE WHEN EXCLUDED.name <> '' THEN EXCLUDED.name ELSE asset_services.name END
            RETURNING (xmax = 0) AS inserted"""),
            {"a": target, "port": int(s.get("port") or 0), "proto": s.get("protocol") or "", "name": (s.get("name") or "")[:120],
             "product": (s.get("product") or "")[:200], "version": (s.get("version") or "")[:100], "src": obs.source}).one()
        if r.inserted:
            _event(conn, target, "service_seen", obs.source, actor,
                   {"port": s.get("port"), "protocol": s.get("protocol"), "product": s.get("product") or s.get("name")})
    return out


def asset_for_agent(conn: Connection, agent_id: str, agent_name: str = "", ip: str | None = None) -> uuid.UUID | None:
    """The canonical asset of a Wazuh agent (created from the alert when the agent is not yet in the inventory)."""
    if normalize("wazuh_agent", agent_id) is None:
        return None
    hit = conn.execute(text("SELECT asset_id FROM novrsoc.asset_identifiers WHERE kind = 'wazuh_agent' AND value = :v AND site_key = ''"),
                       {"v": agent_id}).scalar()
    if hit is not None:
        return _resolve(conn, hit)
    ids = [("wazuh_agent", agent_id)]
    if agent_name:
        ids.append(("hostname", agent_name))
    return upsert(conn, Observation(source="wazuh", kind="host", display_name=agent_name or f"agent {agent_id}", identifiers=ids,
                                    attributes={"hostname": normalize("hostname", agent_name)}), "alert ingest").asset_id


def merge(conn: Connection, target: uuid.UUID, source: uuid.UUID, reason: str, actor: str) -> None:
    conn.execute(text("UPDATE novrsoc.asset_identifiers SET asset_id = :t WHERE asset_id = :s"), {"t": target, "s": source})
    conn.execute(text("""INSERT INTO novrsoc.asset_services (org_id, asset_id, port, protocol, name, product, version, source, first_seen_at, last_seen_at)
                         SELECT org_id, :t, port, protocol, name, product, version, source, first_seen_at, last_seen_at
                         FROM novrsoc.asset_services WHERE asset_id = :s ON CONFLICT (asset_id, port, protocol, product) DO NOTHING"""),
                 {"t": target, "s": source})
    moved_f = conn.execute(text("UPDATE novrsoc.vms_findings SET asset_id = :t WHERE asset_id = :s"), {"t": target, "s": source}).rowcount
    moved_a = conn.execute(text("UPDATE novrsoc.alerts SET asset_id = :t WHERE asset_id = :s"), {"t": target, "s": source}).rowcount
    if conn.execute(text("SELECT 1 FROM novrsoc.cnii_monitored_assets WHERE asset_id = :t"), {"t": target}).first() is None:
        conn.execute(text("UPDATE novrsoc.cnii_monitored_assets SET asset_id = :t WHERE asset_id = :s"), {"t": target, "s": source})
    conn.execute(text("""UPDATE novrsoc.assets SET status = 'retired', merged_into = :t, updated_at = now() WHERE id = :s"""),
                 {"t": target, "s": source})
    conn.execute(text("""UPDATE novrsoc.assets t SET first_seen_at = least(t.first_seen_at, s.first_seen_at),
                           last_seen_at = greatest(t.last_seen_at, s.last_seen_at), updated_at = now(),
                           hostname = coalesce(t.hostname, s.hostname), fqdn = coalesce(t.fqdn, s.fqdn),
                           primary_ip = coalesce(t.primary_ip, s.primary_ip), mac_address = coalesce(t.mac_address, s.mac_address)
                         FROM novrsoc.assets s WHERE t.id = :t AND s.id = :s"""), {"t": target, "s": source})
    _event(conn, target, "merged", "manual", actor, {"merged_asset": str(source), "reason": reason, "findings": moved_f, "alerts": moved_a})
    _event(conn, source, "merged", "manual", actor, {"merged_into": str(target), "reason": reason})


def link_unlinked(conn: Connection, limit: int = 500) -> int:
    """Link stored alerts and VMS findings that have no canonical asset yet (records from before the inventory, or
    whose host could not be reconciled at ingest). Bounded per call; used by the jobs worker."""
    n = 0
    for r in conn.execute(text("""SELECT DISTINCT agent_id, agent_name FROM novrsoc.alerts WHERE asset_id IS NULL AND agent_id <> ''
                                  LIMIT :n"""), {"n": limit}).all():
        aid = asset_for_agent(conn, r.agent_id, r.agent_name)
        if aid:
            n += conn.execute(text("UPDATE novrsoc.alerts SET asset_id = :a WHERE agent_id = :g AND asset_id IS NULL"),
                              {"a": aid, "g": r.agent_id}).rowcount
    for r in conn.execute(text("SELECT DISTINCT host FROM novrsoc.vms_findings WHERE asset_id IS NULL LIMIT :n"), {"n": limit}).all():
        ids = host_identifiers(r.host)
        if not ids:
            continue
        aid = upsert(conn, Observation(source="vms", kind="host", display_name=r.host, identifiers=ids,
                                       attributes={"primary_ip": normalize("ip", r.host), "fqdn": normalize("fqdn", r.host)}), "jobs worker").asset_id
        n += conn.execute(text("UPDATE novrsoc.vms_findings SET asset_id = :a WHERE host = :h AND asset_id IS NULL"), {"a": aid, "h": r.host}).rowcount
    return n
