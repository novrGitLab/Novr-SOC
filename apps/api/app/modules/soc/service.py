"""SOC domain logic: severity mapping and alert ingest (shared by the forwarder endpoint and local seeding)."""
from __future__ import annotations

import ipaddress
import json
import uuid
from dataclasses import dataclass, field

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.assets.reconcile import asset_for_agent
from app.secops.log_sources import MANAGER_AGENT_IDS, classify_location
from novrsoc_contracts.v1.soc import WazuhAlertIn

RAW_CAP_BYTES = 32 * 1024
# Ported from NovrSOC@5054be3:backend/src/lib/severity.ts (SEVERITY_MIN_LEVEL), the one Wazuh level mapping.
SEVERITY_MIN_LEVEL = {"critical": 13, "high": 10, "medium": 7, "low": 0}


def severity_from_level(level: int) -> str:
    for sev in ("critical", "high", "medium"):
        if level >= SEVERITY_MIN_LEVEL[sev]:
            return sev
    return "low"


def _raw(alert: WazuhAlertIn) -> str:
    body = json.dumps(alert.raw or {}, default=str)
    if len(body.encode()) > RAW_CAP_BYTES:
        # keep the source location: it is what attributes (or quarantines) a manager-received event
        body = json.dumps({"_truncated": True, "_original_bytes": len(body.encode()),
                           "location": str((alert.raw or {}).get("location") or "")[:300]})
    return body


@dataclass(frozen=True)
class Attribution:
    """Installation-wide ownership rules (from Settings), never from the payload.
    collection_groups: agent groups that only COLLECT agents (Wazuh `default`): membership never establishes an owner,
      and a mapping of such a group is ignored. An agent with only collection groups is quarantined.
    platform_org: owner of the Wazuh manager's own telemetry (agent 000, not a registered source); None quarantines it."""
    collection_groups: frozenset[str] = field(default_factory=lambda: frozenset({"default"}))
    platform_org: uuid.UUID | None = None


DEFAULT_ATTRIBUTION = Attribution()


def _manager_source(conn: Connection, alert: WazuhAlertIn):
    """(source row, None) for a manager-received event from a live, enabled source; (None, quarantine reason) otherwise.
    The manager's own events return (None, 'manager_local_event'); the caller decides whether the platform owns them."""
    kind, value = classify_location(str((alert.raw or {}).get("location") or ""))
    if kind == "manager_local":
        return None, "manager_local_event"
    row = conn.execute(text("SELECT * FROM novrsoc.log_source_for(:k, :v)"), {"k": kind, "v": value}).first()
    if row is None:
        return None, "unknown_log_source"
    if not row.enabled or row.org_status == "archived":
        return None, "log_source_disabled"
    return row, None


def _ip(v: str | None) -> str | None:
    try:
        return str(ipaddress.ip_address(v)) if v else None
    except ValueError:
        return None


@dataclass
class IngestCounts:
    accepted: int = 0
    duplicates: int = 0
    quarantined: int = 0


def resolve_owner(conn: Connection, a: WazuhAlertIn, attr: Attribution = DEFAULT_ATTRIBUTION):
    """(org_id, log source row, None) for the ONE organization that owns the alert, or (None, None, quarantine reason).
    The single ownership decision, shared by ingest and its dry run (classify_alerts).
      * agent 000: a registered, enabled syslog/agentless source's organization; the manager's own telemetry belongs to
        the platform organization (attr.platform_org) or is quarantined; anything else is quarantined;
      * any other agent: the ONE organization mapping its groups, collection groups (attr.collection_groups) left out.
        Only collection groups -> quarantined (collection_group_only), whichever organization maps such a group."""
    if a.agent.id in MANAGER_AGENT_IDS:
        src, reason = _manager_source(conn, a)
        if src is not None:
            return src.org_id, src, None
        if reason == "manager_local_event" and attr.platform_org is not None:
            return attr.platform_org, None, None
        return None, None, reason
    groups = [g for g in a.agent.groups if g not in attr.collection_groups]
    if not groups:
        return None, None, "collection_group_only" if a.agent.groups else "no_organization_for_groups"
    org, matched = conn.execute(text("SELECT org_id, matched_orgs FROM novrsoc.org_for_agent_groups(:g)"), {"g": groups}).one()
    if org is None:
        return None, None, "ambiguous_organization" if matched > 1 else "no_organization_for_groups"
    return org, None, None


def classify_alerts(conn: Connection, alerts: list[WazuhAlertIn], *, source: str,
                    attr: Attribution = DEFAULT_ATTRIBUTION) -> list[dict]:
    """What ingest WOULD do with each alert, without storing anything: the owner (or quarantine reason) and whether the
    alert is already stored for that owner. Reads only; app.org_id is set per alert (transaction-local)."""
    out = []
    for a in alerts:
        org, src, reason = resolve_owner(conn, a, attr)
        if org is None:
            out.append({"id": a.id, "verdict": "quarantine", "reason": reason})
            continue
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
        r = conn.execute(text("""SELECT o.slug::text AS slug, EXISTS (SELECT 1 FROM novrsoc.alerts x WHERE x.org_id = :o AND x.source = :s
                                 AND x.external_id = :x) AS stored FROM novrsoc.organizations o WHERE o.id = :o"""),
                         {"o": org, "s": source, "x": a.id}).one()
        out.append({"id": a.id, "verdict": "duplicate" if r.stored else "new", "org_id": org, "org_slug": r.slug,
                    "log_source_id": src.id if src is not None else None})
    return out


def ingest_alerts(conn: Connection, alerts: list[WazuhAlertIn], *, source: str,
                  attr: Attribution = DEFAULT_ATTRIBUTION) -> IngestCounts:
    """Store each alert under the ONE organization that owns it, or quarantine it.
    * an agent's alert: the organization that maps its agent groups (exactly one);
    * an event the Wazuh manager received itself (agent 000: remote syslog, agentless): the organization of the live,
      enabled registration of its source (app.secops.log_sources); agent 000's groups are never used.
    The organization is never taken from the payload. Idempotent: a repeated alert is a duplicate, not a copy.
    Runs inside the caller's transaction; app.org_id is set per alert (transaction-local)."""
    counts = IngestCounts()
    for a in alerts:
        org, src, reason = resolve_owner(conn, a, attr)
        if org is None:
            conn.execute(text("SELECT novrsoc.quarantine_alert(:s, :x, :r, :g, CAST(:raw AS jsonb))"),
                         {"s": source, "x": a.id, "r": reason, "g": list(a.agent.groups), "raw": _raw(a)})
            counts.quarantined += 1
            continue
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
        inserted = conn.execute(text("""
            INSERT INTO novrsoc.alerts (org_id, source, external_id, rule_id, rule_level, rule_description, severity,
                                        agent_id, agent_name, agent_groups, src_ip, mitre_techniques, observed_at, raw)
            VALUES (:org, :src, :xid, :rid, :lvl, :desc, :sev, :aid, :aname, :groups, CAST(:ip AS inet), :mitre, :ts,
                    CAST(:raw AS jsonb))
            ON CONFLICT (org_id, source, external_id) DO NOTHING RETURNING id"""),
            {"org": org, "src": source, "xid": a.id, "rid": a.rule.id, "lvl": a.rule.level,
             "desc": a.rule.description[:1000], "sev": severity_from_level(a.rule.level), "aid": a.agent.id,
             "aname": a.agent.name, "groups": list(a.agent.groups), "ip": _ip(a.src_ip),
             "mitre": list(a.rule.mitre_ids), "ts": a.timestamp, "raw": _raw(a)}).first()
        if inserted and src is not None:
            counts.accepted += 1
            conn.execute(text("UPDATE novrsoc.alerts SET log_source_id = :s, asset_id = :a WHERE id = :id"),
                         {"s": src.id, "a": src.asset_id, "id": inserted.id})
            conn.execute(text("""UPDATE novrsoc.log_sources SET event_count = event_count + 1,
                                 last_event_at = GREATEST(coalesce(last_event_at, :ts), :ts) WHERE id = :s"""),
                         {"s": src.id, "ts": a.timestamp})
        elif inserted:
            counts.accepted += 1
            asset = asset_for_agent(conn, a.agent.id, a.agent.name)  # consolidation: one canonical asset per agent
            if asset is not None:
                conn.execute(text("UPDATE novrsoc.alerts SET asset_id = :a WHERE id = :id"), {"a": asset, "id": inserted.id})
        else:
            counts.duplicates += 1
    return counts
