"""SOC domain logic: severity mapping and alert ingest (shared by the forwarder endpoint and local seeding)."""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.assets.reconcile import asset_for_agent
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
        body = json.dumps({"_truncated": True, "_original_bytes": len(body.encode())})
    return body


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


def ingest_alerts(conn: Connection, alerts: list[WazuhAlertIn], *, source: str) -> IngestCounts:
    """Store each alert under the ONE organization that owns its agent groups, or quarantine it.
    The organization is never taken from the payload. Idempotent: a repeated alert is a duplicate, not a copy.
    Runs inside the caller's transaction; app.org_id is set per alert (transaction-local)."""
    counts = IngestCounts()
    for a in alerts:
        org, matched = conn.execute(text("SELECT org_id, matched_orgs FROM novrsoc.org_for_agent_groups(:g)"),
                                    {"g": list(a.agent.groups)}).one()
        if org is None:
            conn.execute(text("SELECT novrsoc.quarantine_alert(:s, :x, :r, :g, CAST(:raw AS jsonb))"),
                         {"s": source, "x": a.id, "r": "ambiguous_organization" if matched > 1 else "no_organization_for_groups",
                          "g": list(a.agent.groups), "raw": _raw(a)})
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
        if inserted:
            counts.accepted += 1
            asset = asset_for_agent(conn, a.agent.id, a.agent.name)  # consolidation: one canonical asset per agent
            if asset is not None:
                conn.execute(text("UPDATE novrsoc.alerts SET asset_id = :a WHERE id = :id"), {"a": asset, "id": inserted.id})
        else:
            counts.duplicates += 1
    return counts
