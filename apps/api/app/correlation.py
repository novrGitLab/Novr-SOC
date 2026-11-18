"""SIEM <-> VMS correlation through the canonical asset inventory.

Alerts (`alerts.asset_id`) and VMS findings (`vms_findings.asset_id`) both point at the organization's canonical asset
(migration 0012). A case therefore correlates with vulnerability findings through the assets of its linked alerts: no
second inventory, no guessing by hostname. Every query runs on the caller's connection, so row-level security keeps it
inside the active organization.
"""
from __future__ import annotations

import uuid
from collections import defaultdict

from sqlalchemy import text
from sqlalchemy.engine import Connection, Row

# Findings no longer needing attention: fixed and verified, or a documented risk acceptance.
CLOSED_FINDING_STATUSES = ("verified", "risk_accepted")


def case_assets(conn: Connection, case_id: uuid.UUID) -> tuple[list[Row], dict[uuid.UUID, list[uuid.UUID]], int]:
    """The canonical assets of a case's linked alerts, the alert ids per asset, and how many linked alerts have no asset."""
    rows = conn.execute(text("""SELECT a.id, a.asset_id FROM novrsoc.case_alerts ca JOIN novrsoc.alerts a ON a.id = ca.alert_id
                                WHERE ca.case_id = :c ORDER BY a.observed_at"""), {"c": case_id}).all()
    by_asset: dict[uuid.UUID, list[uuid.UUID]] = defaultdict(list)
    unlinked = 0
    for r in rows:
        if r.asset_id is None:
            unlinked += 1
        else:
            by_asset[r.asset_id].append(r.id)
    assets = conn.execute(text("""SELECT id, display_name, criticality, exposure FROM novrsoc.assets WHERE id = ANY(:a)
                                  ORDER BY display_name"""), {"a": list(by_asset)}).all() if by_asset else []
    return assets, dict(by_asset), unlinked


def open_findings(conn: Connection, asset_ids: list[uuid.UUID], *, per_asset: int = 10) -> dict[uuid.UUID, tuple[list[Row], int]]:
    """Open VMS findings per asset, highest risk first: up to `per_asset` rows and the full count."""
    if not asset_ids:
        return {}
    rows = conn.execute(text("""
        SELECT * FROM (
          SELECT f.id, f.asset_id, f.title, f.severity, f.status, f.priority, f.risk_score, f.cves, f.port, f.last_seen_at,
                 row_number() OVER (PARTITION BY f.asset_id ORDER BY f.risk_score DESC, f.last_seen_at DESC) AS rn,
                 count(*) OVER (PARTITION BY f.asset_id) AS total
          FROM novrsoc.vms_findings f
          WHERE f.asset_id = ANY(:a) AND f.status <> ALL(:closed)) x
        WHERE x.rn <= :n ORDER BY x.asset_id, x.rn"""),
        {"a": list(asset_ids), "closed": list(CLOSED_FINDING_STATUSES), "n": per_asset}).all()
    out: dict[uuid.UUID, tuple[list[Row], int]] = {}
    for r in rows:
        items, _ = out.get(r.asset_id, ([], 0))
        items.append(r)
        out[r.asset_id] = (items, r.total)
    return out


def findings_line(rows: list[Row]) -> str:
    """One evidence line for NHAI: priority, severity, title, status and CVEs of each finding."""
    return "; ".join(f"{r.priority} {r.severity} '{r.title}'" + (f" port {r.port}" if r.port else "")
                     + f" ({r.status}; CVEs: {', '.join(r.cves) or 'none'})" for r in rows)
