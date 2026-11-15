"""STIX 2.1 object store for one organization (runs under the caller's organization context; RLS applies).

ingest_bundle(): validates every object with novrsoc_contracts.stix21 (shared with the Server 1 service), stores the
valid ones (idempotent per (id, modified)), imports single-comparison indicators into the matching engine with the
bundle's provenance, keeps relationships queryable (source_ref / target_ref), and records a feed run.
related(): one-hop relationship context of an object (e.g. indicator --indicates--> malware), used by the UI and by
NHAI evidence. Names come only from stored objects; nothing is inferred.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.insights import engine
from novrsoc_contracts import stix21


def ingest_bundle(conn: Connection, org_id: uuid.UUID, bundle: dict, *, source: str, collection: str = "",
                  user_id: uuid.UUID | None = None, label: str = "") -> dict:
    objects, rejected = stix21.normalize_bundle(bundle)
    stored = rels = 0
    for o in objects:
        r = conn.execute(text("""
            INSERT INTO novrsoc.ti_stix_objects (org_id, stix_id, type, modified, source_ref, target_ref, relationship_type, object, source)
            VALUES (:org, :id, :t, :m, :s, :tg, :rt, CAST(:obj AS jsonb), :src)
            ON CONFLICT (org_id, stix_id, modified) DO NOTHING RETURNING id"""),
            {"org": org_id, "id": o["id"], "t": o["type"], "m": datetime.fromisoformat((o.get("modified") or o["created"]).replace("Z", "+00:00")),
             "s": o.get("source_ref"), "tg": o.get("target_ref"), "rt": o.get("relationship_type"), "obj": json.dumps(o), "src": source}).first()
        stored += 1 if r else 0
        rels += 1 if (r and o["type"] == "relationship") else 0
    parsed, skipped = engine.parse_stix_bundle({"type": "bundle", "objects": [o for o in objects if o["type"] == "indicator"]})
    counts = engine.upsert_indicators(conn, org_id, [(i.model_copy(update={"source": source}), ref, until) for i, ref, until in parsed],
                                      source=source, tlp="amber", user_id=user_id, label=label or source)
    rejected = rejected + skipped
    conn.execute(text("""INSERT INTO novrsoc.ti_feed_runs (org_id, source, collection, objects_received, objects_stored, indicators_imported, rejected)
                         VALUES (:o, :s, :c, :n, :st, :i, :r)"""),
                 {"o": org_id, "s": source, "c": collection[:200], "n": len((bundle or {}).get("objects") or []), "st": stored,
                  "i": counts.imported, "r": len(rejected)})
    return {"objects_received": len((bundle or {}).get("objects") or []), "objects_stored": stored, "indicators_imported": counts.imported,
            "relationships": rels, "rejected": rejected[:200]}


def related(conn: Connection, stix_id: str) -> list[dict]:
    rows = conn.execute(text("""
        SELECT DISTINCT ON (other.stix_id) r.relationship_type, other.stix_id, other.type, other.object ->> 'name' AS name,
               CASE WHEN r.source_ref = :id THEN 'outgoing' ELSE 'incoming' END AS edge
        FROM novrsoc.ti_stix_objects r
        JOIN novrsoc.ti_stix_objects other ON other.org_id = r.org_id
             AND other.stix_id = CASE WHEN r.source_ref = :id THEN r.target_ref ELSE r.source_ref END
        WHERE r.type = 'relationship' AND (r.source_ref = :id OR r.target_ref = :id)
        ORDER BY other.stix_id, other.modified DESC"""), {"id": stix_id}).all()
    return [{"stix_id": r.stix_id, "type": r.type, "name": r.name or r.stix_id, "relationship_type": r.relationship_type, "edge": r.edge}
            for r in rows]


def indicator_stix_ids(conn: Connection, ind_type: str, value: str) -> list[str]:
    """STIX ids of stored indicator objects whose single-comparison pattern names exactly this normalized value."""
    rows = conn.execute(text("""SELECT DISTINCT stix_id, object ->> 'pattern' AS pattern FROM novrsoc.ti_stix_objects
                                WHERE type = 'indicator' AND strpos(object ->> 'pattern', :v) > 0"""), {"v": value}).all()
    out = []
    for r in rows:
        m = engine.STIX_PATTERN.match((r.pattern or "").strip())
        if m and engine.STIX_TYPE[m.group(1)] == ind_type and engine.normalize(ind_type, m.group(2)) == value:
            out.append(r.stix_id)
    return out
