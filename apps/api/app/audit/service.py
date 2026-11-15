"""Audit events. Written in their OWN transaction so a denial is recorded even when the request
fails and its transaction rolls back. The table is append-only (trigger) and readable only within
its organization (RLS)."""
from __future__ import annotations

import ipaddress
import json
import logging
import uuid
from typing import Any, Literal

from sqlalchemy import text

from app.db.session import set_context, transaction

log = logging.getLogger("novrsoc.audit")

Outcome = Literal["success", "denied", "failure"]


def record(action: str, outcome: Outcome, *, org_id: uuid.UUID | None = None, actor_type: str = "user",
           actor_id: uuid.UUID | None = None, actor_label: str = "", resource_type: str = "",
           resource_id: str = "", request_id: str = "", ip: str | None = None,
           details: dict[str, Any] | None = None) -> None:
    try:
        ip = str(ipaddress.ip_address(ip)) if ip else None
    except ValueError:  # e.g. a non-IP peer name from a proxy or test client: never fail the audit write
        ip = None
    try:
        with transaction() as conn:
            if org_id is not None:
                set_context(conn, org_id=org_id)
            conn.execute(text("""
                INSERT INTO novrsoc.audit_events
                  (org_id, actor_type, actor_id, actor_label, action, outcome, resource_type, resource_id,
                   request_id, ip, details)
                VALUES (:org, :atype, :aid, :alabel, :action, :outcome, :rtype, :rid, :req, CAST(:ip AS inet),
                        CAST(:details AS jsonb))"""),
                {"org": org_id, "atype": actor_type, "aid": actor_id, "alabel": actor_label[:200], "action": action,
                 "outcome": outcome, "rtype": resource_type, "rid": resource_id[:200], "req": request_id,
                 "ip": ip, "details": json.dumps(details or {}, default=str)})
    except Exception as exc:  # audit failure must be visible, never silent
        log.error("audit write failed action=%s outcome=%s error=%s", action, outcome, type(exc).__name__)
        raise
