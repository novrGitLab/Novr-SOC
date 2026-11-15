"""SLA arithmetic, shared by cases, SLA management, shift handover, posture, reports and the jobs worker.

A case receives its due times ONCE, at creation, from the organization's policy for its severity; the policy that applied
is kept in sla_policy_snapshot, so a later policy change never rewrites history. A case without a policy is `no_policy`
(never counted as met). `at_risk` = inside the escalation window before a due time (the policy's
escalate_before_minutes, or 20% of the target when that is 0).
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

SEVERITIES = ("critical", "high", "medium", "low")


def policy_for(conn: Connection, severity: str):
    return conn.execute(text("SELECT * FROM novrsoc.sla_policies WHERE severity = :s"), {"s": severity}).first()


def apply_policy(conn: Connection, case_id, severity: str, created_at: datetime) -> None:
    pol = policy_for(conn, severity)
    if pol is None:
        return
    snap = {"severity": severity, "response_minutes": pol.response_minutes, "resolution_minutes": pol.resolution_minutes,
            "escalate_before_minutes": pol.escalate_before_minutes, "escalate_to_role": pol.escalate_to_role}
    conn.execute(text("""UPDATE novrsoc.cases SET sla_response_due_at = :r, sla_resolution_due_at = :x, sla_policy_snapshot = CAST(:s AS jsonb)
                         WHERE id = :id"""),
                 {"r": created_at + timedelta(minutes=pol.response_minutes), "x": created_at + timedelta(minutes=pol.resolution_minutes),
                  "s": json.dumps(snap), "id": case_id})


def _window(snapshot: dict | None, created_at: datetime, due: datetime) -> timedelta:
    before = int((snapshot or {}).get("escalate_before_minutes") or 0)
    return timedelta(minutes=before) if before > 0 else (due - created_at) * 0.2


def state(now: datetime, created_at: datetime, due: datetime | None, done_at: datetime | None, snapshot: dict | None) -> str:
    if due is None:
        return "no_policy"
    if done_at is not None:
        return "met" if done_at <= due else "breached"
    if now > due:
        return "breached"
    return "at_risk" if due - now <= _window(snapshot, created_at, due) else "on_track"


def case_states(r, now: datetime | None = None) -> tuple[str, str]:
    """(response_state, resolution_state) for a row with the cases SLA columns."""
    now = now or datetime.now(timezone.utc)
    snap = r.sla_policy_snapshot if isinstance(r.sla_policy_snapshot, dict) else None
    return (state(now, r.created_at, r.sla_response_due_at, r.first_response_at, snap),
            state(now, r.created_at, r.sla_resolution_due_at, r.resolved_at, snap))


def overall(response: str, resolution: str) -> str:
    order = ["breached", "at_risk", "on_track", "met", "no_policy"]
    if "no_policy" in (response, resolution) and response == resolution:
        return "no_policy"
    for s in order:
        if s in (response, resolution):
            return s
    return "no_policy"


def mark_first_response(conn: Connection, case_id) -> None:
    conn.execute(text("UPDATE novrsoc.cases SET first_response_at = now() WHERE id = :id AND first_response_at IS NULL"), {"id": case_id})
