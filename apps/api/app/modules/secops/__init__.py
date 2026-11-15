"""Security operations (consolidation; workstream A): SLA management, shift handover, notifications.

SLA: policies per severity (sla:manage), live status of open cases, historical performance, and escalation (cases at
risk or breached are marked once and the policy's escalation role is notified). The jobs worker runs the same
escalation periodically; it can also be run on demand.
Shift handover: the queue is frozen into the handover when it is written (unresolved alerts, open cases, pending
approvals, SLA risk); another analyst acknowledges it. Acknowledgement by the author is refused (database CHECK too).
"""
from __future__ import annotations

import json
import statistics
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import activity
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, current_principal, require
from app.core.errors import ApiError, forbidden, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from app.secops import sla
from novrsoc_contracts.v1.common import ActorRef
from novrsoc_contracts.v1.secops import (CaseSlaView, EscalationResult, HandoverAcknowledge, HandoverAlert, HandoverApproval, HandoverCase,
                                         HandoverCreate, HandoverDraft, HandoverList, HandoverSnapshot, HandoverView, NotificationList,
                                         NotificationView, SlaPerformance, SlaPerformanceRow, SlaPolicyList, SlaPolicySet, SlaPolicyView,
                                         SlaStatus, SlaWeek, UserRef)

MODULE = ModuleInfo(name="secops", workstream="A", prefix="/api/v1/secops",
                    summary="SLA management, shift handover and notifications")
router = APIRouter(prefix="/api/v1/secops", tags=["secops"], responses=ERRORS)

_CASE_SLA_SQL = """SELECT c.id, c.number, c.title, c.severity, c.status, c.created_at, c.sla_response_due_at, c.sla_resolution_due_at,
                          c.first_response_at, c.resolved_at, c.escalated_at, c.sla_policy_snapshot,
                          (SELECT u.email::text FROM novrsoc.users u WHERE u.id = c.assignee_id) AS assignee_label
                   FROM novrsoc.cases c"""


def _now() -> datetime:
    return datetime.now(timezone.utc)


def case_sla(r, now: datetime | None = None) -> CaseSlaView:
    resp, res = sla.case_states(r, now)
    return CaseSlaView(case_id=r.id, reference=f"CASE-{r.number:06d}", title=r.title, severity=r.severity, status=r.status,
                       assignee_label=r.assignee_label, created_at=r.created_at, response_due_at=r.sla_response_due_at,
                       resolution_due_at=r.sla_resolution_due_at, first_response_at=r.first_response_at, resolved_at=r.resolved_at,
                       response_state=resp, resolution_state=res, escalated_at=r.escalated_at)


def open_case_slas(conn: Connection) -> list[CaseSlaView]:
    now = _now()
    return [case_sla(r, now) for r in conn.execute(text(_CASE_SLA_SQL + " WHERE c.status IN ('open', 'in_progress') ORDER BY c.created_at"))]


# ---------------------------------------------------------------- SLA policies
@router.get("/sla/policies", response_model=SlaPolicyList, summary="SLA policies of the organization (one per severity)")
def get_policies(p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> SlaPolicyList:
    rows = conn.execute(text("""SELECT * FROM novrsoc.sla_policies ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                WHEN 'medium' THEN 2 ELSE 3 END""")).all()
    return SlaPolicyList(items=[SlaPolicyView(severity=r.severity, response_minutes=r.response_minutes, resolution_minutes=r.resolution_minutes,
                                              escalate_before_minutes=r.escalate_before_minutes, escalate_to_role=r.escalate_to_role,
                                              updated_at=r.updated_at) for r in rows])


@router.put("/sla/policies", response_model=SlaPolicyList, summary="Set SLA policies (applies to cases created from now on)")
def set_policies(body: SlaPolicySet, request: Request, p: Principal = Depends(require("sla:manage")),
                 conn: Connection = Depends(request_connection)) -> SlaPolicyList:
    for pol in body.policies:
        conn.execute(text("""INSERT INTO novrsoc.sla_policies (org_id, severity, response_minutes, resolution_minutes, escalate_before_minutes,
                                                               escalate_to_role, updated_by)
                             VALUES (:o, :s, :r, :x, :e, :role, :u)
                             ON CONFLICT (org_id, severity) DO UPDATE SET response_minutes = EXCLUDED.response_minutes,
                               resolution_minutes = EXCLUDED.resolution_minutes, escalate_before_minutes = EXCLUDED.escalate_before_minutes,
                               escalate_to_role = EXCLUDED.escalate_to_role, updated_by = EXCLUDED.updated_by, updated_at = now()"""),
                     {"o": p.org_id, "s": pol.severity, "r": pol.response_minutes, "x": pol.resolution_minutes, "e": pol.escalate_before_minutes,
                      "role": pol.escalate_to_role, "u": p.user_id})
    audit.record("SLA_POLICY_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="sla_policy",
                 request_id=request.state.request_id, ip=client_ip(request), details=body.model_dump(mode="json"))
    return get_policies(p, conn)


@router.get("/sla/status", response_model=SlaStatus, summary="SLA state of every open case")
def sla_status(p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> SlaStatus:
    items = open_case_slas(conn)
    counts: dict[str, int] = {}
    for i in items:
        k = sla.overall(i.response_state, i.resolution_state)
        counts[k] = counts.get(k, 0) + 1
    n = conn.execute(text("SELECT count(*) FROM novrsoc.sla_policies")).scalar()
    rank = {"breached": 0, "at_risk": 1, "on_track": 2, "met": 3, "no_policy": 4}
    items.sort(key=lambda i: (rank[sla.overall(i.response_state, i.resolution_state)], i.resolution_due_at or i.created_at))
    return SlaStatus(generated_at=_now(), policies_configured=n, items=items, counts=counts)


@router.get("/sla/performance", response_model=SlaPerformance, summary="Historical SLA performance (cases created in the period)")
def sla_performance(days: int = Query(30, ge=7, le=365), p: Principal = Depends(require("cases:read")),
                    conn: Connection = Depends(request_connection)) -> SlaPerformance:
    return performance(conn, days)


def performance(conn: Connection, days: int) -> SlaPerformance:
    now = _now()
    rows = conn.execute(text(_CASE_SLA_SQL + " WHERE c.created_at > :since ORDER BY c.created_at"), {"since": now - timedelta(days=days)}).all()
    out = []
    weekly: dict = {}
    for sev in sla.SEVERITIES:
        rs = [r for r in rows if r.severity == sev]
        resp = [sla.case_states(r, now) for r in rs]
        rt = [(r.first_response_at - r.created_at).total_seconds() / 60 for r in rs if r.first_response_at]
        xt = [(r.resolved_at - r.created_at).total_seconds() / 60 for r in rs if r.resolved_at]
        out.append(SlaPerformanceRow(
            severity=sev, cases=len(rs), response_met=sum(1 for a, _ in resp if a == "met"), response_breached=sum(1 for a, _ in resp if a == "breached"),
            resolution_met=sum(1 for _, b in resp if b == "met"), resolution_breached=sum(1 for _, b in resp if b == "breached"),
            without_policy=sum(1 for r in rs if r.sla_response_due_at is None),
            median_response_minutes=round(statistics.median(rt)) if rt else None,
            median_resolution_minutes=round(statistics.median(xt)) if xt else None))
    for r in rows:
        resp, res = sla.case_states(r, now)
        wk = (r.created_at - timedelta(days=r.created_at.weekday())).date()
        w = weekly.setdefault(wk, [0, 0])
        if "breached" in (resp, res):
            w[1] += 1
        elif resp == "met" and res == "met":
            w[0] += 1
    note = "" if any(r.sla_response_due_at for r in rows) else "No case in the period had an SLA policy; performance cannot be measured."
    return SlaPerformance(days=days, rows=out, weekly=[SlaWeek(week_start=k, met=v[0], breached=v[1]) for k, v in sorted(weekly.items())],
                          note=note)


def escalate(conn: Connection, actor: str = "system") -> EscalationResult:
    """Mark open cases that are at risk or breached (once) and notify the policy's escalation role."""
    items = open_case_slas(conn)
    checked, escalated, notified = len(items), 0, 0
    for i in items:
        if i.escalated_at is not None or "breached" not in (i.response_state, i.resolution_state) and \
                "at_risk" not in (i.response_state, i.resolution_state):
            continue
        snap = conn.execute(text("SELECT sla_policy_snapshot FROM novrsoc.cases WHERE id = :i"), {"i": i.case_id}).scalar() or {}
        role = snap.get("escalate_to_role", "soc_manager")
        state = "breached" if "breached" in (i.response_state, i.resolution_state) else "at risk"
        conn.execute(text("UPDATE novrsoc.cases SET escalated_at = now() WHERE id = :i"), {"i": i.case_id})
        conn.execute(text("""INSERT INTO novrsoc.case_events (case_id, org_id, actor_label, kind, body, details)
                             VALUES (:c, novrsoc.app_org(), :a, 'sla_escalated', :b, CAST(:d AS jsonb))"""),
                     {"c": i.case_id, "a": actor, "b": f"SLA {state}: escalated to {role}.",
                      "d": json.dumps({"response": i.response_state, "resolution": i.resolution_state, "role": role})})
        users = [u.user_id for u in activity.users_with_roles(conn, [role])]
        notified += activity.notify(conn, users, "sla_escalation", f"SLA {state}: {i.reference}", i.title, f"/app/cases/{i.case_id}")
        escalated += 1
    return EscalationResult(checked=checked, escalated=escalated, notified=notified)


@router.post("/sla/escalate", response_model=EscalationResult, summary="Run the SLA escalation check now")
def run_escalation(request: Request, p: Principal = Depends(require("sla:manage")), conn: Connection = Depends(request_connection)) -> EscalationResult:
    out = escalate(conn, p.email)
    audit.record("SLA_ESCALATION_RUN", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="sla",
                 request_id=request.state.request_id, ip=client_ip(request), details=out.model_dump())
    return out


# ---------------------------------------------------------------- shift handover
def snapshot(conn: Connection, user_id: uuid.UUID) -> HandoverSnapshot:
    alerts = conn.execute(text("""SELECT a.id, a.rule_description, a.severity, a.status, a.observed_at,
                                         (SELECT u.email::text FROM novrsoc.users u WHERE u.id = a.assignee_id) AS assignee
                                  FROM novrsoc.alerts a WHERE a.status IN ('new', 'acknowledged')
                                  ORDER BY CASE a.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                                           a.observed_at DESC LIMIT 15""")).all()
    unresolved = conn.execute(text("SELECT count(*) FROM novrsoc.alerts WHERE status IN ('new', 'acknowledged')")).scalar()
    unassigned_crit = conn.execute(text("""SELECT count(*) FROM novrsoc.alerts WHERE status <> 'closed' AND severity = 'critical'
                                           AND assignee_id IS NULL""")).scalar()
    cases = conn.execute(text("""SELECT c.id, c.number, c.title, c.severity, c.status,
                                        (SELECT u.email::text FROM novrsoc.users u WHERE u.id = c.assignee_id) AS assignee
                                 FROM novrsoc.cases c WHERE c.status IN ('open', 'in_progress')
                                 ORDER BY CASE c.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,
                                          c.created_at LIMIT 25""")).all()
    open_cases = conn.execute(text("SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress')")).scalar()
    approvals = conn.execute(text("""SELECT id, action, target, requested_label, expires_at FROM novrsoc.soar_approvals
                                     WHERE decision IS NULL AND expires_at > now() ORDER BY expires_at LIMIT 20""")).all()
    slas = open_case_slas(conn)
    mine = conn.execute(text("""SELECT (SELECT count(*) FROM novrsoc.alerts WHERE assignee_id = :u AND status <> 'closed')
                                     + (SELECT count(*) FROM novrsoc.cases WHERE assignee_id = :u AND status IN ('open', 'in_progress'))"""),
                        {"u": user_id}).scalar()
    return HandoverSnapshot(
        taken_at=_now(), unresolved_alerts=unresolved, unassigned_critical_alerts=unassigned_crit,
        top_alerts=[HandoverAlert(id=a.id, rule_description=a.rule_description, severity=a.severity, status=a.status, observed_at=a.observed_at,
                                  assignee_label=a.assignee) for a in alerts],
        open_cases=open_cases,
        cases=[HandoverCase(id=c.id, reference=f"CASE-{c.number:06d}", title=c.title, severity=c.severity, status=c.status,
                            assignee_label=c.assignee) for c in cases],
        pending_approvals=[HandoverApproval(id=a.id, action=a.action, target=a.target, requested_by=a.requested_label, expires_at=a.expires_at)
                           for a in approvals],
        sla_at_risk=[s for s in slas if "at_risk" in (s.response_state, s.resolution_state)][:20],
        sla_breached=sum(1 for s in slas if "breached" in (s.response_state, s.resolution_state)), my_assignments=mine)


def _recipients(conn: Connection, exclude: uuid.UUID) -> list[UserRef]:
    return [UserRef(id=u.user_id, email=str(u.email), role=u.role_key)
            for u in activity.users_with_roles(conn, ["analyst", "soc_manager", "super_admin"]) if u.user_id != exclude]


@router.get("/handovers/draft", response_model=HandoverDraft, summary="The current queue, to start a shift handover")
def handover_draft(p: Principal = Depends(require("handover:write")), conn: Connection = Depends(request_connection)) -> HandoverDraft:
    return HandoverDraft(snapshot=snapshot(conn, p.user_id), recipients=_recipients(conn, p.user_id))


def _handover(r) -> HandoverView:
    return HandoverView(id=r.id, author=ActorRef(type="user", id=r.author_id, label=r.author_label), shift_start=r.shift_start,
                        shift_end=r.shift_end, summary=r.summary, watch_items=list(r.watch_items or []),
                        snapshot=HandoverSnapshot.model_validate(r.snapshot), incoming_user_id=r.incoming_user_id,
                        incoming_label=r.incoming_label, status=r.status,
                        acknowledged_by=ActorRef(type="user", id=r.acknowledged_by, label=r.acknowledged_label or "") if r.acknowledged_by else None,
                        acknowledged_at=r.acknowledged_at, acknowledgement_note=r.acknowledgement_note, created_at=r.created_at)


_HANDOVER_SQL = """SELECT h.*, (SELECT u.email::text FROM novrsoc.users u WHERE u.id = h.incoming_user_id) AS incoming_label
                   FROM novrsoc.shift_handovers h"""


@router.post("/handovers", response_model=HandoverView, status_code=201, summary="Submit a shift handover (the queue is frozen into it)")
def create_handover(body: HandoverCreate, request: Request, p: Principal = Depends(require("handover:write")),
                    conn: Connection = Depends(request_connection)) -> HandoverView:
    if body.incoming_user_id is not None:
        if body.incoming_user_id == p.user_id:
            raise ApiError(422, "validation_error", "The incoming analyst must be someone else")
        if body.incoming_user_id not in {u.id for u in _recipients(conn, p.user_id)}:
            raise ApiError(422, "validation_error", "The incoming analyst must be an analyst or manager of this organization")
    snap = snapshot(conn, p.user_id)
    hid = conn.execute(text("""INSERT INTO novrsoc.shift_handovers (org_id, author_id, author_label, shift_start, shift_end, summary,
                                                                    watch_items, snapshot, incoming_user_id)
                               VALUES (:o, :u, :l, :s, :e, :sum, CAST(:w AS jsonb), CAST(:snap AS jsonb), :inc) RETURNING id"""),
                       {"o": p.org_id, "u": p.user_id, "l": p.email, "s": body.shift_start, "e": body.shift_end, "sum": body.summary,
                        "w": json.dumps(body.watch_items), "snap": snap.model_dump_json(), "inc": body.incoming_user_id}).scalar()
    targets = [body.incoming_user_id] if body.incoming_user_id else [u.id for u in _recipients(conn, p.user_id)]
    activity.notify(conn, targets, "shift_handover", f"Shift handover from {p.email}", body.summary[:300], "/app/handover")
    audit.record("HANDOVER_SUBMITTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="shift_handover",
                 resource_id=str(hid), request_id=request.state.request_id, ip=client_ip(request),
                 details={"incoming": str(body.incoming_user_id) if body.incoming_user_id else None, "open_cases": snap.open_cases})
    return _handover(conn.execute(text(_HANDOVER_SQL + " WHERE h.id = :i"), {"i": hid}).one())


@router.get("/handovers", response_model=HandoverList, summary="Shift handovers (newest first)")
def list_handovers(limit: int = Query(30, ge=1, le=200), p: Principal = Depends(require("cases:read")),
                   conn: Connection = Depends(request_connection)) -> HandoverList:
    return HandoverList(items=[_handover(r) for r in conn.execute(text(_HANDOVER_SQL + " ORDER BY h.created_at DESC LIMIT :n"), {"n": limit})])


@router.post("/handovers/{handover_id}/acknowledge", response_model=HandoverView, summary="Acknowledge a handover (incoming analyst)")
def acknowledge(handover_id: uuid.UUID, body: HandoverAcknowledge, request: Request, p: Principal = Depends(require("handover:write")),
                conn: Connection = Depends(request_connection)) -> HandoverView:
    h = conn.execute(text("SELECT * FROM novrsoc.shift_handovers WHERE id = :i FOR UPDATE"), {"i": handover_id}).first()
    if h is None:
        raise not_found("Handover not found")
    if h.author_id == p.user_id:
        raise forbidden("The author cannot acknowledge their own handover")
    if h.incoming_user_id is not None and h.incoming_user_id != p.user_id:
        raise forbidden("This handover is addressed to another analyst")
    if h.status == "acknowledged":
        raise ApiError(409, "conflict", "This handover was already acknowledged")
    conn.execute(text("""UPDATE novrsoc.shift_handovers SET status = 'acknowledged', acknowledged_by = :u, acknowledged_label = :l,
                         acknowledged_at = now(), acknowledgement_note = :n WHERE id = :i"""),
                 {"u": p.user_id, "l": p.email, "n": body.note, "i": handover_id})
    activity.notify(conn, [h.author_id], "handover_acknowledged", f"{p.email} acknowledged your handover", body.note[:300], "/app/handover")
    audit.record("HANDOVER_ACKNOWLEDGED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="shift_handover",
                 resource_id=str(handover_id), request_id=request.state.request_id, ip=client_ip(request))
    return _handover(conn.execute(text(_HANDOVER_SQL + " WHERE h.id = :i"), {"i": handover_id}).one())


# ---------------------------------------------------------------- notifications (own, active organization)
@router.get("/notifications", response_model=NotificationList, summary="The signed-in user's notifications")
def notifications(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> NotificationList:
    conn.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(p.user_id)})
    rows = conn.execute(text("SELECT * FROM novrsoc.notifications ORDER BY created_at DESC LIMIT 50")).all()
    unread = conn.execute(text("SELECT count(*) FROM novrsoc.notifications WHERE read_at IS NULL")).scalar()
    return NotificationList(unread=unread, items=[NotificationView(id=r.id, kind=r.kind, title=r.title, body=r.body, link=r.link,
                                                                   created_at=r.created_at, read_at=r.read_at) for r in rows])


@router.post("/notifications/read", response_model=NotificationList, summary="Mark all of the user's notifications as read")
def mark_read(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> NotificationList:
    conn.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(p.user_id)})
    conn.execute(text("UPDATE novrsoc.notifications SET read_at = now() WHERE read_at IS NULL"))
    return notifications(p, conn)
