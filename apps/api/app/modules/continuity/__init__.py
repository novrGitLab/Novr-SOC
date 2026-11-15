"""Data continuity (consolidation; workstream E): recovery plans, recovery requests, verification and evidence.

What is connected and what is administrative (shown on every plan as `execution`):
  * novrsoc_platform_backup  NovrSOC's own database: encrypted logical backups and restore drills on Server 2, run by the
                             platform administrator (app/backup.py). This is the only connected backup system.
  * external_provider        a third-party backup service: NovrSOC records the workflow; the provider does the recovery.
  * manual_procedure         a documented manual procedure: NovrSOC records the workflow and evidence only.
NovrSOC never claims that deleted data can be recovered: a request ends `not_recoverable` when no backup covers it.
Decisions and verification are made by someone other than the requester (database CHECKs too).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.audit import activity
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.errors import ApiError, forbidden, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.common import ActorRef
from novrsoc_contracts.v1.continuity import (ContinuityOverview, PlatformBackupState, RecoveryDecision, RecoveryEventView, RecoveryPlanCreate,
                                             RecoveryPlanList, RecoveryPlanTested, RecoveryPlanView, RecoveryProgress, RecoveryRequestCreate,
                                             RecoveryRequestList, RecoveryRequestView, RecoveryVerification)

MODULE = ModuleInfo(name="continuity", workstream="E", prefix="/api/v1/continuity",
                    summary="Data continuity: recovery plans, recovery requests, verification, RPO and RTO")
router = APIRouter(prefix="/api/v1/continuity", tags=["continuity"], responses=ERRORS)

EXECUTION = {
    "novrsoc_platform_backup": "Connected: NovrSOC's own encrypted database backups and restore drills (platform administrator, Server 2).",
    "external_provider": "Administrative workflow: the named provider performs the recovery; NovrSOC records decisions and evidence.",
    "manual_procedure": "Administrative workflow: a documented manual procedure; NovrSOC records decisions and evidence.",
}
TRANSITIONS = {"assess": ({"submitted"}, "assessing"), "approve": ({"submitted", "assessing"}, "approved"),
               "reject": ({"submitted", "assessing"}, "rejected"), "not_recoverable": ({"submitted", "assessing", "approved", "in_progress"},
                                                                                       "not_recoverable")}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _plan(r) -> RecoveryPlanView:
    return RecoveryPlanView(id=r.id, name=r.name, scope=r.scope, backup_source=r.backup_source, provider_name=r.provider_name,
                            rpo_minutes=r.rpo_minutes, rto_minutes=r.rto_minutes, procedure=r.procedure, owning_unit=r.owning_unit,
                            last_tested_at=r.last_tested_at, created_at=r.created_at, updated_at=r.updated_at,
                            execution=EXECUTION[r.backup_source])


def _audit(p: Principal, request: Request, action: str, rid: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="recovery", resource_id=rid,
                 request_id=request.state.request_id, ip=client_ip(request), details=details or {})


@router.get("/plans", response_model=RecoveryPlanList, summary="Recovery plans of the organization")
def list_plans(p: Principal = Depends(require("recovery:read")), conn: Connection = Depends(request_connection)) -> RecoveryPlanList:
    return RecoveryPlanList(items=[_plan(r) for r in conn.execute(text("SELECT * FROM novrsoc.recovery_plans ORDER BY name"))])


@router.post("/plans", response_model=RecoveryPlanView, status_code=201, summary="Create a recovery plan")
def create_plan(body: RecoveryPlanCreate, request: Request, p: Principal = Depends(require("recovery:manage")),
                conn: Connection = Depends(request_connection)) -> RecoveryPlanView:
    if body.backup_source == "novrsoc_platform_backup":
        kind = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).scalar()
        if kind != "platform":
            raise ApiError(422, "validation_error", "Platform backups cover NovrSOC's own database; a client organization's data needs "
                                                    "an external provider or a manual procedure")
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.recovery_plans (org_id, name, scope, backup_source, provider_name, rpo_minutes, rto_minutes,
                                                                         procedure, owning_unit, created_by)
                                     VALUES (:o, :n, :s, :b, :pn, :rpo, :rto, :pr, :ou, :u) RETURNING *"""),
                             {"o": p.org_id, "n": body.name, "s": body.scope, "b": body.backup_source, "pn": body.provider_name,
                              "rpo": body.rpo_minutes, "rto": body.rto_minutes, "pr": body.procedure, "ou": body.owning_unit, "u": p.user_id}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "A plan with this name already exists")
    _audit(p, request, "RECOVERY_PLAN_CREATED", str(r.id), {"backup_source": body.backup_source})
    return _plan(r)


@router.post("/plans/{plan_id}/tested", response_model=RecoveryPlanView, summary="Record that a plan was tested")
def plan_tested(plan_id: uuid.UUID, body: RecoveryPlanTested, request: Request, p: Principal = Depends(require("recovery:manage")),
                conn: Connection = Depends(request_connection)) -> RecoveryPlanView:
    if body.tested_at > _now() + timedelta(minutes=5):
        raise ApiError(422, "validation_error", "A test date cannot be in the future")
    r = conn.execute(text("UPDATE novrsoc.recovery_plans SET last_tested_at = :t, updated_at = now() WHERE id = :i RETURNING *"),
                     {"t": body.tested_at, "i": plan_id}).first()
    if r is None:
        raise not_found("Plan not found")
    _audit(p, request, "RECOVERY_PLAN_TESTED", str(plan_id), {"tested_at": body.tested_at.isoformat(), "note": body.note})
    return _plan(r)


_REQ_SQL = """SELECT r.*, pl.name AS plan_name, pl.backup_source, pl.rpo_minutes, pl.rto_minutes FROM novrsoc.recovery_requests r
              LEFT JOIN novrsoc.recovery_plans pl ON pl.id = r.plan_id"""


def _minutes(a: datetime | None, b: datetime | None) -> int | None:
    return round((b - a).total_seconds() / 60) if a and b else None


def _request(conn: Connection, r, events: bool = False) -> RecoveryRequestView:
    ev = []
    if events:
        ev = [RecoveryEventView(id=e.id, occurred_at=e.occurred_at, kind=e.kind, actor_label=e.actor_label, body=e.body, details=e.details or {})
              for e in conn.execute(text("SELECT * FROM novrsoc.recovery_events WHERE request_id = :r ORDER BY id"), {"r": r.id})]
    return RecoveryRequestView(
        id=r.id, plan_id=r.plan_id, plan_name=r.plan_name, backup_source=r.backup_source, title=r.title, description=r.description,
        affected_data=r.affected_data, loss_detected_at=r.loss_detected_at, requested_recovery_point=r.requested_recovery_point, status=r.status,
        requested_by=ActorRef(type="user", id=r.requested_by, label=r.requested_label),
        decided_by=ActorRef(type="user", id=r.decided_by, label=r.decided_label or "") if r.decided_by else None, decision_reason=r.decision_reason,
        backup_reference=r.backup_reference, recovered_point=r.recovered_point, verification=r.verification, started_at=r.started_at,
        completed_at=r.completed_at, created_at=r.created_at,
        achieved_rpo_minutes=_minutes(r.recovered_point, r.loss_detected_at) if r.status == "completed" else None,
        achieved_rto_minutes=_minutes(r.created_at, r.completed_at), rpo_target_minutes=r.rpo_minutes, rto_target_minutes=r.rto_minutes,
        events=ev)


def _get(conn: Connection, request_id: uuid.UUID, lock: bool = False):
    r = conn.execute(text(_REQ_SQL + " WHERE r.id = :i" + (" FOR UPDATE OF r" if lock else "")), {"i": request_id}).first()
    if r is None:
        raise not_found("Recovery request not found")
    return r


def _event(conn: Connection, request_id: uuid.UUID, kind: str, actor: str, body: str, details: dict | None = None) -> None:
    conn.execute(text("""INSERT INTO novrsoc.recovery_events (org_id, request_id, kind, actor_label, body, details)
                         VALUES (novrsoc.app_org(), :r, :k, :a, :b, CAST(:d AS jsonb))"""),
                 {"r": request_id, "k": kind, "a": actor, "b": body[:4000], "d": json.dumps(details or {}, default=str)})


@router.get("/requests", response_model=RecoveryRequestList, summary="Recovery requests (newest first)")
def list_requests(p: Principal = Depends(require("recovery:read")), conn: Connection = Depends(request_connection)) -> RecoveryRequestList:
    return RecoveryRequestList(items=[_request(conn, r) for r in conn.execute(text(_REQ_SQL + " ORDER BY r.created_at DESC LIMIT 200"))])


@router.get("/requests/{request_id}", response_model=RecoveryRequestView, summary="One recovery request with its events")
def get_request(request_id: uuid.UUID, p: Principal = Depends(require("recovery:read")),
                conn: Connection = Depends(request_connection)) -> RecoveryRequestView:
    return _request(conn, _get(conn, request_id), events=True)


@router.post("/requests", response_model=RecoveryRequestView, status_code=201, summary="Submit a recovery request")
def create_request(body: RecoveryRequestCreate, request: Request, p: Principal = Depends(require("recovery:read")),
                   conn: Connection = Depends(request_connection)) -> RecoveryRequestView:
    if p.role not in ("super_admin", "soc_manager", "analyst"):
        raise forbidden("Recovery requests are submitted by SOC staff")
    if body.loss_detected_at > _now() + timedelta(minutes=5):
        raise ApiError(422, "validation_error", "The loss cannot be detected in the future")
    if body.plan_id and conn.execute(text("SELECT 1 FROM novrsoc.recovery_plans WHERE id = :i"), {"i": body.plan_id}).first() is None:
        raise not_found("Plan not found")
    rid = conn.execute(text("""INSERT INTO novrsoc.recovery_requests (org_id, plan_id, title, description, affected_data, loss_detected_at,
                                                                      requested_recovery_point, requested_by, requested_label)
                               VALUES (:o, :pl, :t, :d, :a, :l, :rp, :u, :ul) RETURNING id"""),
                       {"o": p.org_id, "pl": body.plan_id, "t": body.title, "d": body.description, "a": body.affected_data,
                        "l": body.loss_detected_at, "rp": body.requested_recovery_point, "u": p.user_id, "ul": p.email}).scalar()
    _event(conn, rid, "submitted", p.email, body.description)
    managers = [u.user_id for u in activity.users_with_roles(conn, ["soc_manager", "super_admin"]) if u.user_id != p.user_id]
    activity.notify(conn, managers, "recovery_request", f"Recovery request: {body.title}", body.affected_data[:300], "/app/recovery")
    _audit(p, request, "RECOVERY_REQUESTED", str(rid), {"plan": str(body.plan_id) if body.plan_id else None})
    return _request(conn, _get(conn, rid), events=True)


@router.post("/requests/{request_id}/decision", response_model=RecoveryRequestView, summary="Assess, approve, reject or declare not recoverable")
def decide(request_id: uuid.UUID, body: RecoveryDecision, request: Request, p: Principal = Depends(require("recovery:manage")),
           conn: Connection = Depends(request_connection)) -> RecoveryRequestView:
    r = _get(conn, request_id, lock=True)
    if r.requested_by == p.user_id:
        raise forbidden("The requester cannot decide their own recovery request")
    allowed, to = TRANSITIONS[body.decision]
    if r.status not in allowed:
        raise ApiError(409, "conflict", f"A {r.status} request cannot be moved to {to}")
    if body.decision == "approve" and r.plan_id is None:
        raise ApiError(422, "plan_required", "Approval needs a recovery plan that covers the data (or declare it not recoverable)")
    conn.execute(text("""UPDATE novrsoc.recovery_requests SET status = :s, decided_by = :u, decided_label = :l, decision_reason = :r,
                           backup_reference = CASE WHEN :b <> '' THEN :b ELSE backup_reference END,
                           verification = CASE WHEN :s IN ('rejected', 'not_recoverable') THEN 'not_applicable' ELSE verification END,
                           updated_at = now() WHERE id = :i"""),
                 {"s": to, "u": p.user_id, "l": p.email, "r": body.reason, "b": body.backup_reference, "i": request_id})
    _event(conn, request_id, "status_changed", p.email, body.reason, {"from": r.status, "to": to})
    activity.notify(conn, [r.requested_by], "recovery_decision", f"Recovery request {to.replace('_', ' ')}", body.reason[:300], "/app/recovery")
    _audit(p, request, "RECOVERY_DECIDED", str(request_id), {"to": to})
    return _request(conn, _get(conn, request_id), events=True)


@router.post("/requests/{request_id}/progress", response_model=RecoveryRequestView, summary="Record recovery progress or completion")
def progress(request_id: uuid.UUID, body: RecoveryProgress, request: Request, p: Principal = Depends(require("recovery:manage")),
             conn: Connection = Depends(request_connection)) -> RecoveryRequestView:
    r = _get(conn, request_id, lock=True)
    if body.status == "in_progress" and r.status != "approved":
        raise ApiError(409, "conflict", "Only an approved request can start")
    if body.status == "completed":
        if r.status != "in_progress":
            raise ApiError(409, "conflict", "Only a request in progress can complete")
        if body.recovered_point is None:
            raise ApiError(422, "validation_error", "Completion records the point in time the data was recovered to")
    conn.execute(text("""UPDATE novrsoc.recovery_requests SET status = :s, updated_at = now(),
                           started_at = CASE WHEN :s = 'in_progress' THEN now() ELSE started_at END,
                           completed_at = CASE WHEN :s = 'completed' THEN now() ELSE completed_at END,
                           recovered_point = coalesce(:rp, recovered_point) WHERE id = :i"""),
                 {"s": body.status, "rp": body.recovered_point, "i": request_id})
    _event(conn, request_id, "status_changed", p.email, body.note, {"from": r.status, "to": body.status})
    for e in body.evidence:
        _event(conn, request_id, "evidence", p.email, e)
    _audit(p, request, "RECOVERY_PROGRESS", str(request_id), {"to": body.status, "evidence": len(body.evidence)})
    return _request(conn, _get(conn, request_id), events=True)


@router.post("/requests/{request_id}/verify", response_model=RecoveryRequestView, summary="Verify a completed recovery (not the requester)")
def verify(request_id: uuid.UUID, body: RecoveryVerification, request: Request, p: Principal = Depends(require("recovery:manage")),
           conn: Connection = Depends(request_connection)) -> RecoveryRequestView:
    r = _get(conn, request_id, lock=True)
    if r.status != "completed":
        raise ApiError(409, "conflict", "Only a completed recovery can be verified")
    if r.requested_by == p.user_id:
        raise forbidden("The requester cannot verify their own recovery")
    conn.execute(text("UPDATE novrsoc.recovery_requests SET verification = :v, verified_by = :u, verified_at = now(), updated_at = now() WHERE id = :i"),
                 {"v": body.result, "u": p.user_id, "i": request_id})
    _event(conn, request_id, "verification", p.email, body.note, {"result": body.result})
    _audit(p, request, "RECOVERY_VERIFIED", str(request_id), {"result": body.result})
    return _request(conn, _get(conn, request_id), events=True)


@router.get("/overview", response_model=ContinuityOverview, summary="Continuity overview: backups, plans, requests, RPO and RTO")
def overview(p: Principal = Depends(require("recovery:read")), conn: Connection = Depends(request_connection)) -> ContinuityOverview:
    if p.has("backups:read"):
        b = conn.execute(text("""SELECT (SELECT max(finished_at) FROM novrsoc.backup_runs WHERE status = 'succeeded') AS ok,
                                        (SELECT finished_at FROM novrsoc.restore_drills ORDER BY finished_at DESC LIMIT 1) AS drill,
                                        (SELECT status FROM novrsoc.restore_drills ORDER BY finished_at DESC LIMIT 1) AS drill_status""")).one()
        backups = PlatformBackupState(visible=True, last_succeeded_at=b.ok, last_drill_at=b.drill, last_drill_status=b.drill_status,
                                      note="NovrSOC's own database (Server 2). No backup recorded yet." if b.ok is None else
                                      "NovrSOC's own database (Server 2).")
    else:
        backups = PlatformBackupState(visible=False, note="Platform backup history is visible to platform administrators only.")
    plans = conn.execute(text("SELECT * FROM novrsoc.recovery_plans")).all()
    reqs = [_request(conn, r) for r in conn.execute(text(_REQ_SQL))]
    done = [r for r in reqs if r.status == "completed"]
    rpo_ok = sum(1 for r in done if r.achieved_rpo_minutes is not None and r.rpo_target_minutes and r.achieved_rpo_minutes <= r.rpo_target_minutes)
    rto_ok = sum(1 for r in done if r.achieved_rto_minutes is not None and r.rto_target_minutes and r.achieved_rto_minutes <= r.rto_target_minutes)
    return ContinuityOverview(
        generated_at=_now(), platform_backups=backups, plans=len(plans),
        plans_untested_90d=sum(1 for x in plans if x.last_tested_at is None or x.last_tested_at < _now() - timedelta(days=90)),
        open_requests=sum(1 for r in reqs if r.status in ("submitted", "assessing", "approved", "in_progress")), completed_requests=len(done),
        not_recoverable=sum(1 for r in reqs if r.status == "not_recoverable"), rpo_met=rpo_ok,
        rpo_missed=sum(1 for r in done if r.achieved_rpo_minutes is not None and r.rpo_target_minutes) - rpo_ok, rto_met=rto_ok,
        rto_missed=sum(1 for r in done if r.achieved_rto_minutes is not None and r.rto_target_minutes) - rto_ok)
