"""SOAR engine (Server 2): playbooks, the organization's response policy, runs, approvals, dispatch and receipts.

Safety model (contracts v1/soar.py, migration 0010):
  * Non-consequential steps run in-process (IOC enrichment from Threat Insights, case tasks); notifications report
    skipped_not_configured (no adapter). Nothing is ever executed by NHAI or automatically.
  * A consequential step (block_ip, isolate_agent, disable_account) needs: the action in the organization's policy
    allow-list; a target taken from the case's OWN evidence (alert source IP / agent / account seen in the alerts);
    the agent's Wazuh groups in the policy's authorized groups; for live mode, live_enabled on the policy. Then a
    human approval by someone other than the requester (response:approve) before it expires.
  * On approval the target and authorization are re-checked, and the step is dispatched to the Server 1 bridge with a
    unique request_id and a 5-minute expiry; the bridge's signed receipt is verified and stored. A network failure
    leaves the step dispatchable again with the SAME request_id (the bridge executes at most once).
Every state change is an audit event (SOAR_* vocabulary of v1/soar.SoarAuditEvent).

Consolidation:
  * Playbook lifecycle: draft -> validated -> pending_approval -> approved (by another soar:manage holder) -> retired.
    Only an approved, enabled version runs; approving a version retires the previously approved one. Nothing is
    pre-defined: every playbook is written and approved by people.
  * Execution limits: the playbook's execution policy (modes, minimum case severity, runs per day) and the
    organization's policy (runs per hour, dispatch attempts). An emergency stop blocks new runs, approvals that would
    dispatch, and re-dispatch, until a soar:manage holder lifts it.
  * The operations centre merges engine, approval and policy events with AI activity, which is labelled as analysis.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import activity
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from app.soar import bridge_client
from novrsoc_contracts.v1.common import ActorRef
from novrsoc_contracts.v1.soar import (AiActivityList, AiActivityView, ApprovalDecisionRequest, ApprovalList, ApprovalView,
                                       EmergencyStopRequest, ExecutionReceipt, PlaybookCreate, PlaybookExecutionPolicy, PlaybookList,
                                       PlaybookRecommendation, PlaybookReview, PlaybookStep, PlaybookTriggers, PlaybookValidation,
                                       PlaybookVersionList, PlaybookView, RecommendationList, RunCreate, RunList, RunView,
                                       SoarOperations, SoarPolicyUpdate, SoarPolicyView, SoarTimelineEntry, StepView)

MODULE = ModuleInfo(name="soar", workstream="A", prefix="/api/v1/soar",
                    summary="SOAR engine: playbooks, policy, runs, human approvals, bridge dispatch and receipts")
router = APIRouter(prefix="/api/v1/soar", tags=["soar"], responses=ERRORS)

CONSEQUENTIAL = {"block_ip", "isolate_agent", "disable_account"}
SEV = {"low": 1, "medium": 2, "high": 3, "critical": 4}
DISPATCH_TTL = timedelta(minutes=5)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _audit(p: Principal, request: Request, action: str, run_id, details: dict) -> None:
    audit.record(action, "success" if action != "SOAR_LIVE_REFUSED" else "denied", org_id=p.org_id, actor_id=p.user_id,
                 actor_label=p.email, resource_type="soar_run", resource_id=str(run_id), request_id=request.state.request_id,
                 ip=client_ip(request), details=details)


# ---------------------------------------------------------------- playbooks and policy
_PB_SQL = """SELECT pb.*, (SELECT u.email::text FROM novrsoc.users u WHERE u.id = pb.created_by) AS created_label
             FROM novrsoc.soar_playbooks pb"""


def _playbook(r) -> PlaybookView:
    v = r.validation or {}
    return PlaybookView(id=r.id, name=r.name, version=r.version, title=r.title, steps=[PlaybookStep(**s) for s in r.steps],
                        triggers=PlaybookTriggers(**(r.triggers or {})), enabled=r.enabled, created_at=r.created_at, status=r.status,
                        description=r.description, execution_policy=PlaybookExecutionPolicy(**(r.execution_policy or {})),
                        validation=PlaybookValidation(**v) if v.get("checked_at") else None,
                        created_by_label=getattr(r, "created_label", None) or "",
                        approved_by=_actor(r.approved_by, r.approved_label) if r.approved_by else None, approved_at=r.approved_at,
                        review_note=r.review_note)


def _pb(conn: Connection, playbook_id: uuid.UUID):
    r = conn.execute(text(_PB_SQL + " WHERE pb.id = :i"), {"i": playbook_id}).first()
    if r is None:
        raise not_found("Playbook version not found")
    return r


@router.get("/playbooks", response_model=PlaybookList, summary="Playbooks of the organization (latest version of each)")
def list_playbooks(p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> PlaybookList:
    rows = conn.execute(text(f"SELECT * FROM ({_PB_SQL}) x WHERE (x.name, x.version) IN "
                             "(SELECT name, max(version) FROM novrsoc.soar_playbooks GROUP BY name) ORDER BY x.name")).all()
    return PlaybookList(items=[_playbook(r) for r in rows])


def approved_playbooks(conn: Connection) -> list[PlaybookView]:
    rows = conn.execute(text(_PB_SQL + " WHERE pb.status = 'approved' AND pb.enabled ORDER BY pb.name")).all()
    return [_playbook(r) for r in rows]


def validate_playbook(conn: Connection, steps: list[PlaybookStep], triggers: PlaybookTriggers,
                      ep: PlaybookExecutionPolicy) -> PlaybookValidation:
    """Deterministic checks: errors block approval; warnings are shown to the reviewer."""
    errors, warnings = [], []
    keys = [s.step_key for s in steps]
    if len(keys) != len(set(keys)):
        errors.append("Step keys must be unique within a playbook.")
    policy = _policy(conn)
    allowed = {a.value for a in policy.allowed_actions}
    first_consequential = next((i for i, s in enumerate(steps) if s.action.value in CONSEQUENTIAL), None)
    for i, st in enumerate(steps):
        a = st.action.value
        if a == "disable_account" and not str(st.parameters.get("account") or "").strip():
            errors.append(f"Step {st.step_key}: disable_account needs an `account` parameter (it must appear in the case's alerts).")
        if a in CONSEQUENTIAL:
            if a not in allowed:
                warnings.append(f"Step {st.step_key}: {a} is not in the organization's response policy; it will be refused at run time.")
            if st.timeout_seconds > 900:
                warnings.append(f"Step {st.step_key}: a consequential step with a timeout over 15 minutes.")
            warnings.append(f"Step {st.step_key}: {a} always waits for a human approval by someone other than the requester.")
        if a in ("notify_email", "notify_ciso"):
            warnings.append(f"Step {st.step_key}: no notification adapter is configured; the step will be skipped and say so.")
        if a == "enrich_iocs" and first_consequential is not None and i > first_consequential:
            warnings.append(f"Step {st.step_key}: enrichment after a consequential step; reviewers usually want evidence first.")
    if "live" in [m.value for m in ep.modes]:
        if not policy.live_enabled:
            warnings.append("Live mode is allowed by this playbook but not enabled in the organization's response policy.")
        if first_consequential is None:
            warnings.append("Live mode is allowed but the playbook has no consequential step.")
    if not (triggers.rule_ids or triggers.mitre or triggers.min_level):
        warnings.append("No triggers: the playbook is never recommended and can only be run by choosing it on a case.")
    return PlaybookValidation(valid=not errors, errors=errors, warnings=warnings, checked_at=_now())


@router.post("/playbooks", response_model=PlaybookView, status_code=201, summary="Create a playbook, or a new version of one (draft)")
def create_playbook(body: PlaybookCreate, request: Request, p: Principal = Depends(require("soar:manage")),
                    conn: Connection = Depends(request_connection)) -> PlaybookView:
    keys = [s.step_key for s in body.steps]
    if len(keys) != len(set(keys)):
        raise ApiError(422, "validation_error", "Step keys must be unique within a playbook")
    version = (conn.execute(text("SELECT max(version) FROM novrsoc.soar_playbooks WHERE name = :n"), {"n": body.name}).scalar() or 0) + 1
    val = validate_playbook(conn, body.steps, body.triggers, body.execution_policy)
    r = conn.execute(text("""INSERT INTO novrsoc.soar_playbooks (org_id, name, version, title, steps, triggers, created_by, status, description,
                                                                 execution_policy, validation)
                             VALUES (:o, :n, :v, :t, CAST(:s AS jsonb), CAST(:tr AS jsonb), :u, 'draft', :d, CAST(:ep AS jsonb),
                                     CAST(:val AS jsonb)) RETURNING id"""),
                     {"o": p.org_id, "n": body.name, "v": version, "t": body.title, "u": p.user_id, "d": body.description,
                      "s": json.dumps([s.model_dump(mode="json") for s in body.steps]), "tr": body.triggers.model_dump_json(),
                      "ep": body.execution_policy.model_dump_json(), "val": val.model_dump_json()}).scalar()
    audit.record("SOAR_PLAYBOOK_SAVED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="soar_playbook", resource_id=f"{body.name}@{version}", request_id=request.state.request_id,
                 ip=client_ip(request), details={"status": "draft", "valid": val.valid})
    return _playbook(_pb(conn, r))


@router.get("/playbooks/{name}/versions", response_model=PlaybookVersionList, summary="Every version of a playbook")
def playbook_versions(name: str = Path(..., pattern=r"^[a-z0-9][a-z0-9_-]{1,59}$"), p: Principal = Depends(require("cases:read")),
                      conn: Connection = Depends(request_connection)) -> PlaybookVersionList:
    rows = conn.execute(text(_PB_SQL + " WHERE pb.name = :n ORDER BY pb.version DESC"), {"n": name}).all()
    if not rows:
        raise not_found("Playbook not found")
    return PlaybookVersionList(name=name, items=[_playbook(r) for r in rows])


def _lifecycle(p: Principal, request: Request, r, action: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="soar_playbook",
                 resource_id=f"{r.name}@{r.version}", request_id=request.state.request_id, ip=client_ip(request), details=details or {})


@router.post("/playbooks/{playbook_id}/validate", response_model=PlaybookView, summary="Validate a draft version")
def validate_version(playbook_id: uuid.UUID, request: Request, p: Principal = Depends(require("soar:manage")),
                     conn: Connection = Depends(request_connection)) -> PlaybookView:
    r = _pb(conn, playbook_id)
    if r.status not in ("draft", "validated"):
        raise ApiError(409, "conflict", f"A {r.status} version cannot be re-validated; create a new version")
    val = validate_playbook(conn, [PlaybookStep(**x) for x in r.steps], PlaybookTriggers(**(r.triggers or {})),
                            PlaybookExecutionPolicy(**(r.execution_policy or {})))
    conn.execute(text("UPDATE novrsoc.soar_playbooks SET validation = CAST(:v AS jsonb), status = :s WHERE id = :i"),
                 {"v": val.model_dump_json(), "s": "validated" if val.valid else "draft", "i": playbook_id})
    _lifecycle(p, request, r, "SOAR_PLAYBOOK_VALIDATED", {"valid": val.valid, "errors": len(val.errors)})
    return _playbook(_pb(conn, playbook_id))


@router.post("/playbooks/{playbook_id}/submit", response_model=PlaybookView, summary="Submit a validated version for approval")
def submit_version(playbook_id: uuid.UUID, request: Request, p: Principal = Depends(require("soar:manage")),
                   conn: Connection = Depends(request_connection)) -> PlaybookView:
    r = _pb(conn, playbook_id)
    if r.status != "validated":
        raise ApiError(409, "conflict", "Only a validated version can be submitted for approval")
    conn.execute(text("UPDATE novrsoc.soar_playbooks SET status = 'pending_approval', submitted_at = now() WHERE id = :i"), {"i": playbook_id})
    reviewers = [u.user_id for u in activity.users_with_roles(conn, ["soc_manager", "super_admin"]) if u.user_id != r.created_by]
    activity.notify(conn, reviewers, "playbook_review", f"Playbook {r.name} v{r.version} needs approval", r.title, "/app/playbooks")
    _lifecycle(p, request, r, "SOAR_PLAYBOOK_SUBMITTED")
    return _playbook(_pb(conn, playbook_id))


@router.post("/playbooks/{playbook_id}/review", response_model=PlaybookView, summary="Approve or reject a version (not your own)")
def review_version(playbook_id: uuid.UUID, body: PlaybookReview, request: Request, p: Principal = Depends(require("soar:manage")),
                   conn: Connection = Depends(request_connection)) -> PlaybookView:
    r = conn.execute(text(_PB_SQL + " WHERE pb.id = :i FOR UPDATE OF pb"), {"i": playbook_id}).first()
    if r is None:
        raise not_found("Playbook version not found")
    if r.status != "pending_approval":
        raise ApiError(409, "conflict", "Only a version pending approval can be reviewed")
    if r.created_by == p.user_id:
        audit.record("SOAR_PLAYBOOK_SELF_APPROVAL_REFUSED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                     resource_type="soar_playbook", resource_id=f"{r.name}@{r.version}", request_id=request.state.request_id, ip=client_ip(request))
        raise ApiError(403, "forbidden", "The author of a playbook version cannot approve it")
    if body.decision == "approve":
        conn.execute(text("""UPDATE novrsoc.soar_playbooks SET status = 'retired', retired_at = now()
                             WHERE name = :n AND status = 'approved' AND id <> :i"""), {"n": r.name, "i": playbook_id})
        conn.execute(text("""UPDATE novrsoc.soar_playbooks SET status = 'approved', approved_by = :u, approved_label = :l, approved_at = now(),
                             review_note = :note WHERE id = :i"""), {"u": p.user_id, "l": p.email, "note": body.note, "i": playbook_id})
    else:
        conn.execute(text("UPDATE novrsoc.soar_playbooks SET status = 'draft', review_note = :note WHERE id = :i"), {"note": body.note, "i": playbook_id})
    if r.created_by:
        activity.notify(conn, [r.created_by], "playbook_reviewed", f"Playbook {r.name} v{r.version} {body.decision}d", body.note[:300], "/app/playbooks")
    _lifecycle(p, request, r, "SOAR_PLAYBOOK_APPROVED" if body.decision == "approve" else "SOAR_PLAYBOOK_REJECTED", {"note": body.note})
    return _playbook(_pb(conn, playbook_id))


@router.post("/playbooks/{playbook_id}/retire", response_model=PlaybookView, summary="Retire a version (it can no longer run)")
def retire_version(playbook_id: uuid.UUID, request: Request, p: Principal = Depends(require("soar:manage")),
                   conn: Connection = Depends(request_connection)) -> PlaybookView:
    r = _pb(conn, playbook_id)
    if r.status == "retired":
        raise ApiError(409, "conflict", "This version is already retired")
    conn.execute(text("UPDATE novrsoc.soar_playbooks SET status = 'retired', retired_at = now() WHERE id = :i"), {"i": playbook_id})
    _lifecycle(p, request, r, "SOAR_PLAYBOOK_RETIRED")
    return _playbook(_pb(conn, playbook_id))


def _policy(conn: Connection) -> SoarPolicyView:
    r = conn.execute(text("SELECT * FROM novrsoc.soar_policies")).first()
    if r is None:
        return SoarPolicyView(allowed_actions=[], allowed_agent_groups=[], live_enabled=False, approval_ttl_minutes=60)
    return SoarPolicyView(allowed_actions=list(r.allowed_actions), allowed_agent_groups=list(r.allowed_agent_groups),
                          live_enabled=r.live_enabled, approval_ttl_minutes=r.approval_ttl_minutes, updated_at=r.updated_at,
                          emergency_stop=r.emergency_stop, emergency_reason=r.emergency_reason, emergency_at=r.emergency_at,
                          max_runs_per_hour=r.max_runs_per_hour, max_dispatch_attempts=r.max_dispatch_attempts)


@router.get("/policy", response_model=SoarPolicyView, summary="The organization's response authorization policy")
def get_policy(p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> SoarPolicyView:
    return _policy(conn)


@router.put("/policy", response_model=SoarPolicyView, summary="Set the organization's response authorization policy")
def put_policy(body: SoarPolicyUpdate, request: Request, p: Principal = Depends(require("soar:manage")),
               conn: Connection = Depends(request_connection)) -> SoarPolicyView:
    conn.execute(text("""INSERT INTO novrsoc.soar_policies (org_id, allowed_actions, allowed_agent_groups, live_enabled, approval_ttl_minutes,
                                                        updated_by, max_runs_per_hour, max_dispatch_attempts)
                         VALUES (:o, :a, :g, :l, :t, :u, :mr, :md)
                         ON CONFLICT (org_id) DO UPDATE SET allowed_actions = EXCLUDED.allowed_actions,
                           allowed_agent_groups = EXCLUDED.allowed_agent_groups, live_enabled = EXCLUDED.live_enabled,
                           approval_ttl_minutes = EXCLUDED.approval_ttl_minutes, updated_by = EXCLUDED.updated_by, updated_at = now(),
                           max_runs_per_hour = EXCLUDED.max_runs_per_hour, max_dispatch_attempts = EXCLUDED.max_dispatch_attempts"""),
                 {"o": p.org_id, "a": [a.value for a in body.allowed_actions], "g": body.allowed_agent_groups,
                  "l": body.live_enabled, "t": body.approval_ttl_minutes, "u": p.user_id, "mr": body.max_runs_per_hour,
                  "md": body.max_dispatch_attempts})
    audit.record("SOAR_POLICY_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="soar_policy", request_id=request.state.request_id, ip=client_ip(request),
                 details=body.model_dump(mode="json"))
    return _policy(conn)


@router.post("/emergency-stop", response_model=SoarPolicyView, summary="Turn the emergency stop on or off (always audited)")
def emergency_stop(body: EmergencyStopRequest, request: Request, p: Principal = Depends(require("soar:manage")),
                   conn: Connection = Depends(request_connection)) -> SoarPolicyView:
    conn.execute(text("""INSERT INTO novrsoc.soar_policies (org_id, emergency_stop, emergency_reason, emergency_by, emergency_at, updated_by)
                         VALUES (:o, :a, :r, :u, now(), :u)
                         ON CONFLICT (org_id) DO UPDATE SET emergency_stop = EXCLUDED.emergency_stop, emergency_reason = EXCLUDED.emergency_reason,
                           emergency_by = EXCLUDED.emergency_by, emergency_at = now(), updated_by = EXCLUDED.updated_by, updated_at = now()"""),
                 {"o": p.org_id, "a": body.active, "r": body.reason, "u": p.user_id})
    audit.record("SOAR_EMERGENCY_STOP" if body.active else "SOAR_EMERGENCY_STOP_LIFTED", "success", org_id=p.org_id, actor_id=p.user_id,
                 actor_label=p.email, resource_type="soar_policy", request_id=request.state.request_id, ip=client_ip(request),
                 details={"reason": body.reason})
    if body.active:
        users = [u.user_id for u in activity.users_with_roles(conn, ["soc_manager", "super_admin", "analyst"]) if u.user_id != p.user_id]
        activity.notify(conn, users, "soar_emergency_stop", "SOAR emergency stop is ON", body.reason, "/app/soar")
    return _policy(conn)


def _stopped(conn: Connection) -> SoarPolicyView | None:
    pol = _policy(conn)
    return pol if pol.emergency_stop else None


# ---------------------------------------------------------------- case evidence and recommendations
def _case_alerts(conn: Connection, case_id: uuid.UUID) -> list:
    return conn.execute(text("""SELECT a.id, a.rule_id, a.rule_level, a.mitre_techniques, a.agent_id, a.agent_groups,
                                       host(a.src_ip) AS src_ip, a.raw, a.severity
                                FROM novrsoc.case_alerts ca JOIN novrsoc.alerts a ON a.id = ca.alert_id AND a.org_id = ca.org_id
                                WHERE ca.case_id = :c ORDER BY a.observed_at"""), {"c": case_id}).all()


def _target(action: str, params: dict, alerts: list) -> tuple[str | None, str | None, list[str]]:
    """(target, agent_id, agent_groups) taken ONLY from the case's alerts; (None, ...) when the evidence has none."""
    if action == "block_ip":
        a = next((x for x in alerts if x.src_ip), None)
        return (a.src_ip, a.agent_id, list(a.agent_groups or [])) if a else (None, None, [])
    if action == "isolate_agent":
        a = next((x for x in alerts if x.agent_id), None)
        return (a.agent_id, a.agent_id, list(a.agent_groups or [])) if a else (None, None, [])
    if action == "disable_account":
        account = str(params.get("account") or "")
        a = next((x for x in alerts if account and account in json.dumps(x.raw or {})), None)
        return (account, a.agent_id, list(a.agent_groups or [])) if a else (None, None, [])
    return None, None, []


@router.get("/recommendations", response_model=RecommendationList, summary="Playbooks whose triggers match a case's alerts")
def recommendations(case_id: uuid.UUID, p: Principal = Depends(require("cases:read")),
                    conn: Connection = Depends(request_connection)) -> RecommendationList:
    if conn.execute(text("SELECT 1 FROM novrsoc.cases WHERE id = :c"), {"c": case_id}).first() is None:
        raise not_found("Case not found")
    alerts = _case_alerts(conn, case_id)
    out = []
    for pb in approved_playbooks(conn):
        t, why = pb.triggers, []
        if t.rule_ids and any(a.rule_id in t.rule_ids for a in alerts):
            why.append("rule " + ", ".join(sorted({a.rule_id for a in alerts if a.rule_id in t.rule_ids})))
        if t.mitre and any(set(a.mitre_techniques or []) & set(t.mitre) for a in alerts):
            why.append("MITRE " + ", ".join(sorted({m for a in alerts for m in (a.mitre_techniques or []) if m in t.mitre})))
        if (t.rule_ids or t.mitre) and not why:
            continue
        if t.min_level and not any(a.rule_level >= t.min_level for a in alerts):
            continue
        targets = {s.step_key: tg for s in pb.steps if s.action.value in CONSEQUENTIAL
                   for tg in [_target(s.action.value, s.parameters, alerts)[0]] if tg}
        out.append(PlaybookRecommendation(playbook=pb, matched_on=why or [f"rule level >= {t.min_level}"], proposed_targets=targets))
    return RecommendationList(case_id=case_id, items=out)


# ---------------------------------------------------------------- runs
def _actor(uid, label) -> ActorRef:
    return ActorRef(type="user", id=uid, label=label or "")


def _run_view(conn: Connection, run_id: uuid.UUID) -> RunView:
    r = conn.execute(text("""SELECT r.*, p.name AS playbook_name FROM novrsoc.soar_runs r
                             JOIN novrsoc.soar_playbooks p ON p.id = r.playbook_id AND p.org_id = r.org_id WHERE r.id = :id"""),
                     {"id": run_id}).first()
    if r is None:
        raise not_found("Run not found")
    steps = conn.execute(text("""SELECT s.*, a.id AS approval_id FROM novrsoc.soar_steps s
                                 LEFT JOIN novrsoc.soar_approvals a ON a.step_id = s.id WHERE s.run_id = :r ORDER BY s.position"""),
                         {"r": run_id}).all()
    return RunView(id=r.id, playbook_id=r.playbook_id, playbook_name=r.playbook_name, playbook_version=r.playbook_version,
                   case_id=r.case_id, mode=r.mode, state=r.state, requested_by=_actor(r.requested_by, r.requested_label),
                   created_at=r.created_at, updated_at=r.updated_at,
                   steps=[StepView(id=s.id, step_key=s.step_key, action=s.action, target=s.target, state=s.state, message=s.message,
                                   request_id=s.request_id, approval_id=s.approval_id,
                                   receipt=ExecutionReceipt.model_validate(s.receipt) if s.receipt else None) for s in steps])


def _settle_run(conn: Connection, run_id: uuid.UUID) -> str:
    states = [r[0] for r in conn.execute(text("SELECT state FROM novrsoc.soar_steps WHERE run_id = :r"), {"r": run_id})]
    if any(s in ("awaiting_approval", "pending") for s in states):
        state = "awaiting_approval"
    elif any(s == "dispatched" for s in states):
        state = "running"
    elif any(s in ("failed", "refused_by_policy", "rejected", "expired") for s in states):
        state = "failed"
    else:
        state = "succeeded"
    conn.execute(text("UPDATE novrsoc.soar_runs SET state = :s, updated_at = now() WHERE id = :r"), {"s": state, "r": run_id})
    return state


def _step(conn, step_id, state, message, **extra) -> None:
    sets = ", ".join(["state = :s", "message = :m", "updated_at = now()"] + [f"{k} = :{k}" for k in extra])
    conn.execute(text(f"UPDATE novrsoc.soar_steps SET {sets} WHERE id = :id"), {"s": state, "m": message[:500], "id": step_id, **extra})


@router.post("/runs", response_model=RunView, status_code=201, summary="Run a playbook for a case (dry run by default)")
def create_run(body: RunCreate, request: Request, p: Principal = Depends(require("response:contain")),
               conn: Connection = Depends(request_connection)):
    existing = conn.execute(text("SELECT id FROM novrsoc.soar_runs WHERE idempotency_key = :k"), {"k": body.idempotency_key}).scalar()
    if existing:
        return JSONResponse(_run_view(conn, existing).model_dump(mode="json"), status_code=200)
    pb = conn.execute(text("SELECT * FROM novrsoc.soar_playbooks WHERE id = :i"), {"i": body.playbook_id}).first()
    if pb is None or pb.version != body.playbook_version:
        raise not_found("Playbook (version) not found")
    if not pb.enabled:
        raise ApiError(409, "conflict", "This playbook is disabled")
    if pb.status != "approved":
        raise ApiError(409, "playbook_not_approved", f"Only an approved playbook version can run (this one is {pb.status})")
    case = conn.execute(text("SELECT severity FROM novrsoc.cases WHERE id = :c"), {"c": body.case_id}).first()
    if case is None:
        raise not_found("Case not found")
    policy, alerts = _policy(conn), _case_alerts(conn, body.case_id)
    if policy.emergency_stop:
        audit.record("SOAR_RUN_REFUSED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="soar_playbook",
                     resource_id=f"{pb.name}@{pb.version}", request_id=request.state.request_id, ip=client_ip(request),
                     details={"reason": "emergency_stop"})
        raise ApiError(409, "emergency_stop", f"The SOAR emergency stop is on: {policy.emergency_reason}")
    ep = PlaybookExecutionPolicy(**(pb.execution_policy or {}))
    if body.mode.value not in [m.value for m in ep.modes]:
        raise ApiError(409, "mode_not_allowed", f"This playbook version may only run in: {', '.join(m.value for m in ep.modes)}")
    if SEV[case.severity] < SEV[ep.min_case_severity]:
        raise ApiError(409, "severity_below_policy", f"This playbook runs only on {ep.min_case_severity} or more severe cases")
    hour = conn.execute(text("SELECT count(*) FROM novrsoc.soar_runs WHERE created_at > now() - interval '1 hour'")).scalar()
    if hour >= policy.max_runs_per_hour:
        raise ApiError(429, "run_limit", f"The organization's limit of {policy.max_runs_per_hour} runs per hour is reached")
    day = conn.execute(text("""SELECT count(*) FROM novrsoc.soar_runs r JOIN novrsoc.soar_playbooks pb ON pb.id = r.playbook_id
                               WHERE pb.name = :n AND r.created_at > now() - interval '24 hours'"""), {"n": pb.name}).scalar()
    if day >= ep.max_runs_per_day:
        raise ApiError(429, "run_limit", f"This playbook's limit of {ep.max_runs_per_day} runs per day is reached")
    run_id = conn.execute(text("""INSERT INTO novrsoc.soar_runs (org_id, playbook_id, playbook_version, case_id, mode, state,
                                    idempotency_key, requested_by, requested_label)
                                  VALUES (:o, :pb, :v, :c, :m, 'pending', :k, :u, :l) RETURNING id"""),
                          {"o": p.org_id, "pb": pb.id, "v": pb.version, "c": body.case_id, "m": body.mode.value,
                           "k": body.idempotency_key, "u": p.user_id, "l": p.email}).scalar()
    _audit(p, request, "SOAR_RUN_REQUESTED", run_id, {"playbook": f"{pb.name}@{pb.version}", "mode": body.mode.value})
    for pos, raw in enumerate(pb.steps):
        s = PlaybookStep(**raw)
        action = s.action.value
        target, agent_id, groups = _target(action, s.parameters, alerts) if action in CONSEQUENTIAL else (None, None, [])
        sid = conn.execute(text("""INSERT INTO novrsoc.soar_steps (org_id, run_id, position, step_key, action, target, parameters, state)
                                   VALUES (:o, :r, :pos, :k, :a, :t, CAST(:pr AS jsonb), 'pending') RETURNING id"""),
                           {"o": p.org_id, "r": run_id, "pos": pos, "k": s.step_key, "a": action, "t": target,
                            "pr": json.dumps({**s.parameters, "_agent_id": agent_id, "_agent_groups": groups})}).scalar()
        if action == "enrich_iocs":
            n = conn.execute(text("""SELECT count(*) FROM novrsoc.ti_matches m JOIN novrsoc.case_alerts ca
                                     ON ca.alert_id = m.alert_id AND ca.org_id = m.org_id WHERE ca.case_id = :c"""),
                             {"c": body.case_id}).scalar()
            _step(conn, sid, "succeeded", f"{n} Threat Insights indicator match(es) on the case's alerts")
        elif action == "create_task":
            conn.execute(text("""INSERT INTO novrsoc.case_events (case_id, org_id, actor_id, actor_label, kind, body)
                                 VALUES (:c, :o, :u, :l, 'note', :b)"""),
                         {"c": body.case_id, "o": p.org_id, "u": p.user_id, "l": p.email,
                          "b": f"Task (playbook {pb.name}): {s.parameters.get('title', s.step_key)}"})
            _step(conn, sid, "succeeded", "Task added to the case timeline")
        elif action in ("notify_email", "notify_ciso"):
            _step(conn, sid, "skipped_not_configured", "No notification adapter is configured; nothing was sent")
        elif target is None:
            _step(conn, sid, "refused_by_policy", "The case's alerts contain no target for this action")
        elif action not in [a.value for a in policy.allowed_actions]:
            _step(conn, sid, "refused_by_policy", f"{action} is not in the organization's response policy")
        elif not set(groups) & set(policy.allowed_agent_groups):
            _step(conn, sid, "refused_by_policy", "The endpoint's Wazuh groups are not authorized by the response policy")
        elif body.mode.value == "live" and not policy.live_enabled:
            _step(conn, sid, "refused_by_policy", "Live mode is not enabled in the organization's response policy")
            _audit(p, request, "SOAR_LIVE_REFUSED", run_id, {"step": s.step_key})
        else:
            expires = _now() + timedelta(minutes=policy.approval_ttl_minutes)
            aid = conn.execute(text("""INSERT INTO novrsoc.soar_approvals (org_id, step_id, action, target, justification,
                                         requested_by, requested_label, expires_at)
                                       VALUES (:o, :s, :a, :t, :j, :u, :l, :e) RETURNING id"""),
                               {"o": p.org_id, "s": sid, "a": action, "t": target, "j": body.justification, "u": p.user_id,
                                "l": p.email, "e": expires}).scalar()
            _step(conn, sid, "awaiting_approval", "Awaiting a human approval (not the requester)")
            _audit(p, request, "SOAR_APPROVAL_REQUESTED", run_id, {"approval_id": str(aid), "action": action, "target": target})
    state = _settle_run(conn, run_id)
    _audit(p, request, "SOAR_RUN_STATE", run_id, {"to": state})
    return _run_view(conn, run_id)


@router.get("/runs", response_model=RunList, summary="Runs of the organization (newest first)")
def list_runs(case_id: uuid.UUID | None = None, limit: int = Query(50, ge=1, le=200), p: Principal = Depends(require("cases:read")),
              conn: Connection = Depends(request_connection)) -> RunList:
    ids = [r[0] for r in conn.execute(text("""SELECT id FROM novrsoc.soar_runs WHERE (CAST(:c AS uuid) IS NULL OR case_id = CAST(:c AS uuid))
                                              ORDER BY created_at DESC LIMIT :n"""), {"c": case_id, "n": limit})]
    return RunList(items=[_run_view(conn, i) for i in ids])


@router.get("/runs/{run_id}", response_model=RunView, summary="One run with its steps, approvals and receipts")
def get_run(run_id: uuid.UUID, p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> RunView:
    return _run_view(conn, run_id)


# ---------------------------------------------------------------- approvals and dispatch
def _approval_view(r) -> ApprovalView:
    return ApprovalView(id=r.id, run_id=r.run_id, step_key=r.step_key, action=r.action, target=r.target, justification=r.justification,
                        requested_by=_actor(r.requested_by, r.requested_label), decision=r.decision,
                        decided_by=_actor(r.decided_by, r.decided_label) if r.decided_by else None, reason=r.reason,
                        expires_at=r.expires_at, created_at=r.created_at)


_APPROVAL_SQL = """SELECT a.*, s.run_id, s.step_key FROM novrsoc.soar_approvals a JOIN novrsoc.soar_steps s ON s.id = a.step_id"""


@router.get("/approvals", response_model=ApprovalList, summary="Approvals of the organization (pending first)")
def list_approvals(pending: bool = False, p: Principal = Depends(require("cases:read")),
                   conn: Connection = Depends(request_connection)) -> ApprovalList:
    rows = conn.execute(text(_APPROVAL_SQL + """ WHERE (NOT :p OR (a.decision IS NULL AND a.expires_at > now()))
                                                 ORDER BY a.decision NULLS FIRST, a.created_at DESC LIMIT 200"""), {"p": pending}).all()
    return ApprovalList(items=[_approval_view(r) for r in rows])


def _dispatch(conn: Connection, settings: Settings, p: Principal, request: Request, step, run, approval) -> None:
    alerts = _case_alerts(conn, run.case_id)
    params = step.parameters or {}
    target, agent_id, groups = _target(step.action, params, alerts)
    policy = _policy(conn)
    attempts = conn.execute(text("UPDATE novrsoc.soar_steps SET dispatch_attempts = dispatch_attempts + 1 WHERE id = :s RETURNING dispatch_attempts"),
                            {"s": step.id}).scalar()
    if target != step.target or step.action not in [a.value for a in policy.allowed_actions] \
            or not set(groups) & set(policy.allowed_agent_groups) or (run.mode == "live" and not policy.live_enabled):
        _step(conn, step.id, "refused_by_policy", "Re-check at dispatch failed: target or authorization changed")
        return
    req = {"v": 1, "request_id": str(step.request_id), "org_id": str(p.org_id), "run_id": str(run.id), "step_key": step.step_key,
           "action": step.action, "agent_id": agent_id, "target": target, "approval_id": str(approval.id),
           "approved_by": str(approval.decided_by), "issued_at": _now().isoformat(),
           "expires_at": (_now() + DISPATCH_TTL).isoformat(), "mode": run.mode}
    try:
        receipt = bridge_client.factory(settings).execute(req)
    except bridge_client.BridgeUnconfigured as e:
        _step(conn, step.id, "failed", f"{e}")
        return
    except bridge_client.BridgeUnavailable as e:
        if attempts >= policy.max_dispatch_attempts:
            _step(conn, step.id, "failed", f"{e}; {attempts} dispatch attempt(s), the policy's limit: failed")
        else:
            _step(conn, step.id, "dispatched", f"{e}; retry dispatch (same request id, executed at most once; attempt {attempts} of "
                                               f"{policy.max_dispatch_attempts})")
        return
    except bridge_client.BridgeProtocolError as e:
        _step(conn, step.id, "failed", f"Receipt refused: {e}")
        return
    state = {"executed": "succeeded", "dry_run": "dry_run", "rejected": "failed", "failed": "failed"}[receipt.status]
    _step(conn, step.id, state, f"Bridge: {receipt.status} ({receipt.reason})", receipt=receipt.model_dump_json())
    _audit(p, request, "SOAR_STEP_EXECUTED", run.id, {"step": step.step_key, "receipt_status": receipt.status,
                                                      "adapter": receipt.adapter, "request_id": str(step.request_id)})


@router.post("/approvals/{approval_id}/decision", response_model=RunView, summary="Approve or reject (not your own request)")
def decide(approval_id: uuid.UUID, body: ApprovalDecisionRequest, request: Request, p: Principal = Depends(require("response:approve")),
           conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> RunView:
    a = conn.execute(text(_APPROVAL_SQL + " WHERE a.id = :id FOR UPDATE OF a"), {"id": approval_id}).first()
    if a is None:
        raise not_found("Approval not found")
    if a.requested_by == p.user_id:
        raise ApiError(403, "forbidden", "Self-approval is not allowed")
    if a.decision is not None:
        raise ApiError(409, "conflict", "This approval was already decided")
    step = conn.execute(text("SELECT * FROM novrsoc.soar_steps WHERE id = :s"), {"s": a.step_id}).one()
    run = conn.execute(text("SELECT * FROM novrsoc.soar_runs WHERE id = :r"), {"r": step.run_id}).one()
    stop = _stopped(conn)
    if stop is not None and body.decision == "approve":
        raise ApiError(409, "emergency_stop", f"The SOAR emergency stop is on: {stop.emergency_reason}. Approvals that would dispatch are blocked.")
    if a.expires_at <= _now():
        # Returned, not raised: the expiry must be committed with the run's new state.
        _step(conn, step.id, "expired", "The approval expired before a decision")
        _settle_run(conn, run.id)
        return JSONResponse({"error": {"code": "conflict", "message": "This approval has expired",
                                       "request_id": request.state.request_id}}, status_code=409)
    conn.execute(text("""UPDATE novrsoc.soar_approvals SET decision = :d, decided_by = :u, decided_label = :l, reason = :r,
                         decided_at = now() WHERE id = :id"""), {"d": body.decision, "u": p.user_id, "l": p.email, "r": body.reason, "id": a.id})
    _audit(p, request, "SOAR_APPROVAL_DECIDED", run.id, {"approval_id": str(a.id), "decision": body.decision})
    if body.decision == "reject":
        _step(conn, step.id, "rejected", f"Rejected by {p.email}: {body.reason}")
    else:
        conn.execute(text("UPDATE novrsoc.soar_steps SET request_id = :q WHERE id = :s"), {"q": uuid.uuid4(), "s": step.id})
        step = conn.execute(text("SELECT * FROM novrsoc.soar_steps WHERE id = :s"), {"s": step.id}).one()
        approval = conn.execute(text("SELECT * FROM novrsoc.soar_approvals WHERE id = :id"), {"id": a.id}).one()
        _dispatch(conn, settings, p, request, step, run, approval)
    _audit(p, request, "SOAR_RUN_STATE", run.id, {"to": _settle_run(conn, run.id)})
    return _run_view(conn, run.id)


@router.post("/steps/{step_id}/dispatch", response_model=RunView, summary="Re-send a dispatched step (same request id)")
def redispatch(step_id: uuid.UUID, request: Request, p: Principal = Depends(require("response:approve")),
               conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> RunView:
    step = conn.execute(text("SELECT * FROM novrsoc.soar_steps WHERE id = :s"), {"s": step_id}).first()
    if step is None:
        raise not_found("Step not found")
    if step.state != "dispatched" or step.request_id is None:
        raise ApiError(409, "conflict", "Only a dispatched step whose receipt is missing can be re-sent")
    stop = _stopped(conn)
    if stop is not None:
        raise ApiError(409, "emergency_stop", f"The SOAR emergency stop is on: {stop.emergency_reason}")
    run = conn.execute(text("SELECT * FROM novrsoc.soar_runs WHERE id = :r"), {"r": step.run_id}).one()
    approval = conn.execute(text("SELECT * FROM novrsoc.soar_approvals WHERE step_id = :s"), {"s": step.id}).one()
    _dispatch(conn, settings, p, request, step, run, approval)
    _settle_run(conn, run.id)
    return _run_view(conn, run.id)


# ---------------------------------------------------------------- operations centre and AI activity
_CATEGORY = {"SOAR_APPROVAL_REQUESTED": "approval", "SOAR_APPROVAL_DECIDED": "approval", "SOAR_POLICY_UPDATED": "policy",
             "SOAR_EMERGENCY_STOP": "policy", "SOAR_EMERGENCY_STOP_LIFTED": "policy", "SOAR_LIVE_REFUSED": "policy"}


def _ai_view(r) -> AiActivityView:
    return AiActivityView(id=r.id, occurred_at=r.occurred_at, kind=r.kind, module=r.module, task=r.task, subject_type=r.subject_type,
                          subject_id=r.subject_id, actor=ActorRef(type=r.actor_type, id=r.actor_id, label=r.actor_label), model=r.model,
                          outcome=r.outcome, summary=r.summary, nhai_job_id=r.nhai_job_id, details=r.details or {})


@router.get("/operations", response_model=SoarOperations, summary="SOAR operations centre: state, limits and the live timeline")
def operations(p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> SoarOperations:
    pol = _policy(conn)
    c = conn.execute(text("""SELECT
        (SELECT count(*) FROM novrsoc.soar_runs WHERE state = 'awaiting_approval') AS awaiting,
        (SELECT count(*) FROM novrsoc.soar_runs WHERE state = 'running') AS running,
        (SELECT count(*) FROM novrsoc.soar_runs WHERE state = 'succeeded' AND updated_at > now() - interval '24 hours') AS done,
        (SELECT count(*) FROM novrsoc.soar_runs WHERE state = 'failed' AND updated_at > now() - interval '24 hours') AS failed,
        (SELECT count(*) FROM novrsoc.soar_steps WHERE state = 'dispatched') AS dispatched,
        (SELECT count(*) FROM novrsoc.soar_steps WHERE state = 'refused_by_policy' AND updated_at > now() - interval '24 hours') AS refused,
        (SELECT count(*) FROM novrsoc.soar_runs WHERE created_at > now() - interval '1 hour') AS hour,
        (SELECT count(*) FROM novrsoc.soar_playbooks WHERE status = 'approved' AND enabled) AS approved,
        (SELECT count(*) FROM novrsoc.soar_playbooks WHERE status = 'pending_approval') AS pending""")).one()
    timeline = [SoarTimelineEntry(at=r.occurred_at, category=_CATEGORY.get(r.action, "playbook" if "PLAYBOOK" in r.action else "execution"),
                                  action=r.action, actor_label=r.actor_label, resource_id=r.resource_id,
                                  summary=", ".join(f"{k}: {v}" for k, v in list((r.details or {}).items())[:4])[:300],
                                  outcome=r.outcome)
                for r in conn.execute(text("""SELECT occurred_at, action, actor_label, resource_id, outcome, details FROM novrsoc.audit_events
                                              WHERE action LIKE 'SOAR\\_%' ORDER BY id DESC LIMIT 60"""))]
    timeline += [SoarTimelineEntry(at=r.occurred_at, category="ai_analysis", action=f"AI_{r.kind.upper()}", actor_label=r.actor_label,
                                   resource_id=f"{r.subject_type}:{r.subject_id}", summary=(r.summary or r.task)[:300], outcome=r.outcome)
                 for r in conn.execute(text("SELECT * FROM novrsoc.ai_activity ORDER BY id DESC LIMIT 40"))]
    timeline.sort(key=lambda t: t.at, reverse=True)
    return SoarOperations(generated_at=_now(), emergency_stop=pol.emergency_stop, emergency_reason=pol.emergency_reason,
                          live_enabled=pol.live_enabled, awaiting_approval=c.awaiting, running=c.running, completed_24h=c.done,
                          failed_24h=c.failed, dispatched_without_receipt=c.dispatched, refused_24h=c.refused,
                          human_intervention=c.awaiting + c.dispatched, runs_last_hour=c.hour, max_runs_per_hour=pol.max_runs_per_hour,
                          approved_playbooks=c.approved, pending_playbook_reviews=c.pending, timeline=timeline[:80])


@router.get("/ai-activity", response_model=AiActivityList, summary="Every AI analysis, recommendation, failure and review (audit)")
def ai_activity(kind: str | None = Query(None, pattern=r"^[a-z_]{3,30}$"), module: str | None = Query(None, pattern=r"^[a-z_]{2,40}$"),
                limit: int = Query(100, ge=1, le=500), p: Principal = Depends(require("cases:read")),
                conn: Connection = Depends(request_connection)) -> AiActivityList:
    rows = conn.execute(text("""SELECT * FROM novrsoc.ai_activity WHERE (CAST(:k AS text) IS NULL OR kind = :k)
                                AND (CAST(:m AS text) IS NULL OR module = :m) ORDER BY id DESC LIMIT :n"""),
                        {"k": kind, "m": module, "n": limit}).all()
    return AiActivityList(items=[_ai_view(r) for r in rows])
