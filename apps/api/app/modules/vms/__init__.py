"""Vulnerability management (workstream B): scopes, scan jobs, the V2 worker protocol, findings, remediation, report.

The VMS worker runs on Server 2 as the compose service `vms-worker` (profile "vms", owner decision), on an internal
network that reaches only the API, with scanning disabled by default. It authenticates with an organization-bound
`vms_worker` identity (`nsk_`, scope `vms:worker`); its organization comes from the identity.

Scanning is controlled by NOVRSOC_VMS_SCANNING:
  disabled            (default) claims answer `scanning_disabled`; scopes may be recorded, scans are refused.
  local_test_targets  development/test only: a scope may only name loopback addresses or *.test / *.localhost names.
  authorized_scopes   production: scopes the organization approves (bounded ranges, no loopback/link-local), held to the
                      organization's scan policy (app.vms.policy): enabled policy, protected networks, weekly windows,
                      target, rate and concurrency caps; assets inside an approved ip/cidr scope enroll automatically.
Scope is checked when a scan is requested, re-checked at claim and again for every observation at ingest (an
observation outside the scope is dropped and counted). Findings are deduplicated per organization by a fingerprint
(host, port, protocol, check), risk-scored (formula 1.0) and prioritized P1-P4 with remediation due dates.
`verified` / `reopened` are set only by scan evidence: a completed scan of the same host that no longer reports a
finding marked fixed_pending_verification verifies it; one that reports it again reopens it.

Consolidation: every host reconciles to the ONE shared asset inventory (no VMS-only asset table); service and
technology observations become the asset's services. Retest requests create a scan job only where scanning is enabled
and a valid scope covers the host, and are resolved by that job's evidence. Schedules (disabled by default) create jobs
only where scanning is enabled. Findings carry CVE intelligence (KEV) from Threat Insights for prioritization.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request, Response
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.assets import reconcile
from app.audit import service as audit
from app.auth.deps import Principal, ServicePrincipal, client_ip, current_service, require
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, forbidden, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from app.vms import policy as vpolicy
from novrsoc_contracts.v1.operations import ComponentHeartbeat
from novrsoc_contracts.v1.platform import AuditEvent, AuditEventList
from novrsoc_contracts.v1.vms import (MANUAL_TRANSITIONS, FindingStatus, FindingTransition, RiskScore, ScanClaimResult, ScanJobClaim,
                                      ScanResultBatch, ScopeEntry, VmsFindingList, VmsFindingView, VmsReport, VmsResultAck,
                                      VmsScanCreate, VmsScanList, VmsScanView, VmsScopeCreate, VmsScopeList, VmsScopeView,
                                      VmsStatus, VmsWorkerStatus, WorkerFinish, FindingCveIntel, RemediationTaskList,
                                      RemediationTaskUpdate, RemediationTaskView, RetestRequest, RiskAssetRow, ServiceList, ServiceRow,
                                      VerificationRequestView, VmsFindingDetail, VmsRiskOverview, VmsScheduleCreate, VmsScheduleList,
                                      VmsScheduleUpdate, VmsScheduleView, VmsEnrollmentEvaluation, VmsEnrollmentExclusion,
                                      VmsEnrollmentList, VmsEnrollmentView, VmsScanPolicy, VmsScanPolicyUpdate)

MODULE = ModuleInfo(name="vms", workstream="B", prefix="/api/v1/vms",
                    summary="Vulnerability management: scopes, scans, worker protocol, findings, remediation, report")
router = APIRouter(prefix="/api/v1/vms", tags=["vms"], responses=ERRORS)
STALE_AFTER = timedelta(seconds=180)
LEASE = timedelta(minutes=30)
FORMULA = "1.0"
SEVERITY_SCORE = {"critical": 95, "high": 75, "medium": 50, "low": 25, "info": 5}
DUE_DAYS = {"P1": 2, "P2": 7, "P3": 30, "P4": 90}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _enabled(settings: Settings) -> bool:
    return settings.vms_scanning in ("local_test_targets", "authorized_scopes")


def _authorized(settings: Settings) -> bool:
    return settings.vms_scanning == "authorized_scopes"


def _target_allowed(settings: Settings, target: str) -> bool:
    """The installation mode's rule for one concrete target (scope membership is checked separately)."""
    if settings.vms_scanning == "local_test_targets":
        return _local_test_target(_kind(target), target)
    if settings.vms_scanning == "authorized_scopes":
        if _kind(target) == "ip":
            return vpolicy.production_scope_problem("ip", target) is None
        return vpolicy.production_scope_problem("domain", target) is None
    return False


def _local_test_target(kind: str, value: str) -> bool:
    if kind in ("ip", "cidr"):
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return net.subnet_of(ipaddress.ip_network("127.0.0.0/8")) if net.version == 4 else net == ipaddress.ip_network("::1/128")
    host = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0].lower() if kind == "url" else value.lower()
    return host == "localhost" or host.endswith(".test") or host.endswith(".localhost")


def _kind(target: str) -> str:
    try:
        ipaddress.ip_address(target)
        return "ip"
    except ValueError:
        return "domain"


def in_scope(target: str, kind: str, value: str) -> bool:
    t = target.strip().lower()
    if kind == "ip":
        return t == value
    if kind == "cidr":
        try:
            return ipaddress.ip_address(t) in ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
    host = value.split("://", 1)[-1].split("/", 1)[0].lower() if kind == "url" else value.lower()
    th = t.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
    return th == host or th.endswith("." + host)


def risk(severity: str, cvss: float | None) -> tuple[RiskScore, str]:
    score = round(cvss * 10) if cvss is not None else SEVERITY_SCORE.get(severity, 25)
    score = max(0, min(100, score))
    priority = "P1" if score >= 90 else "P2" if score >= 70 else "P3" if score >= 40 else "P4"
    return RiskScore(score=score, formula_version=FORMULA, cvss=cvss), priority


def _sev_from_cvss(cvss: float | None) -> str:
    if cvss is None:
        return "info"
    return "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low" if cvss > 0 else "info"


# ---------------------------------------------------------------- scopes and scans (humans)
def _scope_view(r) -> VmsScopeView:
    return VmsScopeView(id=r.id, entry=ScopeEntry(kind=r.kind, value=r.value), allowed_activities=list(r.allowed_activities),
                        authorization_reference=r.authorization_reference, valid_until=r.valid_until, created_at=r.created_at)


@router.get("/scopes", response_model=VmsScopeList, summary="Approved scan scopes of the organization")
def list_scopes(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> VmsScopeList:
    return VmsScopeList(items=[_scope_view(r) for r in conn.execute(text("SELECT * FROM novrsoc.vms_scopes ORDER BY created_at DESC"))])


@router.post("/scopes", response_model=VmsScopeView, status_code=201, summary="Approve a scan scope (vms:scope)")
def create_scope(body: VmsScopeCreate, request: Request, p: Principal = Depends(require("vms:scope")),
                 conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsScopeView:
    e = body.entry
    if e.kind in ("ip", "cidr"):
        try:
            ipaddress.ip_network(e.value, strict=False)
        except ValueError:
            raise ApiError(422, "validation_error", "Not a valid address or range")
    if _authorized(settings):
        problem = vpolicy.production_scope_problem(e.kind, e.value)
        if problem:
            raise ApiError(422, "scope_not_allowed", f"This scope cannot be approved: {problem}")
    elif not _local_test_target(e.kind, e.value):
        raise ApiError(422, "scope_not_allowed", "In this installation a scope may only name a local test target "
                                                 "(loopback address, *.test or *.localhost); production scanning is not enabled")
    r = conn.execute(text("""INSERT INTO novrsoc.vms_scopes (org_id, kind, value, allowed_activities, authorization_reference, approved_by, valid_until)
                             VALUES (:o, :k, :v, :a, :ref, :u, :until)
                             ON CONFLICT (org_id, kind, value) DO UPDATE SET allowed_activities = EXCLUDED.allowed_activities,
                               authorization_reference = EXCLUDED.authorization_reference, valid_until = EXCLUDED.valid_until
                             RETURNING *"""),
                     {"o": p.org_id, "k": e.kind, "v": e.value.lower(), "a": [a.value for a in body.allowed_activities],
                      "ref": body.authorization_reference, "u": p.user_id, "until": _now() + timedelta(days=body.valid_days)}).one()
    audit.record("VMS_SCOPE_APPROVED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_scope",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request), details={"entry": e.model_dump()})
    return _scope_view(r)


def _scan_view(r) -> VmsScanView:
    return VmsScanView(id=r.id, scope_id=r.scope_id, activity=r.activity, targets=list(r.targets), state=r.state, claimed_at=r.claimed_at,
                       finished_at=r.finished_at, outcome=r.outcome or {}, error=r.error, created_at=r.created_at,
                       origin=r.origin, progress=r.progress or {}, asset_ids=list(r.asset_ids or []))


@router.post("/scans", response_model=VmsScanView, status_code=201, summary="Request a scan inside an approved scope (vms:scan)")
def create_scan(body: VmsScanCreate, request: Request, p: Principal = Depends(require("vms:scan")),
                conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)):
    if not _enabled(settings):
        raise ApiError(409, "scanning_disabled", "Scanning is disabled in this installation")
    existing = conn.execute(text("SELECT * FROM novrsoc.vms_scan_jobs WHERE idempotency_key = :k"), {"k": body.idempotency_key}).first()
    if existing:
        return JSONResponse(_scan_view(existing).model_dump(mode="json"), status_code=200)
    s = conn.execute(text("SELECT * FROM novrsoc.vms_scopes WHERE id = :i"), {"i": body.scope_id}).first()
    if s is None:
        raise not_found("Scope not found")
    if s.valid_until <= _now() or body.activity.value not in s.allowed_activities:
        raise ApiError(409, "scope_not_valid", "The scope has expired or does not allow this activity")
    outside = [t for t in body.targets if not in_scope(t, s.kind, s.value)]
    if outside:
        raise ApiError(422, "target_out_of_scope", f"{len(outside)} target(s) are outside the approved scope", {"targets": outside[:20]})
    rate = None
    if _authorized(settings):
        pol, _ = vpolicy.load(conn)
        if not pol["enabled"]:
            raise ApiError(409, "policy_disabled", "The organization's scan policy is not enabled (VMS > Scan policy)")
        if len(body.targets) > pol["max_targets_per_scan"]:
            raise ApiError(422, "too_many_targets", f"The scan policy allows at most {pol['max_targets_per_scan']} targets per scan")
        refused = [t for t in body.targets if not _target_allowed(settings, t) or vpolicy.protected(t, pol["protected_networks"])]
        if refused:
            raise ApiError(422, "target_protected", f"{len(refused)} target(s) are protected or not scannable", {"targets": refused[:20]})
        rate = pol["max_rate_pps"]
    r = conn.execute(text("""INSERT INTO novrsoc.vms_scan_jobs (org_id, scope_id, activity, targets, profile, idempotency_key, requested_by,
                                                                max_rate_pps, progress)
                             VALUES (:o, :s, :a, :t, :pr, :k, :u, :rate, CAST(:pg AS jsonb)) RETURNING *"""),
                     {"o": p.org_id, "s": s.id, "a": body.activity.value, "t": [t.lower() for t in body.targets], "pr": body.profile,
                      "k": body.idempotency_key, "u": p.user_id, "rate": rate,
                      "pg": json.dumps({"targets_total": len(body.targets), "targets_reported": 0, "outcomes": {}})}).one()
    audit.record("VMS_SCAN_REQUESTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_scan",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request), details={"activity": body.activity.value})
    return _scan_view(r)


@router.get("/scans", response_model=VmsScanList, summary="Scan jobs of the organization")
def list_scans(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> VmsScanList:
    return VmsScanList(items=[_scan_view(r) for r in conn.execute(text("SELECT * FROM novrsoc.vms_scan_jobs ORDER BY created_at DESC LIMIT 100"))])


# ---------------------------------------------------------------- findings, remediation, report
_FINDING_SQL = """SELECT f.*, t.due_at, a.display_name AS asset_name,
                         EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev) AS kev
                  FROM novrsoc.vms_findings f
                  LEFT JOIN novrsoc.vms_remediation_tasks t ON t.finding_id = f.id AND t.org_id = f.org_id
                  LEFT JOIN novrsoc.assets a ON a.id = f.asset_id"""


def _finding(r) -> VmsFindingView:
    cvss = float(r.cvss) if r.cvss is not None else None
    return VmsFindingView(id=r.id, host=r.host, port=r.port, protocol=r.protocol, check_id=r.check_id, title=r.title, severity=r.severity,
                          cves=list(r.cves), status=r.status, priority=r.priority,
                          risk=RiskScore(score=r.risk_score, formula_version=FORMULA, cvss=cvss), source=r.source,
                          occurrences=r.occurrences, first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at, remediation_due_at=r.due_at,
                          asset_id=r.asset_id, asset_name=r.asset_name, kev=bool(r.kev))


@router.get("/findings", response_model=VmsFindingList, summary="Findings, highest risk first")
def list_findings(status: str | None = Query(None, pattern=r"^[a-z_]{2,40}$"), limit: int = Query(100, ge=1, le=500),
                  severity: str | None = Query(None, pattern=r"^[a-z]{3,10}$"), priority: str | None = Query(None, pattern=r"^P[1-4]$"),
                  asset_id: uuid.UUID | None = None, q: str | None = Query(None, max_length=200),
                  open_only: bool = False, offset: int = Query(0, ge=0, le=100_000),
                  p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> VmsFindingList:
    where, params = ["true"], {"n": limit, "off": offset}
    for col, val in (("status", status), ("severity", severity), ("priority", priority), ("asset_id", asset_id)):
        if val is not None:
            where.append(f"f.{col} = :{col}"); params[col] = val
    if open_only:
        where.append("f.status NOT IN ('verified', 'risk_accepted')")
    if q:
        where.append("(f.title ILIKE :q OR f.host ILIKE :q OR :qx = ANY(f.cves))"); params["q"], params["qx"] = f"%{q.strip()}%", q.strip().upper()
    cond = " AND ".join(where)
    rows = conn.execute(text(_FINDING_SQL + f" WHERE {cond} ORDER BY f.risk_score DESC, f.last_seen_at DESC LIMIT :n OFFSET :off"), params).all()
    total = conn.execute(text(f"SELECT count(*) FROM novrsoc.vms_findings f WHERE {cond}"), params).scalar()
    return VmsFindingList(items=[_finding(r) for r in rows], total=total)


@router.post("/findings/{finding_id}/transition", response_model=VmsFindingView, summary="Move a finding (manual transitions only)")
def transition(finding_id: uuid.UUID, body: FindingTransition, request: Request, p: Principal = Depends(require("vms:manage")),
               conn: Connection = Depends(request_connection)) -> VmsFindingView:
    if body.finding_id != finding_id:
        raise ApiError(422, "validation_error", "finding_id in the body must match the path")
    f = conn.execute(text("SELECT status FROM novrsoc.vms_findings WHERE id = :i"), {"i": finding_id}).first()
    if f is None:
        raise not_found("Finding not found")
    if body.to_status not in MANUAL_TRANSITIONS[FindingStatus(f.status)]:
        raise ApiError(409, "conflict", f"A finding cannot move from {f.status} to {body.to_status.value} by hand")
    conn.execute(text("UPDATE novrsoc.vms_findings SET status = :s WHERE id = :i"), {"s": body.to_status.value, "i": finding_id})
    task = {"in_progress": "in_progress", "fixed_pending_verification": "in_progress", "risk_accepted": "cancelled"}.get(body.to_status.value)
    if task:
        conn.execute(text("UPDATE novrsoc.vms_remediation_tasks SET status = :s, note = :n, updated_at = now() WHERE finding_id = :i"),
                     {"s": task, "n": body.reason, "i": finding_id})
    audit.record("VMS_FINDING_TRANSITION", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_finding",
                 resource_id=str(finding_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"from": f.status, "to": body.to_status.value})
    return _finding(conn.execute(text(_FINDING_SQL + " WHERE f.id = :i"), {"i": finding_id}).one())


@router.get("/report", response_model=VmsReport, summary="Vulnerability report for the organization")
def report(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> VmsReport:
    def counts(col: str) -> dict[str, int]:
        return {r[0]: r[1] for r in conn.execute(text(f"SELECT {col}, count(*) FROM novrsoc.vms_findings "
                                                      f"WHERE status NOT IN ('verified', 'risk_accepted') GROUP BY {col}"))}
    top = conn.execute(text(_FINDING_SQL + " WHERE f.status NOT IN ('verified', 'risk_accepted') ORDER BY f.risk_score DESC LIMIT 10")).all()
    overdue = conn.execute(text("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()")).scalar()
    scans = conn.execute(text("SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'completed' AND finished_at > now() - interval '30 days'")).scalar()
    by_status = {r[0]: r[1] for r in conn.execute(text("SELECT status, count(*) FROM novrsoc.vms_findings GROUP BY status"))}
    return VmsReport(generated_at=_now(), scanning="enabled" if _enabled(settings) else "disabled", by_priority=counts("priority"),
                     by_status=by_status, by_severity=counts("severity"), overdue_remediation=overdue,
                     top_findings=[_finding(r) for r in top], scans_completed_30d=scans)


@router.get("/status", response_model=VmsStatus, summary="VMS readiness for the active organization")
def status(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> VmsStatus:
    now = _now()
    rows = conn.execute(text("""SELECT h.received_at, h.component_version, h.state, s.name
                                FROM novrsoc.vms_worker_heartbeats h JOIN novrsoc.service_identities s ON s.id = h.identity_id
                                ORDER BY s.name""")).all()
    if settings.vms_scanning == "local_test_targets":
        reason = ("Local test targets only (development): scopes are limited to loopback and *.test / *.localhost names. "
                  "In production NovrVMS only reports health until scanning is approved.")
    elif _authorized(settings):
        reason = ("Authorized scopes: scans run only inside scopes this organization approved, under its enabled scan policy "
                  "(windows, protected networks, rate and concurrency caps), on a worker that declares a route to the target.")
    else:
        reason = "Scanning is disabled in this installation. Workers can report health; they never receive work."
    return VmsStatus(scanning="enabled" if _enabled(settings) else "disabled", reason=reason, workers=[
        VmsWorkerStatus(identity_name=r.name, last_heartbeat_at=r.received_at, component_version=r.component_version,
                        state=r.state, stale=now - r.received_at > STALE_AFTER) for r in rows])


# ---------------------------------------------------------------- worker protocol (machine identity)
def _worker(s: ServicePrincipal, request: Request, conn: Connection) -> None:
    if s.kind != "vms_worker" or "vms:worker" not in s.scopes:
        audit.record("VMS_WORKER_REFUSED", "denied", org_id=s.org_id, actor_type="service", actor_id=s.identity_id,
                     resource_type="service_identity", resource_id=str(s.identity_id), request_id=request.state.request_id,
                     ip=client_ip(request))
        raise forbidden("Only a vms_worker identity with the vms:worker scope may use the worker protocol")
    conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(s.org_id)})


@router.post("/worker/heartbeat", status_code=204, summary="VMS worker: report health (machine identity)")
def heartbeat(body: ComponentHeartbeat, request: Request, s: ServicePrincipal = Depends(current_service),
              conn: Connection = Depends(request_connection)) -> Response:
    _worker(s, request, conn)
    conn.execute(text("""
        INSERT INTO novrsoc.vms_worker_heartbeats (org_id, identity_id, site_id, sent_at, component_version, state, queue_depth, in_flight, dependencies)
        VALUES (:o, :i, :site, :sent, :v, :st, :q, :f, CAST(:d AS jsonb))
        ON CONFLICT (identity_id) DO UPDATE SET sent_at = EXCLUDED.sent_at, received_at = now(), component_version = EXCLUDED.component_version,
          state = EXCLUDED.state, queue_depth = EXCLUDED.queue_depth, in_flight = EXCLUDED.in_flight, dependencies = EXCLUDED.dependencies"""),
        {"o": s.org_id, "i": s.identity_id, "site": s.site_id, "sent": body.sent_at, "v": body.component_version, "st": body.state.value,
         "q": body.queue_depth, "f": body.in_flight, "d": json.dumps([d.model_dump(mode="json") for d in body.dependencies])})
    return Response(status_code=204)


@router.post("/worker/claim", response_model=ScanClaimResult, summary="VMS worker: claim the next scan job of its organization")
def claim(request: Request, s: ServicePrincipal = Depends(current_service), conn: Connection = Depends(request_connection),
          settings: Settings = Depends(get_settings)) -> ScanClaimResult:
    _worker(s, request, conn)
    if not _enabled(settings):
        return ScanClaimResult(job=None, reason="scanning_disabled")
    conn.execute(text("""UPDATE novrsoc.vms_scan_jobs SET state = 'queued', claimed_by = NULL, lease_until = NULL
                         WHERE state = 'running' AND lease_until < now()"""))
    pol = None
    if _authorized(settings):
        pol, _ = vpolicy.load(conn)
        if not pol["enabled"]:
            return ScanClaimResult(job=None, reason="policy_disabled")
        if not vpolicy.in_window(pol):
            return ScanClaimResult(job=None, reason="outside_scan_window")
        running = conn.execute(text("SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'running'")).scalar()
        if running >= pol["max_concurrent_scans"]:
            return ScanClaimResult(job=None, reason="concurrency_limit")
    run_due_schedules(conn, settings)
    job = conn.execute(text("""SELECT j.*, s.kind, s.value, s.valid_until, s.allowed_activities FROM novrsoc.vms_scan_jobs j
                               JOIN novrsoc.vms_scopes s ON s.id = j.scope_id AND s.org_id = j.org_id
                               WHERE j.state = 'queued' ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1""")).first()
    if job is None:
        return ScanClaimResult(job=None, reason="no_job")
    protected_nets = pol["protected_networks"] if pol else []
    if job.valid_until <= _now() or job.activity not in job.allowed_activities or \
            not all(in_scope(t, job.kind, job.value) and _target_allowed(settings, t) and not vpolicy.protected(t, protected_nets)
                    for t in job.targets):
        conn.execute(text("UPDATE novrsoc.vms_scan_jobs SET state = 'failed', error = 'scope re-check failed at claim', finished_at = now() WHERE id = :i"),
                     {"i": job.id})
        return ScanClaimResult(job=None, reason="no_job")
    conn.execute(text("""UPDATE novrsoc.vms_scan_jobs SET state = 'running', claimed_by = :w, claimed_at = now(), lease_until = :l WHERE id = :i"""),
                 {"w": s.identity_id, "l": _now() + LEASE, "i": job.id})
    rates = [x for x in (job.max_rate_pps, pol["max_rate_pps"] if pol else None) if x]
    return ScanClaimResult(reason="job", job=ScanJobClaim(job_id=job.id, activity=job.activity, deadline_at=_now() + LEASE,
                                                          max_runtime_seconds=int(LEASE.total_seconds()),
                                                          targets=[ScopeEntry(kind=_kind(t), value=t) for t in job.targets],
                                                          max_rate_pps=min(rates) if rates else None, protected_networks=protected_nets))


def _running_job(conn: Connection, s: ServicePrincipal, job_id: uuid.UUID):
    job = conn.execute(text("""SELECT j.*, sc.kind, sc.value FROM novrsoc.vms_scan_jobs j JOIN novrsoc.vms_scopes sc
                               ON sc.id = j.scope_id AND sc.org_id = j.org_id WHERE j.id = :i"""), {"i": job_id}).first()
    if job is None or job.claimed_by != s.identity_id:
        raise not_found("Job not found")
    return job


@router.post("/worker/jobs/{job_id}/results", response_model=VmsResultAck, summary="VMS worker: deliver observations (idempotent per batch)")
def results(job_id: uuid.UUID, body: ScanResultBatch, request: Request, s: ServicePrincipal = Depends(current_service),
            conn: Connection = Depends(request_connection)) -> VmsResultAck:
    _worker(s, request, conn)
    if body.job_id != job_id:
        raise ApiError(422, "validation_error", "job_id in the body must match the path")
    job = _running_job(conn, s, job_id)
    prior = conn.execute(text("SELECT observations, new_findings FROM novrsoc.vms_result_batches WHERE batch_id = :b"), {"b": body.batch_id}).first()
    if prior:
        return VmsResultAck(batch_id=body.batch_id, observations=prior.observations, new_findings=prior.new_findings,
                            updated_findings=0, refused_out_of_scope=0, replayed=True)
    if job.state != "running":
        raise ApiError(409, "conflict", "The job is not running")
    new = updated = refused = 0
    assets: dict[str, uuid.UUID] = {}

    def asset_of(host: str, o) -> uuid.UUID | None:
        if host not in assets:
            ids = reconcile.host_identifiers(host)   # a scan target is a host: its IP, or its FQDN and short hostname
            if ids and ids[0][0] == "ip" and vpolicy.address_holders(conn, host) > 1:
                assets[host] = None   # an address two assets report: never guess which device answered
                return None
            if not ids:
                return None
            assets[host] = reconcile.upsert(conn, reconcile.Observation(
                source="vms", kind="host", display_name=host, identifiers=ids,
                attributes={"primary_ip": reconcile.normalize("ip", host), "fqdn": reconcile.normalize("fqdn", host),
                            "hostname": reconcile.normalize("hostname", host) if ids[0][0] != "ip" else None}),
                f"vms job {job_id}").asset_id
        return assets[host]

    for o in body.observations:
        host = o.target.value.lower()
        if not in_scope(host, job.kind, job.value) or host not in job.targets:
            refused += 1
            continue
        if o.kind.value in ("host", "service", "technology"):
            aid = asset_of(host, o)
            if aid is not None and o.kind.value != "host":
                reconcile.upsert(conn, reconcile.Observation(
                    source="vms", kind="host", display_name=host, identifiers=reconcile.host_identifiers(host),
                    services=[{"port": o.port or 0, "protocol": o.protocol or "", "name": o.check_id or "", "product": o.title or ""}]),
                    f"vms job {job_id}")
            continue
        if o.kind.value != "finding":
            continue
        sev = (o.severity.value if o.severity else _sev_from_cvss(o.cvss_v3))
        rs, priority = risk(sev, o.cvss_v3)
        key = hashlib.sha256(f"{host}|{o.port}|{o.protocol}|{o.check_id or o.title}".encode()).hexdigest()
        r = conn.execute(text("""
            INSERT INTO novrsoc.vms_findings (org_id, dedupe_key, host, port, protocol, check_id, title, severity, cvss, cves,
                                              priority, risk_score, source, last_job_id)
            VALUES (novrsoc.app_org(), :k, :h, :p, :pr, :c, :t, :sev, :cvss, :cves, :pri, :score, :src, :j)
            ON CONFLICT (org_id, dedupe_key) DO UPDATE SET last_seen_at = now(), occurrences = vms_findings.occurrences + 1,
              last_job_id = EXCLUDED.last_job_id, severity = EXCLUDED.severity, cvss = EXCLUDED.cvss, risk_score = EXCLUDED.risk_score,
              priority = EXCLUDED.priority,
              status = CASE WHEN vms_findings.status IN ('fixed_pending_verification', 'verified') THEN 'reopened' ELSE vms_findings.status END
            RETURNING id, (xmax = 0) AS inserted"""),
            {"k": key, "h": host, "p": o.port, "pr": o.protocol, "c": o.check_id, "t": o.title or o.check_id or "finding", "sev": sev,
             "cvss": o.cvss_v3, "cves": list(o.cves), "pri": priority, "score": rs.score, "src": job.activity, "j": job_id}).one()
        aid = asset_of(host, o)
        if aid is not None:
            conn.execute(text("UPDATE novrsoc.vms_findings SET asset_id = :a WHERE id = :i AND asset_id IS DISTINCT FROM :a"),
                         {"a": aid, "i": r.id})
        if r.inserted:
            new += 1
            conn.execute(text("""INSERT INTO novrsoc.vms_remediation_tasks (org_id, finding_id, priority, due_at)
                                 VALUES (novrsoc.app_org(), :f, :p, :d) ON CONFLICT (org_id, finding_id) DO NOTHING"""),
                         {"f": r.id, "p": priority, "d": _now() + timedelta(days=DUE_DAYS[priority])})
        else:
            updated += 1
    conn.execute(text("""INSERT INTO novrsoc.vms_result_batches (org_id, batch_id, job_id, observations, new_findings)
                         VALUES (novrsoc.app_org(), :b, :j, :o, :n)"""), {"b": body.batch_id, "j": job_id, "o": len(body.observations), "n": new})
    progress = dict(job.progress or {})
    outcomes = {**progress.get("outcomes", {}), **{t.lower(): o for t, o in body.per_target_outcome.items() if t.lower() in job.targets}}
    progress.update(outcomes=outcomes, targets_total=len(job.targets), targets_reported=len(outcomes),
                    observations=int(progress.get("observations", 0)) + len(body.observations) - refused,
                    refused_out_of_scope=int(progress.get("refused_out_of_scope", 0)) + refused)
    conn.execute(text("UPDATE novrsoc.vms_scan_jobs SET progress = CAST(:pg AS jsonb) WHERE id = :i"), {"pg": json.dumps(progress), "i": job_id})
    return VmsResultAck(batch_id=body.batch_id, observations=len(body.observations), new_findings=new, updated_findings=updated,
                        refused_out_of_scope=refused)


@router.post("/worker/jobs/{job_id}/finish", response_model=VmsScanView, summary="VMS worker: finish a job (verifies fixed findings)")
def finish(job_id: uuid.UUID, body: WorkerFinish, request: Request, s: ServicePrincipal = Depends(current_service),
           conn: Connection = Depends(request_connection)) -> VmsScanView:
    _worker(s, request, conn)
    job = _running_job(conn, s, job_id)
    if job.state != "running":
        raise ApiError(409, "conflict", "The job is not running")
    verified = 0
    outcomes = (job.progress or {}).get("outcomes") or {}
    # A target counts as scanned only when the worker reported it completed: no answer (unreachable, no route) is never
    # evidence that a finding is fixed. A worker that reports no per-target outcome at all completed every target.
    scanned = [t for t in job.targets if outcomes.get(t) == "completed"] if outcomes else list(job.targets)
    if body.outcome == "completed":
        verified = conn.execute(text("""UPDATE novrsoc.vms_findings SET status = 'verified'
                                        WHERE status = 'fixed_pending_verification' AND host = ANY(:h)
                                          AND (last_job_id IS DISTINCT FROM :j)"""), {"h": scanned, "j": job_id}).rowcount
        if job.asset_ids:
            conn.execute(text("""UPDATE novrsoc.vms_enrollments SET last_scanned_at = now(), last_job_id = :j
                                 WHERE asset_id = ANY(:a) AND host(address) = ANY(:h)"""), {"j": job_id, "a": list(job.asset_ids), "h": scanned})
        conn.execute(text("""UPDATE novrsoc.vms_remediation_tasks t SET status = 'done', updated_at = now() FROM novrsoc.vms_findings f
                             WHERE f.id = t.finding_id AND f.status = 'verified' AND t.status <> 'done'"""))
        conn.execute(text("""UPDATE novrsoc.vms_verification_requests v SET updated_at = now(),
                               status = CASE WHEN f.status = 'verified' THEN 'verified' ELSE 'still_present' END
                             FROM novrsoc.vms_findings f WHERE f.id = v.finding_id AND v.scan_job_id = :j AND v.status = 'scan_requested'"""),
                     {"j": job_id})
    r = conn.execute(text("""UPDATE novrsoc.vms_scan_jobs SET state = :st, finished_at = now(), lease_until = NULL, error = :e,
                             outcome = CAST(:o AS jsonb) WHERE id = :i RETURNING *"""),
                     {"st": body.outcome, "e": body.detail if body.outcome == "failed" else None, "i": job_id,
                      "o": json.dumps({"detail": body.detail, "verified": verified, "targets_scanned": len(scanned),
                                       "targets_not_scanned": len(job.targets) - len(scanned)})}).one()
    audit.record("VMS_SCAN_FINISHED", "success", org_id=s.org_id, actor_type="service", actor_id=s.identity_id, resource_type="vms_scan",
                 resource_id=str(job_id), request_id=request.state.request_id, ip=client_ip(request), details={"outcome": body.outcome, "verified": verified})
    return _scan_view(r)



# ---------------------------------------------------------------- consolidation: detail, retest, remediation, risk, schedules
def _verification(r) -> VerificationRequestView:
    return VerificationRequestView(id=r.id, status=r.status, scan_job_id=r.scan_job_id, requested_label=r.requested_label, note=r.note,
                                   created_at=r.created_at, updated_at=r.updated_at)


_TASK_SQL = """SELECT t.*, f.title, f.host, f.asset_id, f.severity, f.status AS finding_status,
                      (SELECT u.email::text FROM novrsoc.users u WHERE u.id = t.assignee_id) AS assignee_label
               FROM novrsoc.vms_remediation_tasks t JOIN novrsoc.vms_findings f ON f.id = t.finding_id"""


def _task(r) -> RemediationTaskView:
    return RemediationTaskView(id=r.id, finding_id=r.finding_id, finding_title=r.title, host=r.host, asset_id=r.asset_id, severity=r.severity,
                               priority=r.priority, status=r.status, finding_status=r.finding_status, due_at=r.due_at,
                               overdue=r.status in ("open", "in_progress") and r.due_at < _now(), assignee_id=r.assignee_id,
                               assignee_label=r.assignee_label, note=r.note, updated_at=r.updated_at)


@router.get("/findings/{finding_id}", response_model=VmsFindingDetail, summary="One finding: CVE intelligence, remediation, verification, history")
def finding_detail(finding_id: uuid.UUID, p: Principal = Depends(require("vms:read")),
                   conn: Connection = Depends(request_connection)) -> VmsFindingDetail:
    r = conn.execute(text(_FINDING_SQL + " WHERE f.id = :i"), {"i": finding_id}).first()
    if r is None:
        raise not_found("Finding not found")
    from app.insights.cve import merged
    intel = conn.execute(text(f"SELECT * FROM ({merged('WHERE cve_id = ANY(:c)')}) m ORDER BY cve_id"), {"c": list(r.cves)}).all()
    known = {i.cve_id for i in intel}
    task = conn.execute(text(_TASK_SQL + " WHERE t.finding_id = :f"), {"f": finding_id}).first()
    ver = conn.execute(text("SELECT * FROM novrsoc.vms_verification_requests WHERE finding_id = :f ORDER BY created_at DESC"), {"f": finding_id}).all()
    hist = conn.execute(text("""SELECT occurred_at, action, actor_label, details FROM novrsoc.audit_events
                                WHERE resource_type = 'vms_finding' AND resource_id = :i ORDER BY id DESC LIMIT 50"""), {"i": str(finding_id)}).all()
    return VmsFindingDetail(
        finding=_finding(r),
        cve_intel=[FindingCveIntel(cve_id=i.cve_id, cvss_v3=float(i.cvss_v3) if i.cvss_v3 is not None else None,
                                   epss=float(i.epss) if i.epss is not None else None, kev=i.kev, description=i.description, source=i.source,
                                   captured_at=i.captured_at) for i in intel],
        cves_without_intel=[c for c in r.cves if c not in known], remediation=_task(task) if task else None,
        verifications=[_verification(v) for v in ver],
        history=[{"at": h.occurred_at.isoformat(), "action": h.action, "actor": h.actor_label, "details": h.details} for h in hist])


@router.post("/findings/{finding_id}/retest", response_model=VerificationRequestView, status_code=201,
             summary="Request a verification scan for one finding (only inside an approved scope, only where scanning is enabled)")
def retest(finding_id: uuid.UUID, body: RetestRequest, request: Request, p: Principal = Depends(require("vms:scan")),
           conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VerificationRequestView:
    f = conn.execute(text("SELECT * FROM novrsoc.vms_findings WHERE id = :i"), {"i": finding_id}).first()
    if f is None:
        raise not_found("Finding not found")
    if f.status in ("verified", "risk_accepted"):
        raise ApiError(409, "conflict", f"A {f.status} finding needs no retest")
    status, job_id = "blocked_scanning_disabled", None
    if _enabled(settings):
        scope = next((s for s in conn.execute(text("SELECT * FROM novrsoc.vms_scopes WHERE valid_until > now()"))
                      if f.source in s.allowed_activities and in_scope(f.host, s.kind, s.value)), None)
        if scope is None:
            status = "blocked_no_scope"
        else:
            job_id = conn.execute(text("""INSERT INTO novrsoc.vms_scan_jobs (org_id, scope_id, activity, targets, profile, idempotency_key,
                                                                            requested_by, origin)
                                          VALUES (:o, :s, :a, :t, 'standard', :k, :u, 'rescan') RETURNING id"""),
                                  {"o": p.org_id, "s": scope.id, "a": f.source, "t": [f.host], "u": p.user_id,
                                   "k": f"retest-{finding_id}-{uuid.uuid4().hex[:12]}"}).scalar()
            status = "scan_requested"
    r = conn.execute(text("""INSERT INTO novrsoc.vms_verification_requests (org_id, finding_id, status, scan_job_id, requested_by,
                                                                            requested_label, note)
                             VALUES (:o, :f, :s, :j, :u, :l, :n) RETURNING *"""),
                     {"o": p.org_id, "f": finding_id, "s": status, "j": job_id, "u": p.user_id, "l": p.email, "n": body.note}).one()
    audit.record("VMS_RETEST_REQUESTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_finding",
                 resource_id=str(finding_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"status": status, "scan_job": str(job_id) if job_id else None})
    return _verification(r)


@router.get("/remediation", response_model=RemediationTaskList, summary="Remediation tasks (overdue first)")
def remediation_tasks(status: str | None = Query(None, pattern=r"^[a-z_]{2,20}$"), assigned: str | None = Query(None, pattern=r"^(me|unassigned)$"),
                      p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> RemediationTaskList:
    where, params = ["true"], {}
    if status:
        where.append("t.status = :s"); params["s"] = status
    if assigned == "me":
        where.append("t.assignee_id = :u"); params["u"] = p.user_id
    elif assigned == "unassigned":
        where.append("t.assignee_id IS NULL")
    rows = conn.execute(text(_TASK_SQL + " WHERE " + " AND ".join(where) +
                             " ORDER BY (t.status IN ('open', 'in_progress') AND t.due_at < now()) DESC, t.due_at LIMIT 500"), params).all()
    items = [_task(r) for r in rows]
    by_status = {r[0]: r[1] for r in conn.execute(text("SELECT status, count(*) FROM novrsoc.vms_remediation_tasks GROUP BY status"))}
    return RemediationTaskList(items=items, by_status=by_status, overdue=sum(1 for i in items if i.overdue))


@router.patch("/remediation/{task_id}", response_model=RemediationTaskView, summary="Assign or annotate a remediation task")
def update_task(task_id: uuid.UUID, body: RemediationTaskUpdate, request: Request, p: Principal = Depends(require("vms:manage")),
                conn: Connection = Depends(request_connection)) -> RemediationTaskView:
    t = conn.execute(text("SELECT * FROM novrsoc.vms_remediation_tasks WHERE id = :i"), {"i": task_id}).first()
    if t is None:
        raise not_found("Remediation task not found")
    if t.status in ("done", "cancelled"):
        raise ApiError(409, "conflict", "A closed task cannot change; verification closes tasks")
    if body.assignee_id is not None and conn.execute(text("""SELECT 1 FROM novrsoc.memberships m JOIN novrsoc.users u ON u.id = m.user_id
                                                            WHERE m.org_id = :o AND m.user_id = :u AND u.status = 'active'"""),
                                                       {"o": p.org_id, "u": body.assignee_id}).first() is None:
        raise ApiError(422, "validation_error", "The assignee must be an active member of this organization")
    conn.execute(text("""UPDATE novrsoc.vms_remediation_tasks SET assignee_id = coalesce(:a, assignee_id),
                           note = CASE WHEN :n <> '' THEN :n ELSE note END, status = coalesce(:s, status), updated_at = now() WHERE id = :i"""),
                 {"a": body.assignee_id, "n": body.note, "s": body.status, "i": task_id})
    audit.record("VMS_REMEDIATION_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_finding",
                 resource_id=str(t.finding_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"assignee": str(body.assignee_id) if body.assignee_id else None, "status": body.status})
    return _task(conn.execute(text(_TASK_SQL + " WHERE t.id = :i"), {"i": task_id}).one())


@router.get("/risk", response_model=VmsRiskOverview, summary="Risk prioritization: priorities, KEV, exposure and the riskiest assets")
def risk_overview(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> VmsRiskOverview:
    open_ = "f.status NOT IN ('verified', 'risk_accepted')"
    by_pri = {r[0]: r[1] for r in conn.execute(text(f"SELECT f.priority, count(*) FROM novrsoc.vms_findings f WHERE {open_} GROUP BY 1"))}
    by_sev = {r[0]: r[1] for r in conn.execute(text(f"SELECT f.severity, count(*) FROM novrsoc.vms_findings f WHERE {open_} GROUP BY 1"))}
    kev = conn.execute(text(f"""SELECT count(*) FROM novrsoc.vms_findings f WHERE {open_}
                                AND EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)""")).scalar()
    exposed = conn.execute(text(f"""SELECT count(*) FROM novrsoc.vms_findings f JOIN novrsoc.assets a ON a.id = f.asset_id
                                    WHERE {open_} AND a.exposure = 'internet_facing'""")).scalar()
    overdue = conn.execute(text("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()")).scalar()
    rows = conn.execute(text(f"""SELECT f.asset_id, coalesce(a.display_name, min(f.host)) AS name, a.criticality, a.exposure, count(*) AS n,
                                        max(f.risk_score) AS max_risk, count(*) FILTER (WHERE f.priority = 'P1') AS p1,
                                        count(*) FILTER (WHERE EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)) AS kev
                                 FROM novrsoc.vms_findings f LEFT JOIN novrsoc.assets a ON a.id = f.asset_id
                                 WHERE {open_} GROUP BY f.asset_id, a.display_name, a.criticality, a.exposure
                                 ORDER BY max(f.risk_score) DESC, count(*) DESC LIMIT 20""")).all()
    return VmsRiskOverview(generated_at=_now(), by_priority=by_pri, by_severity=by_sev, kev_findings=kev, internet_facing_findings=exposed,
                           overdue=overdue, formula=f"Risk formula {FORMULA}: CVSS x 10 when known, else a severity default "
                                                    "(critical 95, high 75, medium 50, low 25, info 5); P1 >= 90, P2 >= 70, P3 >= 40, else P4.",
                           assets=[RiskAssetRow(asset_id=r.asset_id, name=r.name, criticality=r.criticality, exposure=r.exposure,
                                                open_findings=r.n, max_risk=r.max_risk, p1=r.p1, kev=r.kev) for r in rows])


@router.get("/services", response_model=ServiceList, summary="Services and technologies discovered on the organization's assets")
def services(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection)) -> ServiceList:
    rows = conn.execute(text("""SELECT s.*, a.display_name FROM novrsoc.asset_services s JOIN novrsoc.assets a ON a.id = s.asset_id
                                WHERE a.status = 'active' ORDER BY a.display_name, s.port LIMIT 2000""")).all()
    by: dict[str, int] = {}
    for r in rows:
        k = r.product or r.name or f"{r.port}/{r.protocol}"
        by[k] = by.get(k, 0) + 1
    return ServiceList(by_product=dict(sorted(by.items(), key=lambda kv: -kv[1])[:30]), items=[
        ServiceRow(asset_id=r.asset_id, asset_name=r.display_name, port=r.port, protocol=r.protocol, name=r.name, product=r.product,
                   version=r.version, source=r.source, last_seen_at=r.last_seen_at) for r in rows])


@router.get("/audit", response_model=AuditEventList, summary="VMS audit evidence (scopes, scans, findings, remediation, retests)")
def vms_audit(limit: int = Query(200, ge=1, le=500), p: Principal = Depends(require("vms:read")),
              conn: Connection = Depends(request_connection)) -> AuditEventList:
    rows = conn.execute(text("""SELECT id, occurred_at, org_id, actor_type, actor_id, actor_label, action, outcome, resource_type, resource_id,
                                       request_id, details FROM novrsoc.audit_events WHERE action LIKE 'VMS\\_%' ORDER BY id DESC LIMIT :n"""),
                        {"n": limit}).all()
    return AuditEventList(items=[AuditEvent(**r._mapping) for r in rows])


_CADENCE = {"daily": timedelta(days=1), "weekly": timedelta(days=7), "monthly": timedelta(days=30)}


def _schedule(r, settings: Settings) -> VmsScheduleView:
    note = ("Creates a scan job when due." if _enabled(settings) else
            "Scanning is disabled in this installation: a due schedule creates nothing.")
    return VmsScheduleView(id=r.id, scope_id=r.scope_id, name=r.name, activity=r.activity, targets=list(r.targets), cadence=r.cadence,
                           enabled=r.enabled, next_run_at=r.next_run_at, last_job_id=r.last_job_id, created_at=r.created_at, execution=note)


@router.get("/schedules", response_model=VmsScheduleList, summary="Recurring scan schedules")
def list_schedules(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection),
                   settings: Settings = Depends(get_settings)) -> VmsScheduleList:
    return VmsScheduleList(items=[_schedule(r, settings) for r in conn.execute(text("SELECT * FROM novrsoc.vms_scan_schedules ORDER BY name"))])


@router.post("/schedules", response_model=VmsScheduleView, status_code=201, summary="Create a scan schedule inside an approved scope (vms:scope)")
def create_schedule(body: VmsScheduleCreate, request: Request, p: Principal = Depends(require("vms:scope")),
                    conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsScheduleView:
    s = conn.execute(text("SELECT * FROM novrsoc.vms_scopes WHERE id = :i"), {"i": body.scope_id}).first()
    if s is None:
        raise not_found("Scope not found")
    if body.activity.value not in s.allowed_activities:
        raise ApiError(409, "scope_not_valid", "The scope does not allow this activity")
    outside = [t for t in body.targets if not in_scope(t, s.kind, s.value)]
    if outside:
        raise ApiError(422, "target_out_of_scope", f"{len(outside)} target(s) are outside the approved scope", {"targets": outside[:20]})
    try:
        r = conn.execute(text("""INSERT INTO novrsoc.vms_scan_schedules (org_id, scope_id, name, activity, targets, cadence, enabled, next_run_at, created_by)
                                 VALUES (:o, :s, :n, :a, :t, :c, :e, :nx, :u) RETURNING *"""),
                         {"o": p.org_id, "s": s.id, "n": body.name, "a": body.activity.value, "t": [t.lower() for t in body.targets],
                          "c": body.cadence, "e": body.enabled, "nx": _now() + _CADENCE[body.cadence], "u": p.user_id}).one()
    except Exception as e:  # unique name
        if "vms_scan_schedules_org_id_name_key" in str(e):
            raise ApiError(409, "conflict", "A schedule with this name already exists")
        raise
    audit.record("VMS_SCHEDULE_CREATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_schedule",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request), details={"cadence": body.cadence})
    return _schedule(r, settings)


@router.patch("/schedules/{schedule_id}", response_model=VmsScheduleView, summary="Enable or disable a schedule")
def update_schedule(schedule_id: uuid.UUID, body: VmsScheduleUpdate, request: Request, p: Principal = Depends(require("vms:scope")),
                    conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsScheduleView:
    r = conn.execute(text("UPDATE novrsoc.vms_scan_schedules SET enabled = :e WHERE id = :i RETURNING *"), {"e": body.enabled, "i": schedule_id}).first()
    if r is None:
        raise not_found("Schedule not found")
    audit.record("VMS_SCHEDULE_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_schedule",
                 resource_id=str(schedule_id), request_id=request.state.request_id, ip=client_ip(request), details={"enabled": body.enabled})
    return _schedule(r, settings)


def run_due_schedules(conn: Connection, settings: Settings) -> int:
    """Create scan jobs for due, enabled schedules whose scope is still valid. Nothing happens while scanning is disabled."""
    if not _enabled(settings):
        return 0
    made = 0
    for s in conn.execute(text("""SELECT sc.*, sp.valid_until, sp.allowed_activities, sp.kind, sp.value FROM novrsoc.vms_scan_schedules sc
                                  JOIN novrsoc.vms_scopes sp ON sp.id = sc.scope_id WHERE sc.enabled AND sc.next_run_at <= now()
                                  FOR UPDATE OF sc SKIP LOCKED""")).all():
        nxt = _now() + _CADENCE[s.cadence]
        if s.valid_until <= _now() or s.activity not in s.allowed_activities or not all(in_scope(t, s.kind, s.value) for t in s.targets):
            conn.execute(text("UPDATE novrsoc.vms_scan_schedules SET enabled = false WHERE id = :i"), {"i": s.id})
            continue
        job = conn.execute(text("""INSERT INTO novrsoc.vms_scan_jobs (org_id, scope_id, activity, targets, profile, idempotency_key,
                                                                    requested_by, origin)
                                   VALUES (:o, :sc, :a, :t, 'standard', :k, :u, 'schedule') RETURNING id"""),
                           {"o": s.org_id, "sc": s.scope_id, "a": s.activity, "t": list(s.targets), "u": s.created_by,
                            "k": f"schedule-{s.id}-{int(s.next_run_at.timestamp())}"}).scalar()
        conn.execute(text("UPDATE novrsoc.vms_scan_schedules SET next_run_at = :n, last_job_id = :j WHERE id = :i"), {"n": nxt, "j": job, "i": s.id})
        made += 1
    # Enrolled assets of the organization (policy enabled with auto_enroll) that are due for their rescan.
    made += vpolicy.queue_enrollment_scans(conn, target_allowed=lambda t: _target_allowed(settings, t))
    return made


# ---------------------------------------------------------------- organization scan policy and enrollment
def _policy_view(conn: Connection, settings: Settings) -> VmsScanPolicy:
    pol, configured = vpolicy.load(conn)
    label = None
    if pol.get("updated_by"):
        label = conn.execute(text("SELECT email::text FROM novrsoc.users WHERE id = :u"), {"u": pol["updated_by"]}).scalar()
    fields = {k: pol[k] for k in VmsScanPolicyUpdate.model_fields}
    return VmsScanPolicy(**fields, configured=configured, installation_mode=settings.vms_scanning,
                         in_window_now=vpolicy.in_window(pol) if pol["windows"] else False, updated_by_label=label,
                         updated_at=pol.get("updated_at"))


@router.get("/policy", response_model=VmsScanPolicy, summary="The organization's scan policy (standing scan authorization)")
def get_policy(p: Principal = Depends(require("vms:read")), conn: Connection = Depends(request_connection),
               settings: Settings = Depends(get_settings)) -> VmsScanPolicy:
    return _policy_view(conn, settings)


@router.put("/policy", response_model=VmsScanPolicy, summary="Save the organization's scan policy (vms:scope; audited)")
def put_policy(body: VmsScanPolicyUpdate, request: Request, p: Principal = Depends(require("vms:scope")),
               conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsScanPolicy:
    try:
        nets = [str(n) for n in vpolicy.parse_networks(body.protected_networks)]
        vpolicy.tz(body.timezone)
    except ValueError as e:
        raise ApiError(422, "validation_error", str(e))
    if body.enabled and (len(body.authorization_reference.strip()) < 3 or not body.windows):
        raise ApiError(422, "policy_incomplete", "Enabling the scan policy needs an authorization reference and at least one scan window")
    if body.auto_enroll and not body.enabled:
        raise ApiError(422, "policy_incomplete", "Automatic enrollment needs an enabled policy")
    before, configured = vpolicy.load(conn)
    conn.execute(text("""
        INSERT INTO novrsoc.vms_scan_policies (org_id, enabled, auto_enroll, enroll_activity, rescan_interval_days, protected_networks, windows,
                                               timezone, max_targets_per_scan, max_rate_pps, max_concurrent_scans, address_max_age_hours,
                                               authorization_reference, updated_by, updated_at)
        VALUES (novrsoc.app_org(), :en, :ae, :act, :ri, CAST(:pn AS cidr[]), CAST(:w AS jsonb), :tz, :mt, :rate, :mc, :age, :ref, :u, now())
        ON CONFLICT (org_id) DO UPDATE SET enabled = EXCLUDED.enabled, auto_enroll = EXCLUDED.auto_enroll,
          enroll_activity = EXCLUDED.enroll_activity, rescan_interval_days = EXCLUDED.rescan_interval_days,
          protected_networks = EXCLUDED.protected_networks, windows = EXCLUDED.windows, timezone = EXCLUDED.timezone,
          max_targets_per_scan = EXCLUDED.max_targets_per_scan, max_rate_pps = EXCLUDED.max_rate_pps,
          max_concurrent_scans = EXCLUDED.max_concurrent_scans, address_max_age_hours = EXCLUDED.address_max_age_hours,
          authorization_reference = EXCLUDED.authorization_reference, updated_by = EXCLUDED.updated_by, updated_at = now()"""),
        {"en": body.enabled, "ae": body.auto_enroll, "act": body.enroll_activity.value, "ri": body.rescan_interval_days, "pn": nets,
         "w": json.dumps([w.model_dump() for w in body.windows]), "tz": body.timezone, "mt": body.max_targets_per_scan,
         "rate": body.max_rate_pps, "mc": body.max_concurrent_scans, "age": body.address_max_age_hours,
         "ref": body.authorization_reference.strip(), "u": p.user_id})
    counts = vpolicy.evaluate(conn, local_test_only=settings.vms_scanning == "local_test_targets")
    changed = {k: [before.get(k), v] for k, v in body.model_dump(mode="json").items()
               if json.dumps(before.get(k), default=str) != json.dumps(v, default=str)}
    action = "VMS_POLICY_ENABLED" if body.enabled and not before["enabled"] else \
        "VMS_POLICY_DISABLED" if before["enabled"] and not body.enabled else "VMS_POLICY_UPDATED"
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_policy",
                 resource_id=str(p.org_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"changed": changed, "first_save": not configured, "enrollment": counts})
    return _policy_view(conn, settings)


_ENROLL_SQL = """SELECT e.*, host(e.address) AS addr, a.display_name, a.hostname::text AS hostname, sc.value AS scope_value,
                        (SELECT array_agg(DISTINCT src) FROM novrsoc.asset_identifiers i, unnest(i.sources) src WHERE i.asset_id = a.id) AS srcs,
                        (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = a.id
                           AND f.status NOT IN ('verified', 'risk_accepted')) AS open_findings
                 FROM novrsoc.vms_enrollments e JOIN novrsoc.assets a ON a.id = e.asset_id
                 LEFT JOIN novrsoc.vms_scopes sc ON sc.id = e.scope_id"""


def _enrollment(r) -> VmsEnrollmentView:
    return VmsEnrollmentView(asset_id=r.asset_id, asset_name=r.display_name, hostname=r.hostname, address=r.addr, sources=sorted(r.srcs or []),
                             status=r.status, reason=r.reason, scope_id=r.scope_id, scope_value=r.scope_value, evaluated_at=r.evaluated_at,
                             last_scanned_at=r.last_scanned_at, last_job_id=r.last_job_id, open_findings=r.open_findings)


@router.get("/enrollments", response_model=VmsEnrollmentList,
            summary="Every asset of the inventory with its scan enrollment decision and reason")
def list_enrollments(status: str | None = Query(None, pattern=r"^[a-z_]{3,30}$"), p: Principal = Depends(require("vms:read")),
                     conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsEnrollmentList:
    last = conn.execute(text("SELECT max(evaluated_at) FROM novrsoc.vms_enrollments")).scalar()
    unseen = conn.execute(text("""SELECT count(*) FROM novrsoc.assets a WHERE a.status = 'active' AND a.merged_into IS NULL
                                  AND NOT EXISTS (SELECT 1 FROM novrsoc.vms_enrollments e WHERE e.asset_id = a.id)""")).scalar()
    if last is None or unseen or last < _now() - vpolicy.REEVALUATE_AFTER:   # imported assets appear without a manual step
        vpolicy.evaluate(conn, local_test_only=settings.vms_scanning == "local_test_targets")
    rows = conn.execute(text(_ENROLL_SQL + " WHERE a.status = 'active' AND (CAST(:s AS text) IS NULL OR e.status = :s) "
                                           "ORDER BY e.status, lower(a.display_name) LIMIT 2000"), {"s": status}).all()
    by = {r.status: r.n for r in conn.execute(text("""SELECT e.status, count(*) AS n FROM novrsoc.vms_enrollments e
                                                      JOIN novrsoc.assets a ON a.id = e.asset_id WHERE a.status = 'active' GROUP BY 1"""))}
    return VmsEnrollmentList(items=[_enrollment(r) for r in rows], by_status=by,
                             evaluated_at=conn.execute(text("SELECT max(evaluated_at) FROM novrsoc.vms_enrollments")).scalar())


@router.post("/enrollments/evaluate", response_model=VmsEnrollmentEvaluation,
             summary="Re-evaluate enrollment now and queue due enrollment scans (vms:scope; audited)")
def evaluate_enrollments(request: Request, p: Principal = Depends(require("vms:scope")), conn: Connection = Depends(request_connection),
                         settings: Settings = Depends(get_settings)) -> VmsEnrollmentEvaluation:
    counts = vpolicy.evaluate(conn, local_test_only=settings.vms_scanning == "local_test_targets")
    queued = vpolicy.queue_enrollment_scans(conn, target_allowed=lambda t: _target_allowed(settings, t)) if _enabled(settings) else 0
    audit.record("VMS_ENROLLMENT_EVALUATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="vms_policy",
                 resource_id=str(p.org_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"by_status": counts, "scans_queued": queued})
    return VmsEnrollmentEvaluation(evaluated=sum(counts.values()), by_status=counts, scans_queued=queued)


@router.post("/enrollments/{asset_id}/exclusion", response_model=VmsEnrollmentView,
             summary="Exclude one asset from scanning, or lift its exclusion (vms:scope; audited)")
def set_exclusion(asset_id: uuid.UUID, body: VmsEnrollmentExclusion, request: Request, p: Principal = Depends(require("vms:scope")),
                  conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> VmsEnrollmentView:
    if conn.execute(text("SELECT 1 FROM novrsoc.assets WHERE id = :a"), {"a": asset_id}).first() is None:
        raise not_found("Asset not found")
    if body.excluded:
        conn.execute(text("""INSERT INTO novrsoc.vms_enrollments (org_id, asset_id, status, reason, excluded_by)
                             VALUES (novrsoc.app_org(), :a, 'manual_exclusion', :r, :u)
                             ON CONFLICT (org_id, asset_id) DO UPDATE SET status = 'manual_exclusion', reason = EXCLUDED.reason,
                               excluded_by = EXCLUDED.excluded_by, scope_id = NULL, evaluated_at = now()"""),
                     {"a": asset_id, "r": body.reason, "u": p.user_id})
    else:
        conn.execute(text("UPDATE novrsoc.vms_enrollments SET status = 'outside_scope', excluded_by = NULL WHERE asset_id = :a"), {"a": asset_id})
        vpolicy.evaluate(conn, local_test_only=settings.vms_scanning == "local_test_targets")
    audit.record("VMS_ASSET_EXCLUDED" if body.excluded else "VMS_ASSET_EXCLUSION_LIFTED", "success", org_id=p.org_id, actor_id=p.user_id,
                 actor_label=p.email, resource_type="asset", resource_id=str(asset_id), request_id=request.state.request_id,
                 ip=client_ip(request), details={"reason": body.reason})
    return _enrollment(conn.execute(text(_ENROLL_SQL + " WHERE e.asset_id = :a"), {"a": asset_id}).one())
