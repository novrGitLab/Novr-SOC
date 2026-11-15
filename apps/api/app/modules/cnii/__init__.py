"""CNII Watch (pilot): designation-based authorization for Critical National Information Infrastructure.

A permission is necessary but never sufficient: every sector read also needs an explicit, unexpired, unrevoked
designation covering the sector (app/authz/cnii.require_cnii; the SECURITY DEFINER overview function re-checks it).
Designations and organization CNII profiles are granted and maintained by platform administrators, always audited,
always expiring. The sector overview shows aggregate counts only (open alerts, critical alerts in 7 days, open cases)
for the organizations the designation covers.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, current_principal, require
from app.authz.cnii import Designation, require_cnii
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.governance import (CniiDesignation, CniiDesignationGrant, CniiDesignationList, CniiDesignationRevoke,
                                             CniiOrgProfile, CniiOrgProfileList, CniiOrgProfileSet, CniiSectorOverview, CniiSectorRow)

MODULE = ModuleInfo(name="cnii", workstream="E", prefix="/api/v1/cnii",
                    summary="CNII Watch: designations, organization profiles and designation-gated sector overviews")
router = APIRouter(prefix="/api/v1/cnii", tags=["cnii"], responses=ERRORS)


def _designation(r) -> CniiDesignation:
    return CniiDesignation(id=r.id, user_id=r.user_id, sectors=list(r.sectors),
                           scope_org_ids=list(r.scope_org_ids) if r.scope_org_ids is not None else None,
                           granted_by=r.granted_by or r.user_id, granted_at=r.granted_at, expires_at=r.expires_at, revoked_at=r.revoked_at)


@router.get("/designations/mine", response_model=CniiDesignationList, summary="The signed-in user's CNII designations")
def mine(p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> CniiDesignationList:
    rows = conn.execute(text("SELECT * FROM novrsoc.cnii_designations WHERE user_id = :u ORDER BY expires_at DESC"), {"u": p.user_id})
    return CniiDesignationList(items=[_designation(r) for r in rows])


@router.get("/designations", response_model=CniiDesignationList, summary="All CNII designations (platform administrators)")
def all_designations(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> CniiDesignationList:
    return CniiDesignationList(items=[_designation(r) for r in conn.execute(text("SELECT * FROM novrsoc.cnii_designations ORDER BY granted_at DESC"))])


@router.post("/designations", response_model=CniiDesignation, status_code=201, summary="Grant a CNII designation (always expires)")
def grant(body: CniiDesignationGrant, request: Request, p: Principal = Depends(require("users:manage")),
          conn: Connection = Depends(request_connection)) -> CniiDesignation:
    if conn.execute(text("SELECT 1 FROM novrsoc.users WHERE id = :u"), {"u": body.user_id}).first() is None:
        raise not_found("User not found")
    if body.user_id == p.user_id:
        raise ApiError(403, "forbidden", "Administrators cannot designate themselves")
    r = conn.execute(text("""INSERT INTO novrsoc.cnii_designations (user_id, sectors, scope_org_ids, reason, granted_by, expires_at)
                             VALUES (:u, :s, :o, :r, :g, :x) RETURNING *"""),
                     {"u": body.user_id, "s": [s.value if hasattr(s, "value") else s for s in body.sectors], "o": body.scope_org_ids,
                      "r": body.reason, "g": p.user_id, "x": body.expires_at}).one()
    audit.record("CNII_DESIGNATION_GRANTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="cnii_designation", resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"user": str(body.user_id), "sectors": list(r.sectors), "expires_at": body.expires_at.isoformat()})
    return _designation(r)


@router.post("/designations/{designation_id}/revoke", response_model=CniiDesignation, summary="Revoke a CNII designation")
def revoke(designation_id: uuid.UUID, body: CniiDesignationRevoke, request: Request, p: Principal = Depends(require("users:manage")),
           conn: Connection = Depends(request_connection)) -> CniiDesignation:
    if body.designation_id != designation_id:
        raise ApiError(422, "validation_error", "designation_id in the body must match the path")
    r = conn.execute(text("UPDATE novrsoc.cnii_designations SET revoked_at = now() WHERE id = :i AND revoked_at IS NULL RETURNING *"),
                     {"i": designation_id}).first()
    if r is None:
        raise not_found("Active designation not found")
    audit.record("CNII_DESIGNATION_REVOKED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="cnii_designation", resource_id=str(designation_id), request_id=request.state.request_id,
                 ip=client_ip(request), details={"reason": body.reason})
    return _designation(r)


@router.get("/profiles", response_model=CniiOrgProfileList, summary="Organization CNII profiles (platform administrators)")
def profiles(p: Principal = Depends(require("users:manage")), conn: Connection = Depends(request_connection)) -> CniiOrgProfileList:
    rows = conn.execute(text("""SELECT c.*, o.name FROM novrsoc.cnii_org_profiles c JOIN novrsoc.organizations o ON o.id = c.org_id ORDER BY o.name"""))
    return CniiOrgProfileList(items=[CniiOrgProfile(org_id=r.org_id, org_name=r.name, sectors=list(r.sectors), criticality=r.criticality,
                                                    updated_at=r.updated_at) for r in rows])


@router.put("/profiles", response_model=CniiOrgProfile, summary="Set an organization's CNII sectors and criticality")
def set_profile(body: CniiOrgProfileSet, request: Request, p: Principal = Depends(require("users:manage")),
                conn: Connection = Depends(request_connection)) -> CniiOrgProfile:
    name = conn.execute(text("SELECT name FROM novrsoc.organizations WHERE id = :o"), {"o": body.org_id}).scalar()
    if name is None:
        raise not_found("Organization not found")
    r = conn.execute(text("""INSERT INTO novrsoc.cnii_org_profiles (org_id, sectors, criticality, updated_by) VALUES (:o, :s, :c, :u)
                             ON CONFLICT (org_id) DO UPDATE SET sectors = EXCLUDED.sectors, criticality = EXCLUDED.criticality,
                               updated_by = EXCLUDED.updated_by, updated_at = now() RETURNING *"""),
                     {"o": body.org_id, "s": [s.value if hasattr(s, "value") else s for s in body.sectors], "c": body.criticality,
                      "u": p.user_id}).one()
    audit.record("CNII_PROFILE_SET", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="cnii_profile",
                 resource_id=str(body.org_id), request_id=request.state.request_id, ip=client_ip(request), details={"sectors": list(r.sectors)})
    return CniiOrgProfile(org_id=r.org_id, org_name=name, sectors=list(r.sectors), criticality=r.criticality, updated_at=r.updated_at)


@router.get("/sector-overview", response_model=CniiSectorOverview, summary="Sector overview (permission AND designation)")
def sector_overview(d: Designation = Depends(require_cnii("cnii:sector")), conn: Connection = Depends(request_connection)) -> CniiSectorOverview:
    expires = conn.execute(text("SELECT expires_at FROM novrsoc.cnii_designations WHERE id = :i"), {"i": d.id}).scalar()
    rows = conn.execute(text("SELECT * FROM novrsoc.cnii_sector_overview(:s)"), {"s": d.sector}).all()
    return CniiSectorOverview(sector=d.sector, designation_id=d.id, designation_expires_at=expires,
                              items=[CniiSectorRow(org_id=r.org_id, org_name=r.org_name, criticality=r.criticality, open_alerts=r.open_alerts,
                                                   critical_alerts_7d=r.critical_alerts_7d, open_cases=r.open_cases) for r in rows])


# ---------------------------------------------------------------- consolidation: CNII monitoring scope (active organization)
# Monitoring exists ONLY for explicitly designated assets of the active organization, each under an active
# authorization record. Every endpoint needs the permission AND an active designation covering the organization, and
# it only shows or accepts the sectors that designation covers. Nothing here discovers or scans third-party
# infrastructure; no availability probe is configured, so a due check is recorded as `not_run` with the reason.
from datetime import datetime, timedelta, timezone  # noqa: E402

from fastapi import Request as _Request  # noqa: E402

from novrsoc_contracts.v1.governance import (CniiAuthorizationCreate, CniiAuthorizationList, CniiAuthorizationRevoke,  # noqa: E402
                                             CniiAuthorizationView, CniiCheckView, CniiMonitoredAssetCreate, CniiMonitoredAssetList,
                                             CniiMonitoredAssetStatus, CniiMonitoredAssetView, CniiOverview, CniiScheduleSet,
                                             CniiScheduleView)

PROBE = ("No availability probe is configured in this installation: due checks are recorded as not_run, never as up. "
         "A probe on Server 1 needs separate authorization.")


class CniiScope:
    def __init__(self, sectors: set[str], designation_ids: list[uuid.UUID]):
        self.sectors, self.designation_ids = sectors, designation_ids


def cnii_scope(permission: str):
    def dep(request: _Request, p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> CniiScope:
        def deny(reason: str):
            audit.record("CNII_ACCESS_DENIED", "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                         resource_type="cnii_monitoring", resource_id=str(p.org_id), request_id=request.state.request_id,
                         ip=client_ip(request), details={"reason": reason, "permission": permission})
            return ApiError(403, "forbidden", "CNII monitoring requires the permission and an explicit CNII designation",
                            {"required": permission, "designation": "required"})
        if not p.has(permission):
            raise deny("missing permission")
        rows = conn.execute(text("""SELECT id, sectors FROM novrsoc.cnii_designations WHERE user_id = novrsoc.app_user()
                                    AND revoked_at IS NULL AND expires_at > now()
                                    AND (scope_org_ids IS NULL OR :o = ANY(scope_org_ids))"""), {"o": p.org_id}).all()
        if not rows:
            raise deny("no active designation covering the organization")
        return CniiScope({s for r in rows for s in r.sectors}, [r.id for r in rows])
    return dep


def _auth_state(r) -> str:
    now = datetime.now(timezone.utc)
    if r.revoked_at is not None:
        return "revoked"
    if r.valid_from > now:
        return "not_yet_valid"
    return "expired" if r.valid_until <= now else "active"


def _authorization(r, count: int = 0) -> CniiAuthorizationView:
    return CniiAuthorizationView(id=r.id, reference=r.reference, issuing_authority=r.issuing_authority, scope_description=r.scope_description,
                                 sectors=list(r.sectors), valid_from=r.valid_from, valid_until=r.valid_until, document_sha256=r.document_sha256,
                                 state=_auth_state(r), recorded_by=r.recorded_label, revoked_at=r.revoked_at, revoked_reason=r.revoked_reason,
                                 monitored_assets=count, created_at=r.created_at)


def _audit_cnii(p: Principal, request: _Request, action: str, rid: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="cnii_monitoring",
                 resource_id=rid, request_id=request.state.request_id, ip=client_ip(request), details=details or {})


@router.get("/authorizations", response_model=CniiAuthorizationList, summary="Monitoring authorization records (designated sectors only)")
def list_authorizations(s: CniiScope = Depends(cnii_scope("cnii:read")), conn: Connection = Depends(request_connection)) -> CniiAuthorizationList:
    rows = conn.execute(text("""SELECT a.*, (SELECT count(*) FROM novrsoc.cnii_monitored_assets m WHERE m.authorization_id = a.id) AS n
                                FROM novrsoc.cnii_authorizations a WHERE a.sectors && :s ORDER BY a.valid_until DESC"""),
                        {"s": sorted(s.sectors)}).all()
    return CniiAuthorizationList(items=[_authorization(r, r.n) for r in rows])


@router.post("/authorizations", response_model=CniiAuthorizationView, status_code=201, summary="Record a monitoring authorization")
def create_authorization(body: CniiAuthorizationCreate, request: _Request, s: CniiScope = Depends(cnii_scope("cnii:manage")),
                         p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> CniiAuthorizationView:
    outside = sorted(set(body.sectors) - s.sectors)
    if outside:
        raise ApiError(403, "forbidden", "Your CNII designation does not cover these sectors", {"sectors": outside})
    if conn.execute(text("SELECT 1 FROM novrsoc.cnii_authorizations WHERE reference = :r"), {"r": body.reference}).first():
        raise ApiError(409, "conflict", "An authorization with this reference already exists")
    r = conn.execute(text("""INSERT INTO novrsoc.cnii_authorizations (org_id, reference, issuing_authority, scope_description, sectors, valid_from,
                                                                      valid_until, document_sha256, recorded_by, recorded_label)
                             VALUES (:o, :ref, :ia, :sd, :sec, :vf, :vu, :doc, :u, :l) RETURNING *"""),
                     {"o": p.org_id, "ref": body.reference, "ia": body.issuing_authority, "sd": body.scope_description, "sec": list(body.sectors),
                      "vf": body.valid_from, "vu": body.valid_until, "doc": body.document_sha256, "u": p.user_id, "l": p.email}).one()
    _audit_cnii(p, request, "CNII_AUTHORIZATION_RECORDED", str(r.id), {"reference": body.reference, "sectors": list(body.sectors),
                                                                        "valid_until": body.valid_until.isoformat()})
    return _authorization(r)


@router.post("/authorizations/{authorization_id}/revoke", response_model=CniiAuthorizationView,
             summary="Revoke an authorization (its assets' schedules stop)")
def revoke_authorization(authorization_id: uuid.UUID, body: CniiAuthorizationRevoke, request: _Request,
                         s: CniiScope = Depends(cnii_scope("cnii:manage")), p: Principal = Depends(current_principal),
                         conn: Connection = Depends(request_connection)) -> CniiAuthorizationView:
    r = conn.execute(text("""UPDATE novrsoc.cnii_authorizations SET revoked_at = now(), revoked_reason = :r
                             WHERE id = :i AND revoked_at IS NULL AND sectors && :s RETURNING *"""),
                     {"r": body.reason, "i": authorization_id, "s": sorted(s.sectors)}).first()
    if r is None:
        raise not_found("Active authorization not found")
    conn.execute(text("""UPDATE novrsoc.cnii_schedules sc SET enabled = false FROM novrsoc.cnii_monitored_assets m
                         WHERE m.id = sc.monitored_asset_id AND m.authorization_id = :i"""), {"i": authorization_id})
    _audit_cnii(p, request, "CNII_AUTHORIZATION_REVOKED", str(authorization_id), {"reason": body.reason})
    return _authorization(r)


_MA_SQL = """SELECT m.*, a.display_name, a.kind AS asset_kind, z.reference, z.valid_from, z.valid_until, z.revoked_at,
                    (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = m.asset_id AND f.status NOT IN ('verified', 'risk_accepted')) AS open_f,
                    (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = m.asset_id AND f.status NOT IN ('verified', 'risk_accepted')
                       AND f.severity = 'critical') AS crit_f
             FROM novrsoc.cnii_monitored_assets m JOIN novrsoc.assets a ON a.id = m.asset_id
             JOIN novrsoc.cnii_authorizations z ON z.id = m.authorization_id"""


def _check(r) -> CniiCheckView:
    return CniiCheckView(id=r.id, kind=r.kind, observed_at=r.observed_at, outcome=r.outcome, latency_ms=r.latency_ms, detail=r.detail, source=r.source)


def _schedule_view(r) -> CniiScheduleView:
    return CniiScheduleView(id=r.id, check_kind=r.check_kind, interval_minutes=r.interval_minutes, enabled=r.enabled, next_due_at=r.next_due_at,
                            last_run_at=r.last_run_at, execution=PROBE if r.check_kind == "availability" else
                            "Vulnerability checks are VMS scans: they run only where scanning is enabled, inside an approved scope.")


def _monitored(conn: Connection, r) -> CniiMonitoredAssetView:
    last = conn.execute(text("SELECT * FROM novrsoc.cnii_checks WHERE monitored_asset_id = :m ORDER BY observed_at DESC LIMIT 1"), {"m": r.id}).first()
    avail = conn.execute(text("""SELECT count(*) FILTER (WHERE outcome = 'up') AS up, count(*) FILTER (WHERE outcome IN ('up', 'down', 'degraded')) AS n
                                 FROM novrsoc.cnii_checks WHERE monitored_asset_id = :m AND kind = 'availability'
                                 AND observed_at > now() - interval '30 days'"""), {"m": r.id}).one()
    sched = conn.execute(text("SELECT * FROM novrsoc.cnii_schedules WHERE monitored_asset_id = :m ORDER BY check_kind"), {"m": r.id}).all()
    return CniiMonitoredAssetView(id=r.id, asset_id=r.asset_id, asset_name=r.display_name, asset_kind=r.asset_kind,
                                  authorization_id=r.authorization_id, authorization_reference=r.reference,
                                  authorization_state=_auth_state(r), sector=r.sector, owning_unit=r.owning_unit, monitoring=r.monitoring,
                                  status=r.status, open_findings=r.open_f, critical_findings=r.crit_f, last_check=_check(last) if last else None,
                                  availability_30d=round(avail.up / avail.n, 4) if avail.n else None,
                                  schedules=[_schedule_view(x) for x in sched], created_at=r.created_at)


@router.get("/monitored-assets", response_model=CniiMonitoredAssetList, summary="Designated CNII assets (designated sectors only)")
def list_monitored(s: CniiScope = Depends(cnii_scope("cnii:read")), conn: Connection = Depends(request_connection)) -> CniiMonitoredAssetList:
    rows = conn.execute(text(_MA_SQL + " WHERE m.sector = ANY(:s) ORDER BY m.sector, a.display_name"), {"s": sorted(s.sectors)}).all()
    return CniiMonitoredAssetList(items=[_monitored(conn, r) for r in rows])


@router.post("/monitored-assets", response_model=CniiMonitoredAssetView, status_code=201,
             summary="Designate an asset for CNII monitoring (needs an active authorization covering the sector)")
def designate_asset(body: CniiMonitoredAssetCreate, request: _Request, s: CniiScope = Depends(cnii_scope("cnii:manage")),
                    p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> CniiMonitoredAssetView:
    if body.sector not in s.sectors:
        raise ApiError(403, "forbidden", "Your CNII designation does not cover this sector")
    z = conn.execute(text("SELECT * FROM novrsoc.cnii_authorizations WHERE id = :i"), {"i": body.authorization_id}).first()
    if z is None:
        raise not_found("Authorization not found")
    if _auth_state(z) != "active":
        raise ApiError(409, "authorization_not_active", f"The authorization is {_auth_state(z)}; nothing can be monitored under it")
    if body.sector not in z.sectors:
        raise ApiError(422, "validation_error", "The authorization does not cover this sector")
    a = conn.execute(text("SELECT status FROM novrsoc.assets WHERE id = :i"), {"i": body.asset_id}).first()
    if a is None:
        raise not_found("Asset not found")
    if a.status != "active":
        raise ApiError(409, "conflict", "A retired asset cannot be designated")
    if conn.execute(text("SELECT 1 FROM novrsoc.cnii_monitored_assets WHERE asset_id = :a"), {"a": body.asset_id}).first():
        raise ApiError(409, "conflict", "This asset is already designated")
    mid = conn.execute(text("""INSERT INTO novrsoc.cnii_monitored_assets (org_id, asset_id, authorization_id, sector, owning_unit, monitoring,
                                                                          designated_by, designated_label)
                               VALUES (:o, :a, :z, :s, :ou, :m, :u, :l) RETURNING id"""),
                       {"o": p.org_id, "a": body.asset_id, "z": z.id, "s": body.sector, "ou": body.owning_unit, "m": body.monitoring,
                        "u": p.user_id, "l": p.email}).scalar()
    _audit_cnii(p, request, "CNII_ASSET_DESIGNATED", str(mid), {"asset": str(body.asset_id), "sector": body.sector, "authorization": z.reference})
    return _monitored(conn, conn.execute(text(_MA_SQL + " WHERE m.id = :i"), {"i": mid}).one())


def _ma(conn: Connection, s: CniiScope, mid: uuid.UUID):
    r = conn.execute(text(_MA_SQL + " WHERE m.id = :i AND m.sector = ANY(:s)"), {"i": mid, "s": sorted(s.sectors)}).first()
    if r is None:
        raise not_found("Monitored asset not found")
    return r


@router.post("/monitored-assets/{monitored_id}/status", response_model=CniiMonitoredAssetView, summary="Suspend or resume monitoring")
def set_monitored_status(monitored_id: uuid.UUID, body: CniiMonitoredAssetStatus, request: _Request,
                         s: CniiScope = Depends(cnii_scope("cnii:manage")), p: Principal = Depends(current_principal),
                         conn: Connection = Depends(request_connection)) -> CniiMonitoredAssetView:
    r = _ma(conn, s, monitored_id)
    if body.status == "active" and _auth_state(r) != "active":
        raise ApiError(409, "authorization_not_active", "Monitoring cannot resume: the authorization is not active")
    conn.execute(text("UPDATE novrsoc.cnii_monitored_assets SET status = :s WHERE id = :i"), {"s": body.status, "i": monitored_id})
    if body.status == "suspended":
        conn.execute(text("UPDATE novrsoc.cnii_schedules SET enabled = false WHERE monitored_asset_id = :i"), {"i": monitored_id})
    _audit_cnii(p, request, "CNII_MONITORING_STATUS", str(monitored_id), {"status": body.status, "reason": body.reason})
    return _monitored(conn, _ma(conn, s, monitored_id))


@router.put("/monitored-assets/{monitored_id}/schedule", response_model=CniiMonitoredAssetView, summary="Set a monitoring schedule")
def set_schedule(monitored_id: uuid.UUID, body: CniiScheduleSet, request: _Request, s: CniiScope = Depends(cnii_scope("cnii:manage")),
                 p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> CniiMonitoredAssetView:
    r = _ma(conn, s, monitored_id)
    if body.enabled and (_auth_state(r) != "active" or r.status != "active"):
        raise ApiError(409, "authorization_not_active", "A schedule can only be enabled for an active asset under an active authorization")
    conn.execute(text("""INSERT INTO novrsoc.cnii_schedules (org_id, monitored_asset_id, check_kind, interval_minutes, enabled, next_due_at)
                         VALUES (:o, :m, :k, :i, :e, now() + make_interval(mins => :i))
                         ON CONFLICT (monitored_asset_id, check_kind) DO UPDATE SET interval_minutes = EXCLUDED.interval_minutes,
                           enabled = EXCLUDED.enabled, next_due_at = EXCLUDED.next_due_at"""),
                 {"o": p.org_id, "m": monitored_id, "k": body.check_kind, "i": body.interval_minutes, "e": body.enabled})
    _audit_cnii(p, request, "CNII_SCHEDULE_SET", str(monitored_id), body.model_dump())
    return _monitored(conn, _ma(conn, s, monitored_id))


@router.get("/monitored-assets/{monitored_id}/checks", response_model=list[CniiCheckView], summary="Recorded checks (newest first)")
def checks(monitored_id: uuid.UUID, s: CniiScope = Depends(cnii_scope("cnii:read")), conn: Connection = Depends(request_connection)) -> list[CniiCheckView]:
    _ma(conn, s, monitored_id)
    return [_check(r) for r in conn.execute(text("""SELECT * FROM novrsoc.cnii_checks WHERE monitored_asset_id = :m
                                                    ORDER BY observed_at DESC LIMIT 200"""), {"m": monitored_id})]


@router.get("/overview", response_model=CniiOverview, summary="CNII monitoring overview of the active organization (designated sectors)")
def overview(s: CniiScope = Depends(cnii_scope("cnii:read")), conn: Connection = Depends(request_connection)) -> CniiOverview:
    sec = sorted(s.sectors)
    auth = conn.execute(text("SELECT * FROM novrsoc.cnii_authorizations WHERE sectors && :s"), {"s": sec}).all()
    now = datetime.now(timezone.utc)
    active = [a for a in auth if _auth_state(a) == "active"]
    ma = conn.execute(text("""SELECT m.sector, m.status, m.asset_id FROM novrsoc.cnii_monitored_assets m WHERE m.sector = ANY(:s)"""), {"s": sec}).all()
    ids = [m.asset_id for m in ma]
    f = conn.execute(text("""SELECT count(*) AS n, count(*) FILTER (WHERE severity = 'critical') AS c FROM novrsoc.vms_findings
                             WHERE asset_id = ANY(:a) AND status NOT IN ('verified', 'risk_accepted')"""), {"a": ids}).one()
    n_checks = conn.execute(text("""SELECT count(*) FROM novrsoc.cnii_checks c JOIN novrsoc.cnii_monitored_assets m ON m.id = c.monitored_asset_id
                                    WHERE m.sector = ANY(:s) AND c.observed_at > now() - interval '30 days' AND c.outcome <> 'not_run'"""),
                           {"s": sec}).scalar()
    by: dict[str, int] = {}
    for m in ma:
        by[m.sector] = by.get(m.sector, 0) + 1
    return CniiOverview(generated_at=now, designation_sectors=sec, authorizations_active=len(active),
                        authorizations_expiring_30d=sum(1 for a in active if a.valid_until <= now + timedelta(days=30)),
                        monitored_assets=sum(1 for m in ma if m.status == "active"), suspended_assets=sum(1 for m in ma if m.status == "suspended"),
                        by_sector=by, open_findings=f.n, critical_findings=f.c, availability_checks_30d=n_checks, probe=PROBE)


def run_due_checks(conn: Connection) -> int:
    """Jobs worker: record due checks honestly. No probe exists, so each due check is `not_run` with the reason; a
    schedule whose authorization is no longer active is disabled."""
    n = 0
    for sc in conn.execute(text("""SELECT sc.*, m.status AS m_status, z.valid_from, z.valid_until, z.revoked_at
                                   FROM novrsoc.cnii_schedules sc JOIN novrsoc.cnii_monitored_assets m ON m.id = sc.monitored_asset_id
                                   JOIN novrsoc.cnii_authorizations z ON z.id = m.authorization_id
                                   WHERE sc.enabled AND sc.next_due_at <= now() FOR UPDATE OF sc SKIP LOCKED""")).all():
        if _auth_state(sc) != "active" or sc.m_status != "active":
            conn.execute(text("UPDATE novrsoc.cnii_schedules SET enabled = false WHERE id = :i"), {"i": sc.id})
            detail = "Schedule disabled: the authorization is no longer active or monitoring is suspended."
        else:
            detail = PROBE if sc.check_kind == "availability" else "Vulnerability scanning is not run by CNII schedules in this release."
        conn.execute(text("""INSERT INTO novrsoc.cnii_checks (org_id, monitored_asset_id, kind, outcome, detail, source)
                             VALUES (novrsoc.app_org(), :m, :k, 'not_run', :d, 'jobs_worker')"""),
                     {"m": sc.monitored_asset_id, "k": sc.check_kind, "d": detail})
        conn.execute(text("""UPDATE novrsoc.cnii_schedules SET last_run_at = now(), next_due_at = now() + make_interval(mins => interval_minutes)
                             WHERE id = :i"""), {"i": sc.id})
        n += 1
    return n
