"""Tenant-owned foundation records: sites (the Phase 2 integration example), audit events, plus the
service-identity and CNII access checks."""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.audit import service as audit
from app.auth.deps import Principal, ServicePrincipal, client_ip, current_principal, current_service, require
from app.authz.cnii import Designation, require_cnii
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.platform import (AuditEvent, AuditEventList, CniiAccessResponse, ServiceWhoAmI, Site,
                                           SiteCreate, SiteList)

sites = APIRouter(prefix="/api/v1/sites", tags=["sites"], responses=ERRORS)
audit_router = APIRouter(prefix="/api/v1/audit", tags=["audit"], responses=ERRORS)
service = APIRouter(prefix="/api/v1/service", tags=["service-identity"], responses=ERRORS)
cnii = APIRouter(prefix="/api/v1/cnii", tags=["cnii"], responses=ERRORS)

_SITE_COLS = "id, org_id, name, description, network_cidrs::text[] AS network_cidrs, created_at"


def _site(r) -> Site:
    return Site(id=r.id, org_id=r.org_id, name=r.name, description=r.description,
                network_cidrs=list(r.network_cidrs or []), created_at=r.created_at)


@sites.get("", response_model=SiteList, summary="Sites of the active organization")
def list_sites(p: Principal = Depends(require("sites:read")), conn: Connection = Depends(request_connection)) -> SiteList:
    # No WHERE org_id here on purpose: row-level security restricts rows to app.org_id. The tenant tests
    # prove a second organization's rows never appear.
    rows = conn.execute(text(f"SELECT {_SITE_COLS} FROM novrsoc.sites ORDER BY name")).all()
    return SiteList(items=[_site(r) for r in rows])


@sites.get("/{site_id}", response_model=Site, summary="One site of the active organization")
def get_site(site_id: uuid.UUID, p: Principal = Depends(require("sites:read")),
             conn: Connection = Depends(request_connection)) -> Site:
    r = conn.execute(text(f"SELECT {_SITE_COLS} FROM novrsoc.sites WHERE id = :id AND org_id = :org"),
                     {"id": site_id, "org": p.org_id}).first()
    if not r:
        raise not_found("Site not found")
    return _site(r)


@sites.post("", response_model=Site, status_code=201, summary="Create a site in the active organization")
def create_site(body: SiteCreate, request: Request, p: Principal = Depends(require("sites:manage")),
                conn: Connection = Depends(request_connection)) -> Site:
    try:
        with conn.begin_nested():
            r = conn.execute(text(f"""
                INSERT INTO novrsoc.sites (org_id, name, description, network_cidrs, created_by)
                VALUES (:org, :name, :desc, CAST(:cidrs AS cidr[]), :by) RETURNING {_SITE_COLS}"""),
                {"org": p.org_id, "name": body.name.strip(), "desc": body.description, "cidrs": body.network_cidrs,
                 "by": p.user_id}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "A site with this name already exists in the organization")
    audit.record("SITE_CREATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="site", resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request))
    return _site(r)


@audit_router.get("/events", response_model=AuditEventList, summary="Audit events of the active organization")
def list_audit(limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=1_000_000),
               action: str | None = Query(None, pattern=r"^[A-Z][A-Z0-9_]{1,63}$", description="Action, or a prefix ending in _"),
               outcome: Literal["success", "denied", "failure"] | None = None,
               actor: str | None = Query(None, max_length=200), resource_type: str | None = Query(None, pattern=r"^[a-z_]{2,40}$"),
               since: datetime | None = None, until: datetime | None = None,
               p: Principal = Depends(require("audit:read")), conn: Connection = Depends(request_connection)) -> AuditEventList:
    where, params = ["true"], {"n": limit, "off": offset}
    if action:
        where.append("action LIKE :a" if action.endswith("_") else "action = :a")
        params["a"] = action.replace("_", "\\_") + "%" if action.endswith("_") else action
    if outcome:
        where.append("outcome = :o"); params["o"] = outcome
    if actor:
        where.append("actor_label ILIKE :ac"); params["ac"] = f"%{actor}%"
    if resource_type:
        where.append("resource_type = :rt"); params["rt"] = resource_type
    if since:
        where.append("occurred_at >= :s"); params["s"] = since
    if until:
        where.append("occurred_at < :u"); params["u"] = until
    cond = " AND ".join(where)
    total = conn.execute(text(f"SELECT count(*) FROM novrsoc.audit_events WHERE {cond}"), params).scalar()
    rows = conn.execute(text(f"""
        SELECT id, occurred_at, org_id, actor_type, actor_id, actor_label, action, outcome, resource_type,
               resource_id, request_id, details FROM novrsoc.audit_events WHERE {cond} ORDER BY id DESC LIMIT :n OFFSET :off"""), params).all()
    return AuditEventList(items=[AuditEvent(**r._mapping) for r in rows], total=total)


@service.get("/whoami", response_model=ServiceWhoAmI,
             summary="Machine identity check: organization and site come from the credential only")
def whoami(s: ServicePrincipal = Depends(current_service)) -> ServiceWhoAmI:
    return ServiceWhoAmI(identity_id=s.identity_id, org_id=s.org_id, site_id=s.site_id, kind=s.kind,  # type: ignore[arg-type]
                         scopes=sorted(s.scopes))


@cnii.get("/access", response_model=CniiAccessResponse,
          summary="CNII access check: needs cnii:read AND an active designation for the sector")
def cnii_access(d: Designation = Depends(require_cnii("cnii:read")),
                p: Principal = Depends(current_principal)) -> CniiAccessResponse:
    return CniiAccessResponse(sector=d.sector, designation_id=d.id, active_org_id=p.org_id)
