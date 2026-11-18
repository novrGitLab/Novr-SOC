"""Syslog and agentless sources of the active organization (organization management).

A source is a device whose logs reach NovrSOC through the Wazuh manager (agent 000): firewalls, routers, switches,
Linux servers and other syslog-enabled devices, or agentless SSH targets. Registering it, with the client's
authorization reference, is the ONLY way such events are attributed to an organization (app.secops.log_sources).

  * one live registration per source across all organizations (database unique index): a second registration of the
    same sender, in any organization, is refused (409) and never silently overrides the first;
  * disable: its events are quarantined (log_source_disabled) until it is enabled again;
  * reassign (platform administrators): the record is retired in the old organization, which keeps its history and
    alert links, and registered in the new one; only events received afterwards go to the new organization;
  * retire: removed from use, kept for history.
Each source is reconciled into the organization's asset inventory. Every change is audited.
"""
from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.assets import reconcile
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from app.secops import log_sources as attribution
from novrsoc_contracts.v1.sources import (LogSourceCreate, LogSourceList, LogSourceReassign, LogSourceRetire, LogSourceUpdate,
                                          LogSourceView)

MODULE = ModuleInfo(name="log_sources", workstream="C", prefix="/api/v1/log-sources",
                    summary="Syslog and agentless sources: registration, attribution, status and reassignment")
router = APIRouter(prefix="/api/v1/log-sources", tags=["log_sources"], responses=ERRORS)

_COLS = """s.*, host(s.source_ip) AS source_ip_text, s.network::text AS network_text,
           (SELECT si.name FROM novrsoc.sites si WHERE si.id = s.site_id) AS site_name"""
_ASSET_KIND = {"linux_server": "host", "windows_server": "host", "storage": "host"}


def _view(r) -> LogSourceView:
    return LogSourceView(id=r.id, org_id=r.org_id, name=r.name, kind=r.kind, source_ip=r.source_ip_text, host=r.host,
                         match_value=r.match_value, device_type=r.device_type, vendor=r.vendor, protocol=r.protocol, port=r.port,
                         site_id=r.site_id, site_name=r.site_name, network=r.network_text, enabled=r.enabled,
                         authorization_reference=r.authorization_reference, notes=r.notes, asset_id=r.asset_id,
                         event_count=r.event_count, last_event_at=r.last_event_at,
                         verified=r.verified_at is not None, verified_at=r.verified_at,
                         status=("pending_verification" if r.verified_at is None and r.retired_at is None else
                                 attribution.status(enabled=r.enabled, retired_at=r.retired_at, last_event_at=r.last_event_at)),
                         retired_at=r.retired_at, retired_reason=r.retired_reason, created_at=r.created_at, updated_at=r.updated_at)


def _get(conn: Connection, source_id: uuid.UUID):
    r = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.log_sources s WHERE s.id = :id"), {"id": source_id}).first()
    if r is None:
        raise not_found("Source not found")
    return r


def _audit(p: Principal, request: Request, action: str, rid: str, details: dict, org_id: uuid.UUID | None = None) -> None:
    audit.record(action, "success", org_id=org_id or p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="log_source",
                 resource_id=rid, request_id=request.state.request_id, ip=client_ip(request), details=details)


def _check_site(conn: Connection, site_id: uuid.UUID | None, source_ip: str | None) -> None:
    """The site must belong to the organization (RLS), and a sender inside it must be inside one of its networks."""
    if site_id is None:
        return
    site = conn.execute(text("SELECT network_cidrs FROM novrsoc.sites WHERE id = :s"), {"s": site_id}).first()
    if site is None:
        raise ApiError(422, "validation_error", "Unknown site for this organization")
    nets = [ipaddress.ip_network(str(n)) for n in (site.network_cidrs or [])]
    if source_ip and nets and not any(ipaddress.ip_address(source_ip) in n for n in nets):
        raise ApiError(422, "validation_error", "The source address is outside the site's networks")


def _reconcile(conn: Connection, *, name: str, device_type: str, source_ip: str | None, host: str, site_id, actor: str):
    ident = [("ip", source_ip)] if source_ip else []
    if host:
        try:
            ident.append(("ip", str(ipaddress.ip_address(host))))
        except ValueError:
            ident.append(("hostname", host))
    try:
        return reconcile.upsert(conn, reconcile.Observation(source="log_source", kind=_ASSET_KIND.get(device_type, "network_device"),
                                                            display_name=name, identifiers=ident, site_id=site_id,
                                                            attributes={"device_type": device_type}), actor).asset_id
    except ValueError:
        return None


def _platform_staff(conn: Connection, p: Principal) -> bool:
    """NovrSOC staff (a platform administrator, or platform SOC staff working in an assigned organization) register verified
    senders. An organization's own members register PENDING senders: disabled until NovrSOC verifies them, so nobody can
    claim another organization's device by registering its address first."""
    if p.role == "super_admin" or p.cross_org:
        return True
    return conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).scalar() == "platform"


def _conflict() -> ApiError:
    return ApiError(409, "conflict", "This source is already registered (in this or another organization). One source, one "
                                     "organization: reassign the existing registration instead of registering it twice.")


@router.get("", response_model=LogSourceList, summary="Syslog and agentless sources of the active organization")
def list_sources(include_retired: bool = Query(False), p: Principal = Depends(require("endpoints:read")),
                 conn: Connection = Depends(request_connection)) -> LogSourceList:
    cond = "true" if include_retired else "s.retired_at IS NULL"
    rows = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.log_sources s WHERE {cond} ORDER BY s.retired_at NULLS FIRST, s.name")).all()
    return LogSourceList(items=[_view(r) for r in rows])


@router.post("", response_model=LogSourceView, status_code=201, summary="Register a syslog or agentless source (audited)")
def create_source(body: LogSourceCreate, request: Request, p: Principal = Depends(require("endpoints:manage")),
                  conn: Connection = Depends(request_connection)) -> LogSourceView:
    _check_site(conn, body.site_id, body.source_ip)
    value = attribution.match_value(body.kind, body.source_ip, body.host)
    staff = _platform_staff(conn, p)
    try:
        with conn.begin_nested():
            sid = conn.execute(text("""
                INSERT INTO novrsoc.log_sources (org_id, name, kind, source_ip, host, match_value, device_type, vendor, protocol, port,
                                                 site_id, network, enabled, authorization_reference, notes, created_by, verified_at, verified_by)
                VALUES (novrsoc.app_org(), :n, :k, CAST(:ip AS inet), :h, :mv, :dt, :v, :pr, :po, :site, CAST(:net AS cidr), :en,
                        :auth, :notes, :u, CASE WHEN :staff THEN now() END, CASE WHEN :staff THEN CAST(:u AS uuid) END) RETURNING id"""),
                {"n": body.name, "k": body.kind, "ip": body.source_ip, "h": body.host.strip(), "mv": value, "dt": body.device_type,
                 "v": body.vendor, "pr": body.protocol, "po": body.port, "site": body.site_id, "net": body.network,
                 "en": body.enabled and staff, "auth": body.authorization_reference, "notes": body.notes, "u": p.user_id,
                 "staff": staff}).scalar()
    except IntegrityError:
        raise _conflict()
    asset = _reconcile(conn, name=body.name, device_type=body.device_type, source_ip=body.source_ip, host=body.host,
                       site_id=body.site_id, actor=p.email)
    conn.execute(text("UPDATE novrsoc.log_sources SET asset_id = :a WHERE id = :id"), {"a": asset, "id": sid})
    _audit(p, request, "LOG_SOURCE_REGISTERED", str(sid), {"kind": body.kind, "match": value, "device_type": body.device_type,
                                                          "authorization_reference": body.authorization_reference,
                                                          "verification": "verified" if staff else "pending"})
    return _view(_get(conn, sid))


@router.get("/{source_id}", response_model=LogSourceView, summary="One source with its status and event counts")
def get_source(source_id: uuid.UUID, p: Principal = Depends(require("endpoints:read")),
               conn: Connection = Depends(request_connection)) -> LogSourceView:
    return _view(_get(conn, source_id))


@router.patch("/{source_id}", response_model=LogSourceView, summary="Edit, disable or enable a source (audited)")
def update_source(source_id: uuid.UUID, body: LogSourceUpdate, request: Request, p: Principal = Depends(require("endpoints:manage")),
                  conn: Connection = Depends(request_connection)) -> LogSourceView:
    cur = _get(conn, source_id)
    if cur.retired_at is not None:
        raise ApiError(409, "conflict", "A retired source is kept for history and cannot be changed")
    if cur.kind == "syslog" and body.host:
        raise ApiError(422, "validation_error", "A syslog source is identified by its source_ip")
    if cur.kind == "agentless" and body.source_ip:
        raise ApiError(422, "validation_error", "An agentless source is identified by its host")
    new = {k: v for k, v in body.model_dump(exclude={"clear_site", "clear_network"}).items() if v is not None}
    protocol = new.get("protocol", cur.protocol)
    if (cur.kind == "syslog") != (protocol in ("udp", "tcp", "tls")):
        raise ApiError(422, "validation_error", "syslog uses udp, tcp or tls; agentless uses ssh")
    ip = new.get("source_ip", cur.source_ip_text)
    site = None if body.clear_site else new.get("site_id", cur.site_id)
    network = None if body.clear_network else new.get("network", cur.network_text)
    if network and ip and ipaddress.ip_address(ip) not in ipaddress.ip_network(network):
        raise ApiError(422, "validation_error", "source_ip is not inside network")
    _check_site(conn, site, ip)
    host = new.get("host", cur.host)
    value = attribution.match_value(cur.kind, ip, host)
    staff = _platform_staff(conn, p)
    unverify = not staff and value != cur.match_value                  # a new address needs a new verification
    if not staff and new.get("enabled") and (cur.verified_at is None or unverify):
        raise ApiError(409, "verification_required", "NovrSOC verifies a sender before its events are accepted; it stays disabled until then")
    if unverify:
        new["enabled"] = False
    try:
        with conn.begin_nested():
            conn.execute(text("""
                UPDATE novrsoc.log_sources SET name = :n, source_ip = CAST(:ip AS inet), host = :h, match_value = :mv, device_type = :dt,
                       vendor = :v, protocol = :pr, port = :po, site_id = :site, network = CAST(:net AS cidr), enabled = :en,
                       authorization_reference = :auth, notes = :notes, updated_at = now() WHERE id = :id"""),
                {"n": new.get("name", cur.name), "ip": ip, "h": host, "mv": value, "dt": new.get("device_type", cur.device_type),
                 "v": new.get("vendor", cur.vendor), "pr": protocol, "po": new.get("port", cur.port), "site": site, "net": network,
                 "en": new.get("enabled", cur.enabled), "auth": new.get("authorization_reference", cur.authorization_reference),
                 "notes": new.get("notes", cur.notes), "id": source_id})
        if unverify:
            conn.execute(text("UPDATE novrsoc.log_sources SET verified_at = NULL, verified_by = NULL WHERE id = :id"), {"id": source_id})
    except IntegrityError:
        raise _conflict()
    if value != cur.match_value or site != cur.site_id:
        asset = _reconcile(conn, name=new.get("name", cur.name), device_type=new.get("device_type", cur.device_type), source_ip=ip,
                           host=host, site_id=site, actor=p.email)
        conn.execute(text("UPDATE novrsoc.log_sources SET asset_id = :a WHERE id = :id"), {"a": asset, "id": source_id})
    changed = sorted(k for k in new if k != "enabled" and new[k] != getattr(cur, {"source_ip": "source_ip_text", "network": "network_text"}.get(k, k)))
    if "enabled" in new and new["enabled"] != cur.enabled:
        _audit(p, request, "LOG_SOURCE_ENABLED" if new["enabled"] else "LOG_SOURCE_DISABLED", str(source_id), {"match": value})
    if changed or body.clear_site or body.clear_network:
        _audit(p, request, "LOG_SOURCE_UPDATED", str(source_id), {"fields": changed, "match": value,
                                                                  "previous_match": cur.match_value})
    return _view(_get(conn, source_id))


@router.post("/{source_id}/verify", response_model=LogSourceView,
             summary="NovrSOC: verify a sender an organization registered, and enable it (audited)")
def verify_source(source_id: uuid.UUID, request: Request, p: Principal = Depends(require("endpoints:manage")),
                  conn: Connection = Depends(request_connection)) -> LogSourceView:
    if not _platform_staff(conn, p):
        raise ApiError(403, "forbidden", "Only NovrSOC staff verify a sender")
    cur = _get(conn, source_id)
    if cur.retired_at is not None:
        raise ApiError(409, "conflict", "A retired source cannot be verified")
    conn.execute(text("""UPDATE novrsoc.log_sources SET verified_at = now(), verified_by = :u, enabled = true, updated_at = now()
                         WHERE id = :id"""), {"u": p.user_id, "id": source_id})
    _audit(p, request, "LOG_SOURCE_VERIFIED", str(source_id), {"match": cur.match_value})
    return _view(_get(conn, source_id))


@router.post("/{source_id}/retire", response_model=LogSourceView, summary="Retire a source (kept for history; its events are then quarantined)")
def retire_source(source_id: uuid.UUID, body: LogSourceRetire, request: Request, p: Principal = Depends(require("endpoints:manage")),
                  conn: Connection = Depends(request_connection)) -> LogSourceView:
    reason = body.reason.strip()
    cur = _get(conn, source_id)
    if cur.retired_at is not None:
        raise ApiError(409, "conflict", "This source is already retired")
    conn.execute(text("""UPDATE novrsoc.log_sources SET enabled = false, retired_at = now(), retired_reason = :r, updated_at = now()
                         WHERE id = :id"""), {"r": reason, "id": source_id})
    _audit(p, request, "LOG_SOURCE_RETIRED", str(source_id), {"match": cur.match_value, "reason": reason})
    return _view(_get(conn, source_id))


@router.post("/{source_id}/reassign", response_model=LogSourceView, status_code=201,
             summary="Move a source to another organization (platform administrators; audited in both)")
def reassign_source(source_id: uuid.UUID, body: LogSourceReassign, request: Request, p: Principal = Depends(require("users:manage")),
                    conn: Connection = Depends(request_connection)) -> LogSourceView:
    cur = _get(conn, source_id)  # in the active (current owner) organization
    if cur.retired_at is not None:
        raise ApiError(409, "conflict", "A retired source cannot be reassigned")
    if body.org_id == cur.org_id:
        raise ApiError(422, "validation_error", "The source already belongs to this organization")
    target = conn.execute(text("SELECT id, status, name FROM novrsoc.organizations WHERE id = :o"), {"o": body.org_id}).first()
    if target is None or target.status != "active":
        raise ApiError(422, "validation_error", "The target organization must exist and be active")
    conn.execute(text("""UPDATE novrsoc.log_sources SET enabled = false, retired_at = now(), updated_at = now(),
                         retired_reason = :r WHERE id = :id"""), {"r": f"Reassigned to {target.name}: {body.reason}"[:500], "id": source_id})
    _audit(p, request, "LOG_SOURCE_REASSIGNED_OUT", str(source_id), {"to_org": str(body.org_id), "match": cur.match_value,
                                                                      "reason": body.reason})
    conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(body.org_id)})  # act in the new organization
    try:
        with conn.begin_nested():
            sid = conn.execute(text("""
                INSERT INTO novrsoc.log_sources (org_id, name, kind, source_ip, host, match_value, device_type, vendor, protocol, port,
                                                 enabled, authorization_reference, notes, created_by, verified_at, verified_by)
                VALUES (novrsoc.app_org(), :n, :k, :ip, :h, :mv, :dt, :v, :pr, :po, :en, :auth, :notes, :u, now(), :u) RETURNING id"""),
                {"n": cur.name, "k": cur.kind, "ip": cur.source_ip, "h": cur.host, "mv": cur.match_value, "dt": cur.device_type,
                 "v": cur.vendor, "pr": cur.protocol, "po": cur.port, "en": cur.enabled, "auth": cur.authorization_reference,
                 "notes": cur.notes, "u": p.user_id}).scalar()
    except IntegrityError:
        raise ApiError(409, "conflict", "The target organization already has a source with this name")
    asset = _reconcile(conn, name=cur.name, device_type=cur.device_type, source_ip=cur.source_ip_text, host=cur.host, site_id=None,
                       actor=p.email)
    conn.execute(text("UPDATE novrsoc.log_sources SET asset_id = :a WHERE id = :id"), {"a": asset, "id": sid})
    _audit(p, request, "LOG_SOURCE_REASSIGNED_IN", str(sid), {"from_org": str(cur.org_id), "previous_source": str(source_id),
                                                              "match": cur.match_value, "reason": body.reason}, org_id=body.org_id)
    return _view(_get(conn, sid))
