"""NovrAgent installation and SERVER-CONTROLLED enrollment (PUBLIC: the endpoint being onboarded has no session).

An organization administrator issues an enrollment ticket in the portal (POST /api/v1/onboarding/installer): bound to
the organization and an operating system, valid for a limited time, admitting a limited number of endpoints, revocable.
  GET  /novragent.{sh,ps1}?t=<ticket>  the installer script. It names the agent address and the ticket; no password.
  POST /enroll                          the installer on the endpoint presents the ticket; NovrSOC registers the agent on
                                        the NovrSIEM manager itself, in the organization's provisioned group (as its only
                                        group), and returns the agent key once. The manager does not accept
                                        self-enrollment, so no shared password or guessed group name can place an agent
                                        in an organization.
Both answer only at the organization's own portal (else the platform address), only while the organization is active,
and are rate limited per client address. Every download and enrollment is audited.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, Path, Query, Request
from fastapi.responses import JSONResponse, Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app import portal as portals
from app.audit import service as audit
from app.auth.deps import client_ip
from app.connectors import registry
from app.connectors.base import ConnectorError
from app.connectors.enrollment import EnrollmentRejected
from app.core.config import Settings, get_settings
from app.core.errors import ApiError
from app.core.ratelimit import limited
from app.core.security import sha256
from app.db.session import request_connection, set_context
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.portal import AgentEnrollmentRequest, AgentEnrollmentResult

MODULE = ModuleInfo(name="install", workstream="C", prefix="/api/v1/install",
                    summary="NovrAgent installer downloads and server-controlled enrollment (organization-bound tickets)")
router = APIRouter(prefix="/api/v1/install", tags=["install"], responses=ERRORS)

_GONE = "This installation link is not valid or has expired. Generate a new one in your portal."


def _ticket(conn: Connection, request: Request, settings: Settings, token: str, *, lock: bool = False):
    """(ticket row, organization row) of a valid ticket presented at the organization's own address; ApiError(404) else."""
    gone = ApiError(404, "not_found", _GONE)
    if not portals.TICKET.match(token):
        raise gone
    org_id = conn.execute(text("SELECT novrsoc.enrollment_ticket_org(:h)"), {"h": sha256(token)}).scalar()
    if org_id is None:
        raise gone
    set_context(conn, org_id=org_id)
    t = conn.execute(text("SELECT * FROM novrsoc.agent_enrollment_tickets WHERE token_hash = :h" + (" FOR UPDATE" if lock else "")),
                     {"h": sha256(token)}).one()
    org = conn.execute(text("SELECT id, slug::text AS slug, name, brand_display_name, portal_subdomain::text AS sub, portal_enabled, "
                            "status, kind FROM novrsoc.organizations WHERE id = :o"), {"o": org_id}).one()
    if org.status != "active" or org.kind != "client" or t.uses >= t.max_uses:
        raise gone
    here = portals.resolve(conn, request, settings)
    if org.portal_enabled and settings.portal_base_domain:
        if not (here.kind == "tenant" and here.org_id == org.id):
            raise gone
    elif here.kind != "platform":
        raise gone
    return t, org


def _group(conn: Connection) -> str | None:
    return conn.execute(text("SELECT group_name FROM novrsoc.wazuh_group_mappings WHERE provisioned")).scalar()


@router.get("/{script}", summary="Download the organization's NovrAgent installer (link from the portal's onboarding page)",
            response_class=Response, responses={200: {"content": {"text/plain": {}}}}, dependencies=[Depends(limited("installer"))])
def download(request: Request, script: str = Path(..., pattern=r"^novragent\.(sh|ps1)$"),
             t: str = Query(..., min_length=30, max_length=80), conn: Connection = Depends(request_connection),
             settings: Settings = Depends(get_settings)) -> Response:
    ticket, org = _ticket(conn, request, settings, t)
    if script.rsplit(".", 1)[1] != portals.OS_SCRIPT[ticket.os]:
        raise ApiError(404, "not_found", _GONE)
    version, why = portals.agent_compatibility(*_versions(settings))
    if _group(conn) is None or not settings.agent_manager_address or version is None or registry.enrollment(settings) is None:
        raise ApiError(409, "installer_unavailable", why or "The NovrAgent installer is not available for this organization now.")
    enroll_url = f"{portals.base_url(settings, org.sub, org.portal_enabled)}/api/v1/install/enroll"
    body = portals.install_script(ticket.os, org_name=org.brand_display_name or org.name, manager=settings.agent_manager_address,
                                  port=settings.agent_manager_port, version=version, enroll_url=enroll_url, ticket=t,
                                  expires=ticket.expires_at.isoformat(timespec="minutes"))
    audit.record("AGENT_INSTALLER_DOWNLOADED", "success", org_id=org.id, actor_type="system", actor_label="enrollment ticket",
                 resource_type="enrollment_ticket", resource_id=str(ticket.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"os": ticket.os, "agent_version": version})
    return Response(body, media_type="text/plain; charset=utf-8",
                    headers={"Cache-Control": "no-store", "Content-Disposition": f'attachment; filename="{script}"',
                             "X-Content-Type-Options": "nosniff"})


def _versions(settings: Settings) -> tuple[str | None, str]:
    return registry.manager_version(settings)[0], settings.agent_version


@router.post("/enroll", response_model=AgentEnrollmentResult, status_code=201, dependencies=[Depends(limited("enroll"))],
             summary="The installer registers this endpoint with an enrollment ticket; NovrSOC registers the agent on the manager")
def enroll(body: AgentEnrollmentRequest, request: Request, conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)):
    ticket, org = _ticket(conn, request, settings, body.ticket, lock=True)
    if body.os != ticket.os:
        raise ApiError(404, "not_found", _GONE)
    group, client = _group(conn), registry.enrollment(settings)
    if group is None or client is None:
        raise ApiError(409, "installer_unavailable", "Agent enrollment is not available for this organization now.")
    name = portals.agent_name(org.slug, body.hostname)
    try:
        client.ensure_group(group)
        agent_id = key = None
        for attempt, candidate in enumerate([name] + [f"{name[:120]}-{n}" for n in range(2, 5)]):
            try:
                agent_id, key = client.register(candidate)
                name = candidate
                break
            except EnrollmentRejected:
                if attempt == 3:
                    raise
        try:
            client.assign_only_group(agent_id, group)
        except ConnectorError:
            client.remove(agent_id)              # never leave an agent registered outside its organization's group
            raise
    except ConnectorError as e:
        audit.record("AGENT_ENROLLMENT_FAILED", "failure", org_id=org.id, actor_type="system", actor_label="enrollment ticket",
                     resource_type="enrollment_ticket", resource_id=str(ticket.id), request_id=request.state.request_id,
                     ip=client_ip(request), details={"reason": str(e)[:200]})
        raise ApiError(502, "enrollment_failed", "NovrSOC could not register this endpoint now. Try again later.") from None
    conn.execute(text("UPDATE novrsoc.agent_enrollment_tickets SET uses = uses + 1 WHERE id = :i"), {"i": ticket.id})
    conn.execute(text("""INSERT INTO novrsoc.agent_enrollments (org_id, ticket_id, agent_id, agent_name, group_name, hostname, os, source_ip)
                         VALUES (:o, :t, :a, :n, :g, :h, :os, CAST(:ip AS inet))"""),
                 {"o": org.id, "t": ticket.id, "a": agent_id, "n": name, "g": group, "h": body.hostname[:64], "os": body.os,
                  "ip": _ip(client_ip(request))})
    audit.record("AGENT_ENROLLED", "success", org_id=org.id, actor_type="system", actor_label="enrollment ticket", resource_type="agent",
                 resource_id=agent_id, request_id=request.state.request_id, ip=client_ip(request),
                 details={"name": name, "group": group, "ticket": str(ticket.id), "os": body.os})
    return JSONResponse(AgentEnrollmentResult(agent_id=agent_id, name=name, key=key).model_dump(), status_code=201,
                        headers={"Cache-Control": "no-store"})


def _ip(v: str | None) -> str | None:
    import ipaddress
    try:
        return str(ipaddress.ip_address(v)) if v else None
    except ValueError:
        return None
