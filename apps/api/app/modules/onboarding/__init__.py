"""Guided onboarding of an organization's telemetry (the active organization; its portal or a staff switch).

  GET  /status                   what is configured and what has arrived: provisioned agent group, server-controlled
                                 enrollment (manager version, agent version compatibility, enrolled agents, open
                                 tickets), agent installation status, telemetry, registered senders, the canonical asset
                                 inventory (shared with VMS) and its scheduled sync.
  POST /installer                an enrollment ticket and the installer command for Windows, Linux or macOS. The ticket is
                                 organization-bound, expires, admits a chosen number of endpoints and can be revoked; it
                                 carries no password. NovrSOC itself registers each agent on the manager. Audited.
  GET  /tickets, POST /tickets/{id}/revoke   the organization's enrollment tickets.
The agent group is provisioned by NovrSOC administrators (POST /api/v1/admin/organizations/{id}/agent-group).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app import portal as portals
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.connectors import registry
from app.connectors.base import ConnectorError
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.core.security import new_token, sha256
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.modules.endpoints import org_scope
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.portal import (AgentGroupView, AssetSyncStatus, AgentEnrollmentStatus, AgentEnrollmentTicketList, AgentEnrollmentTicket,
                                         InstallerCommand, InstallerRequest, OnboardingAgents, OnboardingSources, OnboardingStep,
                                         OnboardingTelemetry, PortalOrg, SyslogTarget, TenantOnboarding)

MODULE = ModuleInfo(name="onboarding", workstream="C", prefix="/api/v1/onboarding",
                    summary="Guided telemetry onboarding: agent group, server-controlled NovrAgent enrollment, device senders, progress")
router = APIRouter(prefix="/api/v1/onboarding", tags=["onboarding"], responses=ERRORS)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _org(conn: Connection, p: Principal):
    return conn.execute(text("SELECT id, slug::text AS slug, name, kind, status, portal_subdomain::text AS sub, portal_enabled "
                             "FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).one()


def _group(conn: Connection):
    return conn.execute(text("SELECT group_name, created_at FROM novrsoc.wazuh_group_mappings WHERE provisioned")).first()


def enrollment_readiness(settings: Settings, org, group) -> tuple[str | None, str, str | None]:
    """(agent version to install, reason it cannot be installed ('' when it can), manager version)."""
    manager = None
    if org.kind != "client":
        return None, "Agent enrollment is for client organizations.", None
    if group is None:
        return None, "NovrSOC has not provisioned this organization's agent group yet.", None
    problem = registry.enrollment_problem(settings)
    if problem:
        return None, problem, None
    if not settings.agent_manager_address:
        return None, "The address agents connect to is not configured in this installation.", None
    manager, detail = registry.manager_version(settings)
    version, why = portals.agent_compatibility(manager, settings.agent_version)
    if version is None:
        return None, why if manager else detail, manager
    return version, "", manager


def _agents(conn: Connection, p: Principal, settings: Settings) -> OnboardingAgents:
    state = registry.wazuh_states(settings)[0]
    source = registry.wazuh(settings)
    scope = org_scope(conn, p.org_id, settings.collection_groups)
    if source is None or state.state not in ("connected", "local_fixture") or not scope.wazuh_agent_groups:
        return OnboardingAgents(state=state.state)
    try:
        agents = list(source.list_agents(scope))
    except ConnectorError:
        return OnboardingAgents(state="unavailable")
    count = {s: sum(1 for a in agents if a.status == s) for s in ("active", "disconnected", "never_connected", "pending")}
    return OnboardingAgents(state=state.state, total=len(agents), **count)


def asset_sync_status(conn: Connection, settings: Settings) -> AssetSyncStatus:
    """The organization's scheduled agent -> inventory sync (a wazuh_sync collector overrides the installation default)."""
    col = conn.execute(text("SELECT enabled, interval_minutes FROM novrsoc.collectors WHERE kind = 'wazuh_sync' ORDER BY created_at LIMIT 1")).first()
    interval = (col.interval_minutes if col.enabled else 0) if col is not None else settings.asset_sync_interval_minutes
    last = conn.execute(text("""SELECT started_at, outcome, detail FROM novrsoc.asset_sync_runs WHERE source = 'wazuh'
                                ORDER BY started_at DESC LIMIT 1""")).first()
    due = None
    if interval:
        due = (last.started_at + timedelta(minutes=interval)) if last else _now()
    return AssetSyncStatus(interval_minutes=interval, last_run_at=last.started_at if last else None, last_outcome=last.outcome if last else None,
                           last_detail=(last.detail or "")[:300] if last else "", next_due_at=due)


@router.get("/status", response_model=TenantOnboarding, summary="Onboarding progress of the active organization")
def status(p: Principal = Depends(require("endpoints:read")), conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> TenantOnboarding:
    org = _org(conn, p)
    group = _group(conn)
    version, why, manager = enrollment_readiness(settings, org, group)
    agents = _agents(conn, p, settings)
    t = conn.execute(text("""SELECT
        (SELECT count(*) FROM novrsoc.alerts WHERE observed_at > now() - interval '24 hours') AS alerts_24h,
        (SELECT max(observed_at) FROM novrsoc.alerts) AS last_alert_at,
        (SELECT count(*) FROM novrsoc.assets WHERE status = 'active') AS assets,
        (SELECT count(*) FROM novrsoc.vms_enrollments WHERE status = 'enrolled') AS vms_enrolled,
        (SELECT count(*) FROM novrsoc.log_sources WHERE retired_at IS NULL) AS sources,
        (SELECT count(*) FROM novrsoc.log_sources WHERE retired_at IS NULL AND verified_at IS NULL) AS pending,
        (SELECT count(*) FROM novrsoc.log_sources WHERE retired_at IS NULL AND last_event_at > now() - interval '1 hour') AS receiving,
        (SELECT count(*) FROM novrsoc.log_sources WHERE retired_at IS NULL AND verified_at IS NOT NULL AND last_event_at IS NULL) AS never,
        (SELECT count(*) FROM novrsoc.agent_enrollments) AS enrolled,
        (SELECT count(*) FROM novrsoc.agent_enrollment_tickets WHERE revoked_at IS NULL AND expires_at > now() AND uses < max_uses) AS tickets
        """)).one()
    steps = [
        OnboardingStep(key="agent_group", label="Agent group provisioned by NovrSOC", done=group is not None,
                       detail="" if group else "Ask your NovrSOC administrator to provision it."),
        OnboardingStep(key="agents_installed", label="NovrAgent installed on at least one endpoint", done=agents.total > 0 or t.enrolled > 0,
                       detail=f"{t.enrolled} enrolled by NovrSOC, {agents.total} reporting" if (t.enrolled or agents.total) else "Use an installer command below."),
        OnboardingStep(key="agents_active", label="An agent is reporting", done=agents.active > 0, detail=f"{agents.active} active"),
        OnboardingStep(key="senders", label="Network devices registered (optional)", done=t.sources > 0,
                       detail=f"{t.sources} registered, {t.pending} awaiting NovrSOC verification"),
        OnboardingStep(key="telemetry", label="First security event received", done=t.last_alert_at is not None,
                       detail=f"{t.alerts_24h} in the last 24 h" if t.last_alert_at else ""),
        OnboardingStep(key="assets", label="Assets in the inventory (shared with vulnerability management)", done=t.assets > 0,
                       detail=f"{t.assets} asset(s), {t.vms_enrolled} enrolled for scanning"),
    ]
    return TenantOnboarding(
        organization=PortalOrg(slug=org.slug, name=org.name),
        portal_url=portals.base_url(settings, org.sub, org.portal_enabled) if org.portal_enabled and settings.portal_base_domain else None,
        agent_group=AgentGroupView(provisioned=group is not None, group_name=group.group_name if group else None,
                                   created_at=group.created_at if group else None),
        installer_available=version is not None, installer_reason=why,
        enrollment=AgentEnrollmentStatus(available=version is not None, detail=why, manager_version=manager, agent_version=version,
                                    enrolled_agents=t.enrolled, open_tickets=t.tickets),
        asset_sync=asset_sync_status(conn, settings), agents=agents,
        telemetry=OnboardingTelemetry(alerts_24h=t.alerts_24h, last_alert_at=t.last_alert_at, assets=t.assets, vms_enrolled=t.vms_enrolled),
        sources=OnboardingSources(total=t.sources, pending_verification=t.pending, receiving=t.receiving, never_received=t.never),
        syslog=SyslogTarget(address=settings.syslog_collector_address or None, port=settings.syslog_collector_port, protocols=["udp", "tcp"]),
        steps=steps, completed=sum(s.done for s in steps), total=len(steps))


_RUN = {"windows": "an elevated (Administrator) PowerShell", "linux": "a root shell (sudo)", "macos": "Terminal, with sudo"}


@router.post("/installer", response_model=InstallerCommand, summary="An enrollment ticket and NovrAgent installer command (audited)")
def installer(body: InstallerRequest, request: Request, p: Principal = Depends(require("endpoints:manage")),
              conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> InstallerCommand:
    org = _org(conn, p)
    version, why, _ = enrollment_readiness(settings, org, _group(conn))
    if version is None:
        raise ApiError(409, "installer_unavailable", why)
    token = new_token()
    expires = _now() + timedelta(minutes=settings.enrollment_ticket_ttl_minutes)
    tid = conn.execute(text("""INSERT INTO novrsoc.agent_enrollment_tickets (org_id, os, token_hash, max_uses, created_by, created_label, expires_at)
                               VALUES (:o, :os, :h, :m, :u, :l, :e) RETURNING id"""),
                       {"o": p.org_id, "os": body.os, "h": sha256(token), "m": body.endpoints, "u": p.user_id, "l": p.email, "e": expires}).scalar()
    script = f"novragent.{portals.OS_SCRIPT[body.os]}"
    url = f"{portals.base_url(settings, org.sub, org.portal_enabled)}/api/v1/install/{script}?t={token}"
    if body.os == "windows":
        command = (f'Invoke-WebRequest -UseBasicParsing "{url}" -OutFile {script}; '
                   f"powershell -NoProfile -ExecutionPolicy Bypass -File .\\{script}")
    else:
        command = f'curl -fsSLo {script} "{url}" && sudo sh {script}'
    audit.record("AGENT_ENROLLMENT_TICKET_ISSUED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="enrollment_ticket", resource_id=str(tid), request_id=request.state.request_id, ip=client_ip(request),
                 details={"os": body.os, "max_endpoints": body.endpoints, "expires_at": expires.isoformat(), "agent_version": version})
    return InstallerCommand(os=body.os, command=command, ticket_id=tid, max_endpoints=body.endpoints, expires_at=expires,
                            run_as=_RUN[body.os], agent_version=version,
                            notes=[f"This command enrolls up to {body.endpoints} endpoint(s) of this organization until {expires:%Y-%m-%d %H:%M} UTC; "
                                   "revoke it below at any time.",
                                   "NovrSOC registers each endpoint itself, in this organization's agent group. No password is needed or stored.",
                                   f"Agent version {version}, matched to the NovrSIEM manager. The installer checks the package's publisher "
                                   "signature before installing it.",
                                   "You can download the file first and read it before running it."])


def _ticket_view(r) -> AgentEnrollmentTicket:
    state = "revoked" if r.revoked_at else "used_up" if r.uses >= r.max_uses else "expired" if r.expires_at <= _now() else "open"
    return AgentEnrollmentTicket(id=r.id, os=r.os, max_uses=r.max_uses, uses=r.uses, state=state, created_label=r.created_label,
                                created_at=r.created_at, expires_at=r.expires_at)


@router.get("/tickets", response_model=AgentEnrollmentTicketList, summary="Enrollment tickets of the active organization")
def tickets(p: Principal = Depends(require("endpoints:read")), conn: Connection = Depends(request_connection)) -> AgentEnrollmentTicketList:
    rows = conn.execute(text("SELECT * FROM novrsoc.agent_enrollment_tickets ORDER BY created_at DESC LIMIT 50")).all()
    return AgentEnrollmentTicketList(items=[_ticket_view(r) for r in rows])


@router.post("/tickets/{ticket_id}/revoke", response_model=AgentEnrollmentTicket, summary="Revoke an enrollment ticket (audited)")
def revoke_ticket(ticket_id: uuid.UUID, request: Request, p: Principal = Depends(require("endpoints:manage")),
                  conn: Connection = Depends(request_connection)) -> AgentEnrollmentTicket:
    r = conn.execute(text("UPDATE novrsoc.agent_enrollment_tickets SET revoked_at = now() WHERE id = :i AND revoked_at IS NULL RETURNING *"),
                     {"i": ticket_id}).first()
    if r is None:
        raise not_found("No open ticket with this id")
    audit.record("AGENT_ENROLLMENT_TICKET_REVOKED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="enrollment_ticket", resource_id=str(ticket_id), request_id=request.state.request_id, ip=client_ip(request))
    return _ticket_view(r)
