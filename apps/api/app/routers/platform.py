"""Platform status for the dashboard (Phase 4, extended in Phase 5): database, migration, connector and module states.

Connector states come from configuration and real checks only; nothing here claims a service is online
without having established it. Module states describe what this build can actually do.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.auth.deps import Principal, require
from app.connectors import registry
from app.core.config import Settings, get_settings
from app.db.session import request_connection
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.endpoints import ConnectorState
from novrsoc_contracts.v1.platform import ModuleState, PlatformStatus

router = APIRouter(prefix="/api/v1/platform", tags=["platform"], responses=ERRORS)

MODULES = [
    ("command", "Command Center", "live", "Every organization's alerts, assets, vulnerabilities, cases, intelligence, NHAI and SOAR activity in one place, read under each organization's own access rules (platform staff only).", "platform:monitor"),
    ("posture", "Executive overview and security posture", "live", "Explainable measurements; missing data is shown as unavailable, never scored.", "org:read"),
    ("reports", "Reports", "live", "Executive, SECOPS, VMS, Threat Intelligence, Brand, Email, CNII, compliance, SLA and audit reports (JSON, CSV, printable preview).", "reports:read"),
    ("alerts", "Alerts", "live", "Alerts arrive from the NovrFORWARDER (or local fixtures in development).", "alerts:read"),
    ("cases", "Cases and incidents", "live", "Timelines, assignment, SLA, remediation and closure notes.", "cases:read"),
    ("playbooks", "Playbooks", "live", "Draft, validate, approve (by another person), retire. Nothing is pre-defined; nothing runs automatically.", "cases:read"),
    ("soar", "SOAR operations", "live", "Human approval for every consequential step; execution only through NovrSOAR; emergency stop.", "cases:read"),
    ("handover", "Shift handover", "live", "Frozen queue snapshot, acknowledged by the incoming analyst.", "cases:read"),
    ("sla", "SLA management", "live", "Policies per severity, live state, escalation and history.", "cases:read"),
    ("vms", "Vulnerability management", "live", "Scopes, scan policy, asset enrollment, scans, schedules, findings, retests and remediation. Scanning runs only where the installation enables it and the organization's scan policy allows it.", "vms:read"),
    ("insights", "Threat Insights", "live", "Indicators, matching, correlation, STIX 2.1 store, threat actors, CVE intelligence and evidence snapshots.", "intel:read"),
    ("assets", "Asset inventory", "live", "One canonical identity per asset, reconciled from NovrSIEM, VMS, email domains and manual entries.", "assets:read"),
    ("log_sources", "Syslog and agentless sources", "live", "Devices that reach NovrSOC through NovrSIEM, each registered to exactly one organization; unattributed events are quarantined.", "endpoints:read"),
    ("collectors", "Collectors and discovery", "live", "NovrAgent sync runs on demand; network discovery and cloud inventory are configuration only (not authorized).", "assets:read"),
    ("email_security", "Email security", "live", "Domains and DMARC aggregate reports. Domain verification needs a DNS adapter (not configured).", "protection:read"),
    ("brand_protection", "Brand protection", "live", "Watch subjects and lookalike monitoring through the configured resolver.", "protection:read"),
    ("chat", "NovrChat", "live", "Read-only, cited answers from the organization's records; prose drafts through NHAI when configured.", "chat:use"),
    ("continuity", "Data loss recovery", "live", "Recovery plans and requests. Only NovrSOC's own database backups are a connected system.", "recovery:read"),
    ("sites", "Sites", "live", "", "sites:read"),
    ("endpoints", "NovrAgent endpoints", "live", "Data depends on the NovrSIEM connector state (unconfigured, local fixture or live).", "endpoints:read"),
]


@router.get("/status", response_model=PlatformStatus, summary="Database, connector and module states")
def status(p: Principal = Depends(require("org:read")), conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> PlatformStatus:
    revision = conn.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar() or "none"
    modules = [ModuleState(key=k, label=label, state=state, note=note)
               for k, label, state, note, perm in MODULES if perm is None or p.has(perm)]
    if p.has("cnii:read"):
        modules.append(ModuleState(key="cnii", label="CNII Watch", state="restricted",
                                   note="Requires an explicit, expiring CNII designation in addition to permissions."))
    nhai_module, ollama = _nhai(conn, settings)
    modules.append(nhai_module)
    return PlatformStatus(database="ok", migration=revision,
                          connectors=[*registry.wazuh_states(settings), ollama], modules=modules)


NHAI = "Novr Human-Assisted Intelligence (NHAI)"


def _nhai(conn: Connection, settings: Settings) -> tuple[ModuleState, ConnectorState]:
    """NHAI readiness from configuration and the organization's most recent finished job. The API never calls Ollama,
    so `connected` is claimed only when an inference actually succeeded in the last 24 hours."""
    if settings.nhai_backend == "unconfigured":
        return (ModuleState(key="nhai", label=NHAI, state="not_available", note="No inference backend is configured."),
                registry.ollama_state())
    if settings.nhai_backend == "test_adapter":
        return (ModuleState(key="nhai", label=NHAI, state="not_available",
                            note="Development test adapter only: deterministic restatement, not a language model."),
                ConnectorState(connector="ollama", state="local_fixture", detail="Development test adapter; not a model."))
    last = conn.execute(text("""SELECT status, error_code, finished_at FROM novrsoc.nhai_jobs WHERE finished_at IS NOT NULL
                                AND finished_at > now() - interval '24 hours' ORDER BY finished_at DESC LIMIT 1""")).first()
    if last is not None and last.status == "succeeded":
        return (ModuleState(key="nhai", label=NHAI, state="live",
                            note="Asynchronous drafts for human review. CPU inference: expect minutes per result."),
                ConnectorState(connector="ollama", state="connected", checked_at=last.finished_at,
                               detail="The last NHAI analysis succeeded."))
    detail = (f"The last NHAI job ended {last.status} ({last.error_code})." if last is not None
              else "NHAI is configured; no analysis has completed in the last 24 hours, so availability is not established.")
    return (ModuleState(key="nhai", label=NHAI, state="not_available", note=detail[:200]),
            ConnectorState(connector="ollama", state="unavailable", detail=detail[:300]))
