"""Unified asset inventory (consolidation; workstream C): canonical assets, reconciliation, detail, collectors.

One asset, one identity: Wazuh agents, VMS hosts, email domains and manual entries reconcile to the same record
(app/assets/reconcile.py). Asset detail brings together the Wazuh agent (through the configured connector, labelled
with its source state), VMS findings, alerts, cases, SOAR runs, Threat Insights matches, history, trends and NHAI
summaries. Wazuh vulnerability detection is shown NEXT TO VMS findings and never merged into them.
Collectors: a Wazuh sync reads the configured connector (fixture or live, read-only); active network discovery and
cloud inventory are configuration only in this release: nothing scans or calls a cloud API.
"""
from __future__ import annotations

import ipaddress
import json
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request, Response
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.assets import reconcile
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.connectors import registry
from app.connectors.base import ConnectorError
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.modules.endpoints import failed_state, org_scope, os_view
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.endpoints import ScaPolicySummaryView, ScaSummary, VulnerabilitySummary
from novrsoc_contracts.v1.inventory import (AssetAlertRef, AssetCaseRef, AssetCreate, AssetDetail, AssetEventView, AssetFindingRef,
                                            AssetIdentifierView, AssetIntelRef, AssetList, AssetMerge, AssetMonitoring, AssetRetire,
                                            AssetServiceView, AssetSoarRef, AssetSummary, AssetTrendPoint, AssetUpdate, CollectorCreate,
                                            CollectorList, CollectorUpdate, CollectorView, ConflictList, ConflictView, SyncRunList,
                                            SyncRunView, WazuhAgentContext)

MODULE = ModuleInfo(name="assets", workstream="C", prefix="/api/v1/assets",
                    summary="Unified asset inventory: canonical identities, reconciliation, detail, collectors")
router = APIRouter(prefix="/api/v1/assets", tags=["assets"], responses=ERRORS)

OPEN_FINDING = "('verified', 'risk_accepted')"
DETECTION_NOTE = ("NovrSIEM vulnerability detection reads installed packages through the agent; VMS findings come from "
                  "authorized network scans. They are listed separately and never merged: the same CVE seen by both is two "
                  "observations with different evidence.")
EXECUTION = {
    "wazuh_sync": "Reads agents from the configured NovrSIEM connector (read-only) and reconciles them. Runs on demand.",
    "network_discovery": "Configuration only. Active network discovery is not authorized in this release; nothing scans.",
    "cloud_inventory": "Configuration only. No cloud inventory adapter is configured; nothing is called.",
    "manual_import": "Imports the rows an analyst uploads through the inventory import.",
}


def _audit(p: Principal, request: Request, action: str, rid: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="asset", resource_id=rid,
                 request_id=request.state.request_id, ip=client_ip(request), details=details or {})


_LIST_SQL = f"""
SELECT a.*, host(a.primary_ip) AS ip_text, s.name AS site_name,
       (SELECT i.value FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent' LIMIT 1) AS wazuh_agent,
       (SELECT max(j.finished_at) FROM novrsoc.vms_scan_jobs j WHERE j.state = 'completed'
          AND j.targets && ARRAY(SELECT i.value FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id
                                 AND i.kind IN ('ip', 'fqdn', 'domain', 'hostname'))) AS last_scan,
       (SELECT array_agg(DISTINCT src ORDER BY src) FROM novrsoc.asset_identifiers i, unnest(i.sources) src WHERE i.asset_id = a.id) AS srcs,
       (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = a.id AND f.status NOT IN {OPEN_FINDING}) AS open_findings,
       (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = a.id AND f.status NOT IN {OPEN_FINDING} AND f.severity = 'critical') AS crit_findings,
       (SELECT count(*) FROM novrsoc.alerts al WHERE al.asset_id = a.id AND al.status <> 'closed') AS open_alerts,
       EXISTS (SELECT 1 FROM novrsoc.cnii_monitored_assets c WHERE c.asset_id = a.id AND c.status = 'active') AS cnii
FROM novrsoc.assets a LEFT JOIN novrsoc.sites s ON s.id = a.site_id"""


def _summary(r) -> AssetSummary:
    recent = r.last_scan is not None and r.last_scan > datetime.now(timezone.utc) - timedelta(days=30)
    state = "monitored" if (r.wazuh_agent and recent) else "partial" if (r.wazuh_agent or recent) else "unmonitored"
    return AssetSummary(
        id=r.id, kind=r.kind, display_name=r.display_name, hostname=r.hostname and str(r.hostname), fqdn=r.fqdn and str(r.fqdn),
        primary_ip=r.ip_text, site_id=r.site_id, site_name=r.site_name, os_platform=r.os_platform, os_name=r.os_name,
        os_version=r.os_version, classification=r.classification, criticality=r.criticality, exposure=r.exposure, owner=r.owner,
        tags=list(r.tags or []), status=r.status, merged_into=r.merged_into,
        monitoring=AssetMonitoring(state=state, wazuh_agent_id=r.wazuh_agent, last_vms_scan_at=r.last_scan, cnii_designated=bool(r.cnii)),
        sources=list(r.srcs or []), open_findings=r.open_findings, critical_findings=r.crit_findings, open_alerts=r.open_alerts,
        first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at)


def get_summary(conn: Connection, asset_id: uuid.UUID) -> AssetSummary:
    r = conn.execute(text(_LIST_SQL + " WHERE a.id = :id"), {"id": asset_id}).first()
    if r is None:
        raise not_found("Asset not found")
    return _summary(r)


@router.get("", response_model=AssetList, summary="Unified asset inventory of the active organization")
def list_assets(q: str | None = Query(None, max_length=200), kind: str | None = Query(None, pattern=r"^[a-z_]{2,30}$"),
                criticality: Literal["low", "medium", "high", "critical"] | None = None,
                monitoring: Literal["monitored", "partial", "unmonitored"] | None = None,
                status: Literal["active", "retired", "all"] = "active", site_id: uuid.UUID | None = None,
                limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0, le=100_000),
                p: Principal = Depends(require("assets:read")), conn: Connection = Depends(request_connection)) -> AssetList:
    where, params = ["true"], {}
    if status != "all":
        where.append("a.status = :status"); params["status"] = status
    if kind:
        where.append("a.kind = :kind"); params["kind"] = kind
    if criticality:
        where.append("a.criticality = :crit"); params["crit"] = criticality
    if site_id:
        where.append("a.site_id = :site"); params["site"] = site_id
    if q:
        where.append("""(a.display_name ILIKE :q OR a.hostname::text ILIKE :q OR a.fqdn::text ILIKE :q OR host(a.primary_ip) ILIKE :q
                         OR a.owner ILIKE :q OR EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.value ILIKE :q))""")
        params["q"] = f"%{q.strip()}%"
    rows = [_summary(r) for r in conn.execute(text(_LIST_SQL + " WHERE " + " AND ".join(where) +
                                                   " ORDER BY CASE a.criticality WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, lower(a.display_name)"),
                                              params)]
    by_monitoring: dict[str, int] = {}
    for r in rows:
        by_monitoring[r.monitoring.state] = by_monitoring.get(r.monitoring.state, 0) + 1
    if monitoring:
        rows = [r for r in rows if r.monitoring.state == monitoring]
    by_kind: dict[str, int] = {}
    by_crit: dict[str, int] = {}
    for r in rows:
        by_kind[r.kind] = by_kind.get(r.kind, 0) + 1
        by_crit[r.criticality] = by_crit.get(r.criticality, 0) + 1
    return AssetList(items=rows[offset:offset + limit], total=len(rows), limit=limit, offset=offset, by_kind=by_kind,
                     by_criticality=by_crit, by_monitoring=by_monitoring)


def _observation_from_create(body: AssetCreate, source: str) -> reconcile.Observation:
    ids: list[tuple[str, str]] = []
    if body.ip:
        try:
            ipaddress.ip_address(body.ip.strip())
        except ValueError:
            raise ApiError(422, "validation_error", "ip is not a valid address")
        ids.append(("ip", body.ip))
    if body.fqdn:
        ids.append(("domain" if body.kind == "domain" else "fqdn", body.fqdn))
    if body.hostname:
        ids.append(("hostname", body.hostname))
    if body.kind == "domain" and not body.fqdn and reconcile.normalize("domain", body.display_name):
        ids.append(("domain", body.display_name))
    if not any(reconcile.normalize(k, v) for k, v in ids):
        raise ApiError(422, "validation_error", "An asset needs at least one valid identifier (IP address, FQDN/domain or hostname)")
    return reconcile.Observation(source=source, kind=body.kind, display_name=body.display_name, identifiers=ids, site_id=body.site_id,
                                 attributes={"hostname": reconcile.normalize("hostname", body.hostname or ""),
                                             "fqdn": reconcile.normalize("fqdn", body.fqdn or ""), "primary_ip": body.ip,
                                             "classification": body.classification, "criticality": body.criticality,
                                             "exposure": body.exposure, "owner": body.owner, "tags": body.tags})


@router.post("", response_model=AssetSummary, status_code=201, summary="Add an asset (reconciled: an existing identity is reused)")
def create_asset(body: AssetCreate, request: Request, response: Response, p: Principal = Depends(require("assets:manage")),
                 conn: Connection = Depends(request_connection)) -> AssetSummary:
    if body.site_id and conn.execute(text("SELECT 1 FROM novrsoc.sites WHERE id = :s"), {"s": body.site_id}).first() is None:
        raise not_found("Site not found")
    out = reconcile.upsert(conn, _observation_from_create(body, "manual"), p.email)
    if not out.created:
        response.status_code = 200
    _audit(p, request, "ASSET_CREATED" if out.created else "ASSET_RECONCILED", str(out.asset_id), {"conflicts": out.conflicts})
    return get_summary(conn, out.asset_id)


@router.post("/import", response_model=SyncRunView, summary="Import assets (manual list, up to 500 rows), reconciled")
def import_assets(body: list[AssetCreate], request: Request, p: Principal = Depends(require("assets:manage")),
                  conn: Connection = Depends(request_connection)) -> SyncRunView:
    if not 1 <= len(body) <= 500:
        raise ApiError(422, "validation_error", "Import between 1 and 500 assets at a time")
    created = updated = conflicts = 0
    for row in body:
        out = reconcile.upsert(conn, _observation_from_create(row, "manual"), p.email)
        created += out.created
        updated += not out.created
        conflicts += out.conflicts
    r = conn.execute(text("""INSERT INTO novrsoc.asset_sync_runs (org_id, source, source_state, finished_at, outcome, observed, created,
                                                                  updated, conflicts, requested_label)
                             VALUES (:o, 'manual_import', 'manual', now(), 'completed', :n, :c, :u, :x, :l) RETURNING *"""),
                     {"o": p.org_id, "n": len(body), "c": created, "u": updated, "x": conflicts, "l": p.email}).one()
    _audit(p, request, "ASSETS_IMPORTED", str(r.id), {"rows": len(body), "created": created, "conflicts": conflicts})
    return _run(r)


def _run(r) -> SyncRunView:
    return SyncRunView(id=r.id, source=r.source, source_state=r.source_state, started_at=r.started_at, finished_at=r.finished_at,
                       outcome=r.outcome, observed=r.observed, created=r.created, updated=r.updated, conflicts=r.conflicts,
                       detail=r.detail, requested_label=r.requested_label)


def sync_wazuh(conn: Connection, settings: Settings, org_id: uuid.UUID, label: str):
    """Reconcile the organization's Wazuh agents into the inventory. Returns the sync run row."""
    manager_state = registry.wazuh_states(settings)[0]
    source = registry.wazuh(settings)
    counts = {"observed": 0, "created": 0, "updated": 0, "conflicts": 0}
    outcome, detail = "completed", ""
    if source is None:
        outcome, detail = "source_unconfigured", "No NovrSIEM connection is configured; nothing was read."
    elif manager_state.state not in ("connected", "local_fixture"):
        outcome, detail = "source_unavailable", f"NovrSIEM {manager_state.state}: {manager_state.detail}"[:300]
    else:
        try:
            scope = org_scope(conn, org_id, settings.collection_groups)
            for agent in source.list_agents(scope):
                raw = source.raw_agent(agent.agent_id) or {}
                os = os_view(raw.get("os"))
                ip = raw.get("ip") if raw.get("ip") and raw.get("ip") != "any" else None
                ids = [("wazuh_agent", agent.agent_id), ("hostname", agent.name)] + ([("ip", ip)] if ip else [])
                out = reconcile.upsert(conn, reconcile.Observation(
                    source="wazuh", kind="host", display_name=agent.name, identifiers=ids,
                    attributes={"hostname": reconcile.normalize("hostname", agent.name), "primary_ip": reconcile.normalize("ip", ip),
                                "os_platform": os.platform, "os_name": os.name, "os_version": os.version}), label)
                conn.execute(text("UPDATE novrsoc.alerts SET asset_id = :a WHERE agent_id = :g AND asset_id IS NULL"),
                             {"a": out.asset_id, "g": agent.agent_id})   # link earlier alerts of this agent
                counts["observed"] += 1
                counts["created"] += out.created
                counts["updated"] += not out.created
                counts["conflicts"] += out.conflicts
            if manager_state.state == "local_fixture":
                detail = "Local fixture data (development); not live telemetry."
        except ConnectorError as e:
            outcome, detail = "source_unavailable", failed_state(manager_state, e).detail
    return conn.execute(text("""INSERT INTO novrsoc.asset_sync_runs (org_id, source, source_state, finished_at, outcome, observed, created,
                                                                     updated, conflicts, detail, requested_label)
                                VALUES (:o, 'wazuh', :st, now(), :oc, :n, :c, :u, :x, :d, :l) RETURNING *"""),
                        {"o": org_id, "st": manager_state.state, "oc": outcome, "n": counts["observed"], "c": counts["created"],
                         "u": counts["updated"], "x": counts["conflicts"], "d": detail, "l": label}).one()


@router.post("/sync/wazuh", response_model=SyncRunView, summary="Reconcile the organization's Wazuh agents into the inventory")
def run_wazuh_sync(request: Request, p: Principal = Depends(require("assets:manage")), conn: Connection = Depends(request_connection),
                   settings: Settings = Depends(get_settings)) -> SyncRunView:
    r = sync_wazuh(conn, settings, p.org_id, p.email)
    conn.execute(text("UPDATE novrsoc.collectors SET last_run_at = now(), last_outcome = :o WHERE kind = 'wazuh_sync'"), {"o": r.outcome})
    _audit(p, request, "ASSET_SYNC_RUN", str(r.id), {"source": "wazuh", "outcome": r.outcome, "observed": r.observed})
    return _run(r)


@router.get("/sync-runs", response_model=SyncRunList, summary="Reconciliation runs (newest first)")
def sync_runs(p: Principal = Depends(require("assets:read")), conn: Connection = Depends(request_connection)) -> SyncRunList:
    return SyncRunList(items=[_run(r) for r in conn.execute(text("SELECT * FROM novrsoc.asset_sync_runs ORDER BY started_at DESC LIMIT 50"))])


@router.get("/conflicts", response_model=ConflictList, summary="Identifier conflicts waiting for an analyst (merge or ignore)")
def conflicts(p: Principal = Depends(require("assets:read")), conn: Connection = Depends(request_connection)) -> ConflictList:
    rows = conn.execute(text("""SELECT e.id, e.asset_id, a.display_name, e.occurred_at, e.source, e.details,
                                       b.id AS bound_id, b.display_name AS bound_name
                                FROM novrsoc.asset_events e JOIN novrsoc.assets a ON a.id = e.asset_id
                                LEFT JOIN novrsoc.assets b ON b.id = CAST(e.details->>'bound_to' AS uuid)
                                WHERE e.kind = 'identifier_conflict' AND a.status = 'active' AND (b.id IS NULL OR b.status = 'active')
                                ORDER BY e.id DESC LIMIT 200""")).all()
    return ConflictList(items=[ConflictView(event_id=r.id, asset_id=r.asset_id, asset_name=r.display_name, occurred_at=r.occurred_at,
                                            identifier_kind=r.details.get("identifier_kind", ""), identifier_value=r.details.get("identifier_value", ""),
                                            bound_to_asset_id=r.bound_id, bound_to_asset_name=r.bound_name, source=r.source) for r in rows])


# ---------------------------------------------------------------- collectors and discovery settings
def _collector(r) -> CollectorView:
    return CollectorView(id=r.id, name=r.name, kind=r.kind, site_id=r.site_id, enabled=r.enabled, interval_minutes=r.interval_minutes,
                         settings=r.settings or {}, authorization_reference=r.authorization_reference, last_run_at=r.last_run_at,
                         last_outcome=r.last_outcome, created_at=r.created_at, execution=EXECUTION[r.kind])


@router.get("/collectors", response_model=CollectorList, summary="Collector and discovery settings")
def list_collectors(p: Principal = Depends(require("assets:read")), conn: Connection = Depends(request_connection)) -> CollectorList:
    return CollectorList(items=[_collector(r) for r in conn.execute(text("SELECT * FROM novrsoc.collectors ORDER BY name"))])


@router.post("/collectors", response_model=CollectorView, status_code=201, summary="Add a collector or discovery configuration (disabled)")
def create_collector(body: CollectorCreate, request: Request, p: Principal = Depends(require("assets:manage")),
                     conn: Connection = Depends(request_connection)) -> CollectorView:
    if body.site_id and conn.execute(text("SELECT 1 FROM novrsoc.sites WHERE id = :s"), {"s": body.site_id}).first() is None:
        raise not_found("Site not found")
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.collectors (org_id, site_id, name, kind, interval_minutes, settings,
                                                                     authorization_reference, created_by)
                                     VALUES (:o, :s, :n, :k, :i, CAST(:st AS jsonb), :a, :u) RETURNING *"""),
                             {"o": p.org_id, "s": body.site_id, "n": body.name, "k": body.kind, "i": body.interval_minutes,
                              "st": json.dumps(body.settings), "a": body.authorization_reference, "u": p.user_id}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "A collector with this name already exists")
    audit.record("COLLECTOR_CREATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="collector",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request), details={"kind": body.kind})
    return _collector(r)


@router.patch("/collectors/{collector_id}", response_model=CollectorView, summary="Change a collector (enabling discovery needs an authorization)")
def update_collector(collector_id: uuid.UUID, body: CollectorUpdate, request: Request, p: Principal = Depends(require("assets:manage")),
                     conn: Connection = Depends(request_connection)) -> CollectorView:
    r = conn.execute(text("SELECT * FROM novrsoc.collectors WHERE id = :i"), {"i": collector_id}).first()
    if r is None:
        raise not_found("Collector not found")
    auth_ref = body.authorization_reference if body.authorization_reference is not None else r.authorization_reference
    enabled = body.enabled if body.enabled is not None else r.enabled
    if r.kind == "network_discovery" and enabled and len(auth_ref.strip()) < 3:
        raise ApiError(422, "authorization_required", "Network discovery can only be enabled with a recorded authorization reference")
    r = conn.execute(text("""UPDATE novrsoc.collectors SET enabled = :e, interval_minutes = coalesce(:i, interval_minutes),
                               settings = coalesce(CAST(:st AS jsonb), settings), authorization_reference = :a, updated_at = now()
                             WHERE id = :id RETURNING *"""),
                     {"e": enabled, "i": body.interval_minutes, "st": None if body.settings is None else json.dumps(body.settings),
                      "a": auth_ref, "id": collector_id}).one()
    audit.record("COLLECTOR_UPDATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="collector",
                 resource_id=str(collector_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"enabled": enabled, "kind": r.kind})
    return _collector(r)


@router.delete("/collectors/{collector_id}", status_code=204, summary="Remove a collector configuration")
def delete_collector(collector_id: uuid.UUID, request: Request, p: Principal = Depends(require("assets:manage")),
                     conn: Connection = Depends(request_connection)) -> Response:
    r = conn.execute(text("DELETE FROM novrsoc.collectors WHERE id = :i RETURNING name"), {"i": collector_id}).first()
    if r is None:
        raise not_found("Collector not found")
    audit.record("COLLECTOR_DELETED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="collector",
                 resource_id=str(collector_id), request_id=request.state.request_id, ip=client_ip(request), details={"name": r.name})
    return Response(status_code=204)


@router.post("/collectors/{collector_id}/run", response_model=SyncRunView, summary="Run a collector now (what runs depends on its kind)")
def run_collector(collector_id: uuid.UUID, request: Request, p: Principal = Depends(require("assets:manage")),
                  conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> SyncRunView:
    c = conn.execute(text("SELECT * FROM novrsoc.collectors WHERE id = :i"), {"i": collector_id}).first()
    if c is None:
        raise not_found("Collector not found")
    if c.kind == "wazuh_sync":
        r = sync_wazuh(conn, settings, p.org_id, p.email)
    else:
        reason = {"network_discovery": "Active network discovery is not authorized in this release; nothing was scanned.",
                  "cloud_inventory": "No cloud inventory adapter is configured; nothing was called.",
                  "manual_import": "Manual imports run through the inventory import, not on a schedule."}[c.kind]
        r = conn.execute(text("""INSERT INTO novrsoc.asset_sync_runs (org_id, source, source_state, finished_at, outcome, detail, requested_label)
                                 VALUES (:o, :s, 'unconfigured', now(), 'source_unconfigured', :d, :l) RETURNING *"""),
                         {"o": p.org_id, "s": c.kind, "d": reason, "l": p.email}).one()
    conn.execute(text("UPDATE novrsoc.collectors SET last_run_at = now(), last_outcome = :o WHERE id = :i"), {"o": r.outcome, "i": collector_id})
    audit.record("COLLECTOR_RUN", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="collector",
                 resource_id=str(collector_id), request_id=request.state.request_id, ip=client_ip(request), details={"outcome": r.outcome})
    return _run(r)


# ---------------------------------------------------------------- one asset
def _wazuh_context(conn: Connection, settings: Settings, org_id: uuid.UUID, agent_id: str) -> WazuhAgentContext:
    manager_state, indexer_state = registry.wazuh_states(settings)
    source = registry.wazuh(settings)
    if source is None or manager_state.state not in ("connected", "local_fixture"):
        return WazuhAgentContext(source=manager_state, agent_id=agent_id)
    scope = org_scope(conn, org_id, settings.collection_groups)
    try:
        agent = source.get_agent(scope, agent_id)
    except ConnectorError as e:
        return WazuhAgentContext(source=failed_state(manager_state, e), agent_id=agent_id)
    if agent is None:
        return WazuhAgentContext(source=manager_state.model_copy(update={"detail": "The agent is not (or no longer) in this organization's "
                                                                                   "NovrAgent groups."}), agent_id=agent_id)
    try:
        counts = source.vulnerability_counts(scope, agent_id) if indexer_state.state in ("connected", "local_fixture") else None
        vulns = (VulnerabilitySummary(source=indexer_state, total=sum(counts.values()), **counts) if counts is not None
                 else VulnerabilitySummary(source=indexer_state))
    except ConnectorError as e:
        vulns = VulnerabilitySummary(source=failed_state(indexer_state, e))
    try:
        sca = ScaSummary(source=manager_state, policies=[ScaPolicySummaryView(
            policy_id=x.policy_id, name=x.name, passed=x.passed, failed=x.failed, not_applicable=x.not_applicable,
            score_percent=x.score_percent, scanned_at=x.scanned_at) for x in source.sca_policies(scope, agent_id)])
    except ConnectorError as e:
        sca = ScaSummary(source=failed_state(manager_state, e))
    return WazuhAgentContext(source=manager_state, agent_id=agent_id, name=agent.name, status=agent.status, groups=list(agent.groups),
                             agent_version=agent.agent_version, last_keepalive_at=agent.last_keepalive_at, vulnerabilities=vulns, sca=sca)


@router.get("/{asset_id}", response_model=AssetDetail, summary="One asset across SIEM, VMS, cases, SOAR and intelligence")
def detail(asset_id: uuid.UUID, p: Principal = Depends(require("assets:read")), conn: Connection = Depends(request_connection),
           settings: Settings = Depends(get_settings)) -> AssetDetail:
    from app.modules.nhai import jobs_for_subject  # late import: nhai imports the asset bundle builder
    asset = get_summary(conn, asset_id)
    idents = [AssetIdentifierView(kind=r.kind, value=r.value, site_key=r.site_key, sources=list(r.sources), first_seen_at=r.first_seen_at,
                                  last_seen_at=r.last_seen_at)
              for r in conn.execute(text("SELECT * FROM novrsoc.asset_identifiers WHERE asset_id = :a ORDER BY kind, value"), {"a": asset_id})]
    services = [AssetServiceView(port=r.port, protocol=r.protocol, name=r.name, product=r.product, version=r.version, source=r.source,
                                 first_seen_at=r.first_seen_at, last_seen_at=r.last_seen_at)
                for r in conn.execute(text("SELECT * FROM novrsoc.asset_services WHERE asset_id = :a ORDER BY port, product"), {"a": asset_id})]
    findings = [AssetFindingRef(id=r.id, title=r.title, severity=r.severity, status=r.status, priority=r.priority, risk_score=r.risk_score,
                                cves=list(r.cves), port=r.port, last_seen_at=r.last_seen_at)
                for r in conn.execute(text("""SELECT * FROM novrsoc.vms_findings WHERE asset_id = :a
                                              ORDER BY (status IN ('verified', 'risk_accepted')), risk_score DESC LIMIT 200"""), {"a": asset_id})]
    alerts = [AssetAlertRef(id=r.id, rule_id=r.rule_id, rule_description=r.rule_description, severity=r.severity, status=r.status,
                            observed_at=r.observed_at, case_id=r.case_id, source=r.source)
              for r in conn.execute(text("""SELECT a.*, (SELECT ca.case_id FROM novrsoc.case_alerts ca WHERE ca.alert_id = a.id ORDER BY ca.linked_at DESC LIMIT 1) AS case_id
                                            FROM novrsoc.alerts a WHERE a.asset_id = :a ORDER BY a.observed_at DESC LIMIT 100"""), {"a": asset_id})]
    cases = [AssetCaseRef(id=r.id, reference=f"CASE-{r.number:06d}", title=r.title, severity=r.severity, status=r.status, created_at=r.created_at)
             for r in conn.execute(text("""SELECT DISTINCT c.* FROM novrsoc.cases c JOIN novrsoc.case_alerts ca ON ca.case_id = c.id
                                           JOIN novrsoc.alerts a ON a.id = ca.alert_id WHERE a.asset_id = :a ORDER BY c.created_at DESC LIMIT 50"""),
                                   {"a": asset_id})]
    case_ids = [c.id for c in cases]
    runs = [AssetSoarRef(run_id=r.id, case_id=r.case_id, playbook_name=r.name, state=r.state, mode=r.mode, created_at=r.created_at)
            for r in conn.execute(text("""SELECT r.*, p.name FROM novrsoc.soar_runs r JOIN novrsoc.soar_playbooks p ON p.id = r.playbook_id
                                          WHERE r.case_id = ANY(:c) ORDER BY r.created_at DESC LIMIT 50"""), {"c": case_ids})] if case_ids else []
    intel = [AssetIntelRef(match_id=r.id, alert_id=r.alert_id, indicator_type=r.type, indicator_value=r.value, confidence=r.confidence,
                           verdict=r.verdict, matched_at=r.matched_at)
             for r in conn.execute(text("""SELECT m.id, m.alert_id, i.type, i.value, m.confidence, m.verdict, m.matched_at
                                           FROM novrsoc.ti_matches m JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id
                                           JOIN novrsoc.alerts a ON a.id = m.alert_id WHERE a.asset_id = :a ORDER BY m.matched_at DESC LIMIT 50"""),
                                   {"a": asset_id})]
    events = [AssetEventView(id=r.id, occurred_at=r.occurred_at, kind=r.kind, source=r.source, actor_label=r.actor_label, details=r.details or {})
              for r in conn.execute(text("SELECT * FROM novrsoc.asset_events WHERE asset_id = :a ORDER BY id DESC LIMIT 100"), {"a": asset_id})]
    trend = [AssetTrendPoint(week_start=r.wk, alerts=r.alerts, new_findings=r.new_f, resolved_findings=r.done_f)
             for r in conn.execute(text("""
                SELECT w::date AS wk,
                  (SELECT count(*) FROM novrsoc.alerts a WHERE a.asset_id = :a AND a.observed_at >= w AND a.observed_at < w + interval '7 days') AS alerts,
                  (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.asset_id = :a AND f.first_seen_at >= w AND f.first_seen_at < w + interval '7 days') AS new_f,
                  (SELECT count(*) FROM novrsoc.vms_remediation_tasks t JOIN novrsoc.vms_findings f ON f.id = t.finding_id
                    WHERE f.asset_id = :a AND t.status = 'done' AND t.updated_at >= w AND t.updated_at < w + interval '7 days') AS done_f
                FROM generate_series(date_trunc('week', now()) - interval '11 weeks', date_trunc('week', now()), interval '7 days') w ORDER BY w"""),
                {"a": asset_id})]
    agent = asset.monitoring.wazuh_agent_id
    cnii = conn.execute(text("""SELECT c.sector, c.owning_unit, c.monitoring, c.status, a.reference FROM novrsoc.cnii_monitored_assets c
                                JOIN novrsoc.cnii_authorizations a ON a.id = c.authorization_id WHERE c.asset_id = :a"""), {"a": asset_id}).first()
    return AssetDetail(asset=asset, identifiers=idents, services=services,
                       wazuh=_wazuh_context(conn, settings, p.org_id, agent) if agent else None, detection_note=DETECTION_NOTE,
                       findings=findings, alerts=alerts, cases=cases, soar_runs=runs, intel=intel, events=events, trend=trend,
                       nhai_jobs=jobs_for_subject(conn, "asset", str(asset_id)) if p.has("nhai:analyze") else [],
                       cnii={"sector": cnii.sector, "owning_unit": cnii.owning_unit, "monitoring": cnii.monitoring, "status": cnii.status,
                             "authorization": cnii.reference} if cnii else None)


@router.patch("/{asset_id}", response_model=AssetSummary, summary="Classify or update an asset")
def update_asset(asset_id: uuid.UUID, body: AssetUpdate, request: Request, p: Principal = Depends(require("assets:manage")),
                 conn: Connection = Depends(request_connection)) -> AssetSummary:
    before = get_summary(conn, asset_id)
    if before.status != "active":
        raise ApiError(409, "conflict", "A retired asset cannot be changed")
    changes = body.model_dump(exclude_none=True)
    if not changes:
        return before
    if "site_id" in changes and conn.execute(text("SELECT 1 FROM novrsoc.sites WHERE id = :s"), {"s": body.site_id}).first() is None:
        raise not_found("Site not found")
    sets = ", ".join(f"{k} = :{k}" for k in changes)
    conn.execute(text(f"UPDATE novrsoc.assets SET {sets}, updated_at = now() WHERE id = :id"), {**changes, "id": asset_id})
    diff = {k: {"from": getattr(before, k, None), "to": v} for k, v in changes.items()}
    kind = "reclassified" if {"classification", "criticality", "exposure"} & set(changes) else "updated"
    reconcile._event(conn, asset_id, kind, "manual", p.email, {"changes": diff})
    _audit(p, request, "ASSET_UPDATED", str(asset_id), {"fields": sorted(changes)})
    return get_summary(conn, asset_id)


@router.post("/{asset_id}/merge", response_model=AssetSummary, summary="Merge another asset into this one (deduplication)")
def merge_asset(asset_id: uuid.UUID, body: AssetMerge, request: Request, p: Principal = Depends(require("assets:manage")),
                conn: Connection = Depends(request_connection)) -> AssetSummary:
    if body.source_asset_id == asset_id:
        raise ApiError(422, "validation_error", "An asset cannot be merged into itself")
    target, source = get_summary(conn, asset_id), get_summary(conn, body.source_asset_id)
    if target.status != "active" or source.status != "active":
        raise ApiError(409, "conflict", "Both assets must be active")
    reconcile.merge(conn, asset_id, body.source_asset_id, body.reason, p.email)
    _audit(p, request, "ASSET_MERGED", str(asset_id), {"merged": str(body.source_asset_id), "reason": body.reason})
    return get_summary(conn, asset_id)


@router.post("/{asset_id}/retire", response_model=AssetSummary, summary="Retire an asset (kept with its history)")
def retire_asset(asset_id: uuid.UUID, body: AssetRetire, request: Request, p: Principal = Depends(require("assets:manage")),
                 conn: Connection = Depends(request_connection)) -> AssetSummary:
    if get_summary(conn, asset_id).status != "active":
        raise ApiError(409, "conflict", "The asset is already retired")
    conn.execute(text("UPDATE novrsoc.assets SET status = 'retired', updated_at = now() WHERE id = :i"), {"i": asset_id})
    reconcile._event(conn, asset_id, "retired", "manual", p.email, {"reason": body.reason})
    _audit(p, request, "ASSET_RETIRED", str(asset_id), {"reason": body.reason})
    return get_summary(conn, asset_id)
