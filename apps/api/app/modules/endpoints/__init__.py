"""Endpoint management (Phase 4 foundation; ongoing owner: workstream C).

Inventory, details, vulnerability and SCA summaries from the Wazuh connector, scoped to the organization's
mapped agent groups; plus the mapping of Wazuh agent groups to the organization.
The data source state is part of every response: `unconfigured` returns no endpoints, `local_fixture` is
labelled local test data, `live` reads the Wazuh manager/indexer through the API (Phase 5). A connector failure
is reported as `unavailable`/`error` with no items, never as an empty inventory. No request reaches Wazuh from
the browser.
"""
from __future__ import annotations

import uuid

import logging

from fastapi import APIRouter, Depends, Path, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.connectors import registry
from app.connectors.base import ConnectorError, ConnectorRejected, OrgScope, ScopeViolation
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.endpoints import (EndpointDetail, EndpointInventory, EndpointOs, EndpointSummary, GroupMapping,
                                            GroupMappingCreate, GroupMappingList, ScaPolicySummaryView, ScaSummary,
                                            VulnerabilitySummary)

MODULE = ModuleInfo(name="endpoints", workstream="C", prefix="/api/v1/endpoints",
                    summary="Endpoint inventory and details from Wazuh, scoped to the organization")
router = APIRouter(prefix="/api/v1/endpoints", tags=["endpoints"], responses=ERRORS)

# Wazuh agent platforms (os.platform) supported by the Wazuh 4.x agent packages.
SUPPORTED_PLATFORMS = {"windows", "darwin", "ubuntu", "debian", "centos", "rhel", "rocky", "almalinux", "amzn",
                       "ol", "sles", "opensuse", "fedora", "linux"}
AgentId = Path(..., pattern=r"^\d{3,6}$")
log = logging.getLogger("novrsoc.endpoints")


def failed_state(state, exc: ConnectorError):
    """The source state to report after a live connector failure (the message names services/settings only)."""
    if isinstance(exc, ScopeViolation):
        log.error("wazuh scope violation: %s", exc)
        return state.model_copy(update={"state": "error", "detail": "The connector returned data outside the organization scope; nothing was shown."})
    return state.model_copy(update={"state": "error" if isinstance(exc, ConnectorRejected) else "unavailable", "detail": str(exc)[:300]})


def unavailable(exc: ConnectorError) -> ApiError:
    return ApiError(503, "integration_unavailable", "The NovrSIEM connector is unavailable: " + str(exc)[:200]
                    if not isinstance(exc, ScopeViolation) else "The NovrSIEM connector returned out-of-scope data")


def org_scope(conn: Connection, org_id: uuid.UUID) -> OrgScope:
    """The organization's Wazuh scope, read under RLS (only its own mappings are visible)."""
    groups = frozenset(r[0] for r in conn.execute(text("SELECT group_name FROM novrsoc.wazuh_group_mappings")))
    return OrgScope(org_id=org_id, wazuh_agent_groups=groups)


def os_view(raw: dict | None) -> EndpointOs:
    os = raw or {}
    platform = (os.get("platform") or "").lower() or None
    support = "unknown" if platform is None else ("supported" if platform in SUPPORTED_PLATFORMS else "unsupported")
    return EndpointOs(platform=platform, name=os.get("name"), version=os.get("version"), support=support)


def _summary(source, agent) -> EndpointSummary:
    raw = source.raw_agent(agent.agent_id) or {}
    return EndpointSummary(agent_id=agent.agent_id, name=agent.name, status=agent.status, groups=list(agent.groups),
                           os=os_view(raw.get("os")), agent_version=agent.agent_version, ip=raw.get("ip"),
                           last_keepalive_at=agent.last_keepalive_at)


@router.get("", response_model=EndpointInventory, summary="Endpoint inventory of the active organization")
def inventory(p: Principal = Depends(require("endpoints:read")), conn: Connection = Depends(request_connection),
              settings: Settings = Depends(get_settings)) -> EndpointInventory:
    manager_state = registry.wazuh_states(settings)[0]
    scope = org_scope(conn, p.org_id)
    source = registry.wazuh(settings)
    if source is None:
        return EndpointInventory(source=manager_state, items=[], by_status={}, mapped_groups=len(scope.wazuh_agent_groups))
    if manager_state.state not in ("connected", "local_fixture"):
        return EndpointInventory(source=manager_state, items=[], by_status={}, mapped_groups=len(scope.wazuh_agent_groups))
    try:
        items = [_summary(source, a) for a in source.list_agents(scope)]
    except ConnectorError as e:
        return EndpointInventory(source=failed_state(manager_state, e), items=[], by_status={},
                                 mapped_groups=len(scope.wazuh_agent_groups))
    by_status: dict[str, int] = {}
    for i in items:
        by_status[i.status] = by_status.get(i.status, 0) + 1
    return EndpointInventory(source=manager_state, items=items, by_status=by_status, mapped_groups=len(scope.wazuh_agent_groups))


# Wazuh puts every agent in `default` until it is reassigned: mapping it attributes every agent that is in no other
# mapped group to this organization (an agent that is ALSO in another organization's group is quarantined as ambiguous).
BROAD_GROUPS = frozenset({"default"})


@router.get("/group-mappings", response_model=GroupMappingList, summary="Wazuh agent groups mapped to the organization")
def list_mappings(p: Principal = Depends(require("endpoints:read")), conn: Connection = Depends(request_connection),
                  settings: Settings = Depends(get_settings)) -> GroupMappingList:
    rows = conn.execute(text("SELECT id, group_name, created_at FROM novrsoc.wazuh_group_mappings ORDER BY group_name")).all()
    return GroupMappingList(items=[GroupMapping(id=r.id, group_name=r.group_name, created_at=r.created_at,
                                                broad=r.group_name in BROAD_GROUPS,
                                                collection=r.group_name in settings.collection_groups) for r in rows])


@router.post("/group-mappings", response_model=GroupMapping, status_code=201, summary="Map a Wazuh agent group to the organization")
def create_mapping(body: GroupMappingCreate, request: Request, p: Principal = Depends(require("endpoints:manage")),
                   conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> GroupMapping:
    if body.group_name in settings.collection_groups:
        raise ApiError(422, "collection_group_not_mappable",
                       f"'{body.group_name}' is a collection group: NovrSIEM places agents of every "
                       "organization in it, so it can never establish ownership. Put the organization's agents in a group of its "
                       "own and map that group.")
    broad = body.group_name in BROAD_GROUPS
    if broad and not body.acknowledge_broad_group:
        raise ApiError(422, "broad_group_requires_acknowledgement",
                       f"Every NovrAgent is in '{body.group_name}' until it is reassigned: mapping it attributes every agent that "
                       "is in no other mapped group to this organization. Confirm with acknowledge_broad_group.")
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name, created_by)
                                     VALUES (:o, :g, :u) RETURNING id, group_name, created_at"""),
                             {"o": p.org_id, "g": body.group_name, "u": p.user_id}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "This NovrAgent group is already mapped to an organization (one group, one organization: "
                       "an agent's alerts must never match two tenants)")
    audit.record("WAZUH_GROUP_MAPPED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="wazuh_group", resource_id=body.group_name, request_id=request.state.request_id, ip=client_ip(request),
                 details={"broad_group_acknowledged": True} if broad else {})
    return GroupMapping(id=r.id, group_name=r.group_name, created_at=r.created_at, broad=broad)


@router.delete("/group-mappings/{mapping_id}", status_code=204, summary="Remove a Wazuh agent group mapping")
def delete_mapping(mapping_id: uuid.UUID, request: Request, p: Principal = Depends(require("endpoints:manage")),
                   conn: Connection = Depends(request_connection)) -> None:
    r = conn.execute(text("DELETE FROM novrsoc.wazuh_group_mappings WHERE id = :id RETURNING group_name"), {"id": mapping_id}).first()
    if not r:
        raise not_found("Mapping not found")
    audit.record("WAZUH_GROUP_UNMAPPED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="wazuh_group", resource_id=r.group_name, request_id=request.state.request_id, ip=client_ip(request))


@router.get("/{agent_id}", response_model=EndpointDetail, summary="One endpoint: health, OS, vulnerability and SCA summaries")
def detail(agent_id: str = AgentId, p: Principal = Depends(require("endpoints:read")),
           conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> EndpointDetail:
    manager_state, indexer_state = registry.wazuh_states(settings)
    source = registry.wazuh(settings)
    if source is None:
        raise ApiError(503, "integration_unconfigured", "No NovrSIEM connection is configured, so endpoint details are unavailable")
    if manager_state.state not in ("connected", "local_fixture"):
        raise ApiError(503, "integration_unavailable", f"NovrSIEM is {manager_state.state}: {manager_state.detail}"[:300])
    scope = org_scope(conn, p.org_id)
    try:
        agent = source.get_agent(scope, agent_id)
    except ConnectorError as e:
        raise unavailable(e)
    if agent is None:  # unknown, or another organization's endpoint: indistinguishable on purpose
        raise not_found("Endpoint not found")
    try:
        counts = (source.vulnerability_counts(scope, agent_id)
                  if indexer_state.state in ("connected", "local_fixture") else None)
        vulns = (VulnerabilitySummary(source=indexer_state, total=sum(counts.values()), **counts) if counts is not None
                 else VulnerabilitySummary(source=indexer_state if indexer_state.state not in ("connected", "local_fixture")
                                           else indexer_state.model_copy(update={"detail": "No vulnerability data for this endpoint."})))
    except ConnectorError as e:
        vulns = VulnerabilitySummary(source=failed_state(indexer_state, e))
    try:
        sca = ScaSummary(source=manager_state, policies=[
            ScaPolicySummaryView(policy_id=x.policy_id, name=x.name, passed=x.passed, failed=x.failed,
                                 not_applicable=x.not_applicable, score_percent=x.score_percent, scanned_at=x.scanned_at)
            for x in source.sca_policies(scope, agent_id)])
    except ConnectorError as e:
        sca = ScaSummary(source=failed_state(manager_state, e))
    return EndpointDetail(endpoint=_summary(source, agent), source=manager_state, vulnerabilities=vulns, sca=sca)
