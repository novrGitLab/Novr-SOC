"""Wazuh Manager API and Wazuh Indexer connector interfaces (read-only).

Implementation: workstream C (agents, SCA) and workstream A (alerts through the forwarder/indexer).
Response actions (active response) are NOT here: they belong to the SOAR connector and run only
after a human approval (contracts v1/soar.py).

Tenant safety: one Wazuh deployment serves many organizations. Every method takes an OrgScope.
  * Manager: results are filtered to the scope's agent groups, and the implementation must re-check
    every returned agent (filter_agents) before returning: a result outside the scope raises ScopeViolation.
  * Indexer: the organization filter is added server-side by indexer_scope_query() and wraps any caller
    query, so a caller cannot remove or widen it.
Configuration (names only): WAZUH_URL, WAZUH_USER, WAZUH_PASSWORD, WAZUH_CA_CERT, WAZUH_TLS_SERVERNAME;
WAZUH_INDEXER_URL, WAZUH_INDEXER_USER, WAZUH_INDEXER_PASSWORD, WAZUH_INDEXER_CA_CERT, WAZUH_INDEXER_TLS_SERVERNAME.
"""
from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from app.connectors.base import ConnectorHealth, Endpoint, OrgScope, ScopeViolation, load_endpoint

MANAGER_CREDENTIALS = ("WAZUH_USER", "WAZUH_PASSWORD")
INDEXER_CREDENTIALS = ("WAZUH_INDEXER_USER", "WAZUH_INDEXER_PASSWORD")


@dataclass(frozen=True)
class WazuhAgent:
    agent_id: str
    name: str
    groups: tuple[str, ...]
    status: str
    os_platform: str | None = None
    os_version: str | None = None
    agent_version: str | None = None
    last_keepalive_at: datetime | None = None


@dataclass(frozen=True)
class ScaPolicySummary:
    agent_id: str
    policy_id: str
    name: str
    passed: int
    failed: int
    not_applicable: int
    score_percent: int
    scanned_at: datetime


@dataclass(frozen=True)
class ScaCheck:
    check_id: int
    title: str
    result: str  # passed | failed | not_applicable
    rationale: str
    remediation: str
    compliance: Mapping[str, tuple[str, ...]]


@dataclass(frozen=True)
class AlertPage:
    alerts: tuple[Mapping[str, Any], ...]
    search_after: tuple[Any, ...] | None


class WazuhManager(Protocol):
    def list_agents(self, scope: OrgScope) -> list[WazuhAgent]: ...
    def get_agent(self, scope: OrgScope, agent_id: str) -> WazuhAgent | None: ...
    def sca_policies(self, scope: OrgScope, agent_id: str) -> list[ScaPolicySummary]: ...
    def sca_checks(self, scope: OrgScope, agent_id: str, policy_id: str) -> list[ScaCheck]: ...
    def health(self) -> ConnectorHealth: ...


class WazuhIndexer(Protocol):
    def search_alerts(self, scope: OrgScope, *, since: datetime, until: datetime | None = None,
                      query: Mapping[str, Any] | None = None, size: int = 100,
                      search_after: tuple[Any, ...] | None = None) -> AlertPage: ...
    def vulnerability_counts(self, scope: OrgScope, agent_id: str) -> dict[str, int] | None:
        """Counts by severity from the vulnerability-state index; None when not available for the agent."""
        ...
    def health(self) -> ConnectorHealth: ...


def manager_endpoint(env: Mapping[str, str], app_env: str) -> Endpoint:
    return load_endpoint("WAZUH", env, app_env=app_env, credential_names=MANAGER_CREDENTIALS)


def indexer_endpoint(env: Mapping[str, str], app_env: str) -> Endpoint:
    return load_endpoint("WAZUH_INDEXER", env, app_env=app_env, credential_names=INDEXER_CREDENTIALS, default_timeout=30.0)


def agent_in_scope(agent: WazuhAgent, scope: OrgScope) -> bool:
    return bool(scope.wazuh_agent_groups.intersection(agent.groups))


def filter_agents(agents: list[WazuhAgent], scope: OrgScope, *, strict: bool = True) -> list[WazuhAgent]:
    """Re-check every agent against the scope. strict=True: an out-of-scope agent in an already-filtered
    result is a ScopeViolation (the upstream filter failed), never silently shown."""
    out = []
    for a in agents:
        if agent_in_scope(a, scope):
            out.append(a)
        elif strict:
            raise ScopeViolation(f"agent {a.agent_id} is outside the organization scope")
    return out


def indexer_scope_query(scope: OrgScope, *, since: datetime, until: datetime | None = None,
                        query: Mapping[str, Any] | None = None) -> dict[str, Any]:
    """The OpenSearch query actually sent. The organization filter is a `filter` clause the caller cannot
    replace; the caller's query (if any) is nested under `must`. An empty scope matches nothing."""
    if scope.empty:
        return {"bool": {"must_not": [{"match_all": {}}]}}
    org_filter: list[dict[str, Any]] = []
    if scope.wazuh_agent_groups:
        org_filter.append({"terms": {"agent.groups": sorted(scope.wazuh_agent_groups)}})
    if scope.wazuh_syslog_sources:
        # Syslog arrives on the manager itself (agent 000); its `location` names the sending source.
        org_filter.append({"bool": {"filter": [{"term": {"agent.id": "000"}},
                                               {"terms": {"location": sorted(scope.wazuh_syslog_sources)}}]}})
    time_range: dict[str, Any] = {"gte": since.isoformat()}
    if until is not None:
        time_range["lt"] = until.isoformat()
    return {"bool": {
        "filter": [{"bool": {"should": org_filter, "minimum_should_match": 1}}, {"range": {"timestamp": time_range}}],
        "must": [dict(query)] if query else [{"match_all": {}}],
    }}
