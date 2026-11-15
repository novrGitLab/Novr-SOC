"""Unified asset inventory (consolidation): ONE canonical identity per asset, reconciled from every source.

Sources report identifiers (Wazuh agent id, hostname, FQDN, IP, MAC, domain, URL, cloud id); reconciliation binds each
identifier to exactly one asset of the organization. Addresses are site-scoped. A conflicting identifier (already bound
to another asset) is never moved silently: it is recorded as an `identifier_conflict` event for an analyst to merge.
Wazuh vulnerability detection and VMS findings are shown side by side on an asset, never merged into one list: they
come from different detection methods with different evidence.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Any, Literal

from pydantic import Field

from .common import Contract, ShortText
from .endpoints import ConnectorState, ScaSummary, VulnerabilitySummary
from .nhai import NhaiJob

AssetKind = Literal["host", "domain", "web_application", "network_device", "cloud_resource"]
Classification = Literal["server", "workstation", "network", "domain", "web", "cloud", "iot", "unclassified"]
Criticality = Literal["low", "medium", "high", "critical"]
Exposure = Literal["internet_facing", "internal", "unknown"]
IdentifierKind = Literal["wazuh_agent", "hostname", "fqdn", "ip", "mac", "domain", "url", "cloud_id", "serial"]
SourceName = Literal["wazuh", "vms", "manual", "collector", "threat_intel", "soar", "cnii", "email", "brand"]
Tag = Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9_.-]{0,39}$")]


class AssetMonitoring(Contract):
    state: Literal["monitored", "partial", "unmonitored"] = Field(
        description="monitored: a Wazuh agent AND a VMS scan in 30 days; partial: one of them; unmonitored: neither")
    wazuh_agent_id: str | None = None
    last_vms_scan_at: datetime | None = None
    cnii_designated: bool = False


class AssetSummary(Contract):
    id: uuid.UUID
    kind: AssetKind
    display_name: str
    hostname: str | None = None
    fqdn: str | None = None
    primary_ip: str | None = None
    site_id: uuid.UUID | None = None
    site_name: str | None = None
    os_platform: str | None = None
    os_name: str | None = None
    os_version: str | None = None
    classification: Classification
    criticality: Criticality
    exposure: Exposure
    owner: str
    tags: list[str] = []
    status: Literal["active", "retired"]
    merged_into: uuid.UUID | None = None
    monitoring: AssetMonitoring
    sources: list[str] = []
    open_findings: int = Field(ge=0, default=0)
    critical_findings: int = Field(ge=0, default=0)
    open_alerts: int = Field(ge=0, default=0)
    first_seen_at: datetime
    last_seen_at: datetime


class AssetList(Contract):
    items: list[AssetSummary]
    total: int = Field(ge=0)
    limit: int
    offset: int
    by_kind: dict[str, int] = {}
    by_criticality: dict[str, int] = {}
    by_monitoring: dict[str, int] = {}


class AssetCreate(Contract):
    kind: AssetKind
    display_name: Annotated[str, Field(min_length=1, max_length=200)]
    hostname: Annotated[str, Field(max_length=253)] | None = None
    fqdn: Annotated[str, Field(max_length=253)] | None = None
    ip: Annotated[str, Field(max_length=45)] | None = None
    site_id: uuid.UUID | None = None
    classification: Classification = "unclassified"
    criticality: Criticality = "medium"
    exposure: Exposure = "unknown"
    owner: Annotated[str, Field(max_length=200)] = ""
    tags: Annotated[list[Tag], Field(max_length=20)] = []


class AssetUpdate(Contract):
    display_name: Annotated[str, Field(min_length=1, max_length=200)] | None = None
    site_id: uuid.UUID | None = None
    classification: Classification | None = None
    criticality: Criticality | None = None
    exposure: Exposure | None = None
    owner: Annotated[str, Field(max_length=200)] | None = None
    tags: Annotated[list[Tag], Field(max_length=20)] | None = None


class AssetMerge(Contract):
    """Merge `source_asset_id` INTO the asset in the path: identifiers, services, findings and alerts move; the source
    asset is retired with merged_into set. Audited; cannot be undone automatically."""
    source_asset_id: uuid.UUID
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class AssetRetire(Contract):
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class AssetIdentifierView(Contract):
    kind: IdentifierKind
    value: str
    site_key: str = ""
    sources: list[str]
    first_seen_at: datetime
    last_seen_at: datetime


class AssetServiceView(Contract):
    port: int
    protocol: str
    name: str
    product: str
    version: str
    source: str
    first_seen_at: datetime
    last_seen_at: datetime


class AssetEventView(Contract):
    id: int
    occurred_at: datetime
    kind: Literal["discovered", "identifier_added", "identifier_conflict", "updated", "service_seen", "merged", "retired",
                  "reclassified"]
    source: str
    actor_label: str
    details: dict[str, Any] = {}


class AssetFindingRef(Contract):
    id: uuid.UUID
    title: str
    severity: str
    status: str
    priority: str
    risk_score: int
    cves: list[str] = []
    port: int | None = None
    last_seen_at: datetime


class AssetAlertRef(Contract):
    id: uuid.UUID
    rule_id: str
    rule_description: str
    severity: str
    status: str
    observed_at: datetime
    case_id: uuid.UUID | None = None
    source: str


class AssetCaseRef(Contract):
    id: uuid.UUID
    reference: str
    title: str
    severity: str
    status: str
    created_at: datetime


class AssetSoarRef(Contract):
    run_id: uuid.UUID
    case_id: uuid.UUID
    playbook_name: str
    state: str
    mode: str
    created_at: datetime


class AssetIntelRef(Contract):
    match_id: uuid.UUID
    alert_id: uuid.UUID
    indicator_type: str
    indicator_value: str
    confidence: int
    verdict: str
    matched_at: datetime


class AssetTrendPoint(Contract):
    week_start: date
    alerts: int = Field(ge=0)
    new_findings: int = Field(ge=0)
    resolved_findings: int = Field(ge=0)


class WazuhAgentContext(Contract):
    """What the Wazuh connector reports for the asset's agent. `source` says where it came from (local fixture, live,
    unconfigured or unavailable). Wazuh vulnerability detection is a separate method from VMS scanning."""
    source: ConnectorState
    agent_id: str
    name: str | None = None
    status: str | None = None
    groups: list[str] = []
    agent_version: str | None = None
    last_keepalive_at: datetime | None = None
    vulnerabilities: VulnerabilitySummary | None = None
    sca: ScaSummary | None = None


class AssetDetail(Contract):
    asset: AssetSummary
    identifiers: list[AssetIdentifierView]
    services: list[AssetServiceView]
    wazuh: WazuhAgentContext | None = None
    detection_note: str = Field(description="How Wazuh vulnerability detection and VMS findings relate on this asset")
    findings: list[AssetFindingRef]
    alerts: list[AssetAlertRef]
    cases: list[AssetCaseRef]
    soar_runs: list[AssetSoarRef]
    intel: list[AssetIntelRef]
    events: list[AssetEventView]
    trend: list[AssetTrendPoint]
    nhai_jobs: list[NhaiJob] = []
    cnii: dict[str, Any] | None = None


class SyncRunView(Contract):
    id: uuid.UUID
    source: str
    source_state: str
    started_at: datetime
    finished_at: datetime | None = None
    outcome: Literal["completed", "source_unconfigured", "source_unavailable", "failed"]
    observed: int
    created: int
    updated: int
    conflicts: int
    detail: str
    requested_label: str


class SyncRunList(Contract):
    items: list[SyncRunView]


class ConflictView(Contract):
    event_id: int
    asset_id: uuid.UUID
    asset_name: str
    occurred_at: datetime
    identifier_kind: str
    identifier_value: str
    bound_to_asset_id: uuid.UUID | None = None
    bound_to_asset_name: str | None = None
    source: str


class ConflictList(Contract):
    items: list[ConflictView]


CollectorKind = Literal["wazuh_sync", "network_discovery", "cloud_inventory", "manual_import"]


class CollectorView(Contract):
    id: uuid.UUID
    name: str
    kind: CollectorKind
    site_id: uuid.UUID | None = None
    enabled: bool
    interval_minutes: int
    settings: dict[str, Any] = {}
    authorization_reference: str
    last_run_at: datetime | None = None
    last_outcome: str | None = None
    created_at: datetime
    execution: str = Field(description="What actually runs for this collector in this installation")


class CollectorCreate(Contract):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    kind: CollectorKind
    site_id: uuid.UUID | None = None
    interval_minutes: Annotated[int, Field(ge=15, le=10080)] = 1440
    settings: dict[Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")], str | int | bool | list[ShortText]] = {}
    authorization_reference: Annotated[str, Field(max_length=200)] = ""


class CollectorUpdate(Contract):
    enabled: bool | None = None
    interval_minutes: Annotated[int, Field(ge=15, le=10080)] | None = None
    settings: dict[Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")], str | int | bool | list[ShortText]] | None = None
    authorization_reference: Annotated[str, Field(max_length=200)] | None = None


class CollectorList(Contract):
    items: list[CollectorView]
