"""Endpoint-management contracts v1 (Phase 4; ongoing owner: workstream C).

Every response that carries data from Wazuh also carries the honest state of that source (`ConnectorState`).
`local_fixture` data is explicitly labelled local test data and is never presented as live telemetry; an
unconfigured connector returns no endpoints and says so.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Literal

from pydantic import Field

from .common import Contract

GroupName = Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]
SourceState = Literal["unconfigured", "local_fixture", "connected", "unavailable", "error"]


class ConnectorState(Contract):
    """State of one internal connector, as established by the API. Never claims a connection it has not made."""
    connector: Literal["wazuh_manager", "wazuh_indexer", "ollama"]
    state: SourceState
    detail: Annotated[str, Field(max_length=300)] = ""
    checked_at: datetime | None = Field(default=None, description="When reachability was last checked; null = never")


class EndpointOs(Contract):
    platform: str | None = None
    name: str | None = None
    version: str | None = None
    support: Literal["supported", "unsupported", "unknown"] = "unknown"


class EndpointSummary(Contract):
    agent_id: Annotated[str, Field(pattern=r"^\d{3,6}$")]
    name: str
    status: Literal["active", "disconnected", "never_connected", "pending"]
    groups: list[str]
    os: EndpointOs
    agent_version: str | None = None
    ip: str | None = None
    last_keepalive_at: datetime | None = None


class EndpointInventory(Contract):
    source: ConnectorState
    items: list[EndpointSummary]
    by_status: dict[str, int] = {}
    mapped_groups: int = Field(ge=0, description="Wazuh agent groups mapped to this organization")


class VulnerabilitySummary(Contract):
    source: ConnectorState
    critical: int | None = None
    high: int | None = None
    medium: int | None = None
    low: int | None = None
    total: int | None = Field(default=None, description="null when the source is unavailable; never a guessed 0")


class ScaPolicySummaryView(Contract):
    policy_id: str
    name: str
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    score_percent: Annotated[int, Field(ge=0, le=100)]
    scanned_at: datetime


class ScaSummary(Contract):
    source: ConnectorState
    policies: list[ScaPolicySummaryView] = []


class EndpointDetail(Contract):
    endpoint: EndpointSummary
    source: ConnectorState
    vulnerabilities: VulnerabilitySummary
    sca: ScaSummary


class GroupMappingCreate(Contract):
    group_name: GroupName
    acknowledge_broad_group: bool = Field(default=False, description="Required for a broad group (Wazuh's `default`): every "
                                          "agent belongs to it until it is reassigned, so mapping it attributes every agent "
                                          "that is in no other mapped group to this organization")


class GroupMapping(Contract):
    id: uuid.UUID
    group_name: str
    created_at: datetime
    broad: bool = Field(default=False, description="A broad group (Wazuh's `default`): shown with a warning")
    collection: bool = Field(default=False, description="A collection group (NOVRSOC_WAZUH_COLLECTION_GROUPS): this mapping is "
                                                        "IGNORED for attribution; it never makes the organization an agent's owner")


class GroupMappingList(Contract):
    items: list[GroupMapping]
