"""SOC contracts v1: stored alerts, ingest and cases (Phase 4 foundation; ongoing owner: workstream A).

Case creation from alerts reuses `soar.AlertToCasePromotion` / `soar.CasePromotionResult` (no duplicate
models). The ingest batch is MACHINE-INBOUND from the forwarder identity and carries no organisation: the API
derives each alert's organisation from its Wazuh agent groups, and quarantines anything it cannot attribute.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field

from .common import Contract, IdempotencyKey, MachineInbound, Severity

AlertStatus = Literal["new", "acknowledged", "in_progress", "closed"]
CaseStatus = Literal["open", "in_progress", "resolved", "closed"]


# ---------------------------------------------------------------- ingest (forwarder -> API)
class WazuhRule(Contract):
    id: Annotated[str, Field(max_length=20)]
    level: Annotated[int, Field(ge=0, le=16)]
    description: Annotated[str, Field(max_length=1000)] = ""
    mitre_ids: Annotated[list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]], Field(max_length=20)] = []


class WazuhAgentRef(Contract):
    id: Annotated[str, Field(pattern=r"^\d{3,6}$")]
    name: Annotated[str, Field(max_length=200)] = ""
    groups: Annotated[list[Annotated[str, Field(pattern=r"^[A-Za-z0-9_.-]{1,128}$")]], Field(max_length=50)] = []


class WazuhAlertIn(Contract):
    id: Annotated[str, Field(min_length=1, max_length=200, description="Wazuh alert id; dedupe key per organization")]
    timestamp: datetime
    rule: WazuhRule
    agent: WazuhAgentRef
    src_ip: str | None = None
    raw: dict[str, Any] = Field(default={}, description="Original alert; stored capped at 32 KB")


class AlertIngestBatch(MachineInbound):
    batch_id: IdempotencyKey
    alerts: Annotated[list[WazuhAlertIn], Field(min_length=1, max_length=100)]


class AlertIngestResult(Contract):
    batch_id: str
    accepted: int = Field(ge=0)
    duplicates: int = Field(ge=0)
    quarantined: int = Field(ge=0)
    durable: Literal[True] = True
    replayed: bool = Field(default=False, description="Phase 5: True when this batch_id was already acknowledged; "
                           "the stored acknowledgement is returned and nothing is ingested again")


# ---------------------------------------------------------------- stored alerts
class StoredAlert(Contract):
    id: uuid.UUID
    source: Literal["wazuh", "local_fixture"]
    external_id: str
    rule_id: str
    rule_level: int
    rule_description: str
    severity: Severity
    agent_id: str
    agent_name: str
    src_ip: str | None
    mitre_techniques: list[str]
    observed_at: datetime
    received_at: datetime
    status: AlertStatus
    case_id: uuid.UUID | None = Field(default=None, description="The case this alert is linked to, if any (the most recently linked one when several)")
    asset_id: uuid.UUID | None = Field(default=None, description="Consolidation: the canonical asset of the alert's agent")
    assignee_id: uuid.UUID | None = None
    assignee_label: str | None = None


class AlertDetail(StoredAlert):
    agent_groups: list[str]
    status_reason: str
    raw: dict[str, Any]


class AlertList(Contract):
    items: list[StoredAlert]
    total: int = Field(ge=0)
    limit: int
    offset: int


class AlertStatusUpdate(Contract):
    status: AlertStatus
    reason: Annotated[str, Field(max_length=500)] = ""


# ---------------------------------------------------------------- cases
class CaseSummary(Contract):
    id: uuid.UUID
    reference: str = Field(description="Human reference, e.g. CASE-000042")
    title: str
    severity: Severity
    status: CaseStatus
    source: str
    alert_count: int = Field(ge=0)
    created_at: datetime
    updated_at: datetime
    assignee_id: uuid.UUID | None = None
    assignee_label: str | None = None
    sla_response_due_at: datetime | None = Field(default=None, description="Consolidation: from the SLA policy when the case was created")
    sla_resolution_due_at: datetime | None = None
    first_response_at: datetime | None = None
    resolved_at: datetime | None = None
    sla_state: Literal["met", "on_track", "at_risk", "breached", "no_policy"] = "no_policy"


class CaseEvent(Contract):
    id: int
    occurred_at: datetime
    kind: Literal["created", "note", "status_changed", "alert_linked", "assigned", "remediation", "evidence", "sla_escalated",
                  "closure", "severity_changed"]
    actor_label: str
    body: str


class CaseDetail(CaseSummary):
    alerts: list[StoredAlert]
    timeline: list[CaseEvent]
    closed_at: datetime | None = None


class CaseList(Contract):
    items: list[CaseSummary]
    total: int = Field(ge=0)
    limit: int
    offset: int


class CaseNoteCreate(Contract):
    body: Annotated[str, Field(min_length=1, max_length=8000)]
    kind: Literal["note", "remediation", "evidence"] = Field(default="note", description="Consolidation: remediation and "
                                                                                       "evidence notes are typed timeline entries")


class AssignmentRequest(Contract):
    """Assign (or, with null, unassign) an alert or a case. The assignee must be a member of the organization."""
    assignee_id: uuid.UUID | None = None
    note: Annotated[str, Field(max_length=1000)] = ""


class CaseStatusUpdate(Contract):
    status: CaseStatus
    note: Annotated[str, Field(max_length=2000)] = ""


# ---------------------------------------------------------------- alert evidence (Phase 5, additive)
class AlertEvidence(Contract):
    """The original alert document for one stored alert, as read from its source by the API (never by the browser).
    `source.state` says where it came from: `connected` (read live from the Wazuh indexer just now), `local_fixture`
    (the stored fixture copy, labelled), or an unavailable state with `document` null. Secrets are redacted."""
    alert_id: uuid.UUID
    external_id: str
    source: "ConnectorState"
    document: dict[str, Any] | None = None
    redacted: bool = True
    retrieved_at: datetime


from .endpoints import ConnectorState  # noqa: E402

AlertEvidence.model_rebuild()
