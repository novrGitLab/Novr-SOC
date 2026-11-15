"""Security operations (consolidation): SLA policies and tracking, shift handovers, notifications.

SLA due times are fixed when a case is created, from the organization's active policy for the case severity (the
targets that applied are kept with the case). States: on_track, at_risk (inside the escalation window), breached,
met (responded/resolved in time), no_policy (no target applied: never shown as compliant).
A shift handover freezes the queue as it was when it was written; another person acknowledges it.
"""
from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import ActorRef, Contract

CaseSeverity = Literal["critical", "high", "medium", "low"]
SlaState = Literal["met", "on_track", "at_risk", "breached", "no_policy"]


class SlaPolicyInput(Contract):
    severity: CaseSeverity
    response_minutes: Annotated[int, Field(ge=1, le=43200)]
    resolution_minutes: Annotated[int, Field(ge=1, le=525600)]
    escalate_before_minutes: Annotated[int, Field(ge=0, le=10080)] = 0
    escalate_to_role: Literal["soc_manager", "super_admin"] = "soc_manager"

    @model_validator(mode="after")
    def _order(self):
        if self.resolution_minutes < self.response_minutes:
            raise ValueError("the resolution target cannot be shorter than the response target")
        return self


class SlaPolicySet(Contract):
    policies: Annotated[list[SlaPolicyInput], Field(min_length=1, max_length=4)]

    @model_validator(mode="after")
    def _unique(self):
        sev = [p.severity for p in self.policies]
        if len(sev) != len(set(sev)):
            raise ValueError("one policy per severity")
        return self


class SlaPolicyView(SlaPolicyInput):
    updated_at: datetime


class SlaPolicyList(Contract):
    items: list[SlaPolicyView]


class CaseSlaView(Contract):
    case_id: uuid.UUID
    reference: str
    title: str
    severity: CaseSeverity
    status: str
    assignee_label: str | None = None
    created_at: datetime
    response_due_at: datetime | None = None
    resolution_due_at: datetime | None = None
    first_response_at: datetime | None = None
    resolved_at: datetime | None = None
    response_state: SlaState
    resolution_state: SlaState
    escalated_at: datetime | None = None


class SlaStatus(Contract):
    generated_at: datetime
    policies_configured: int = Field(ge=0, le=4)
    items: list[CaseSlaView]
    counts: dict[str, int] = {}


class SlaPerformanceRow(Contract):
    severity: CaseSeverity
    cases: int = Field(ge=0)
    response_met: int = Field(ge=0)
    response_breached: int = Field(ge=0)
    resolution_met: int = Field(ge=0)
    resolution_breached: int = Field(ge=0)
    without_policy: int = Field(ge=0)
    median_response_minutes: int | None = None
    median_resolution_minutes: int | None = None


class SlaWeek(Contract):
    week_start: date
    met: int = Field(ge=0)
    breached: int = Field(ge=0)


class SlaPerformance(Contract):
    days: int
    rows: list[SlaPerformanceRow]
    weekly: list[SlaWeek]
    note: str = ""


class EscalationResult(Contract):
    checked: int = Field(ge=0)
    escalated: int = Field(ge=0)
    notified: int = Field(ge=0)


# ---------------------------------------------------------------- shift handover
class UserRef(Contract):
    id: uuid.UUID
    email: str
    role: str


class HandoverAlert(Contract):
    id: uuid.UUID
    rule_description: str
    severity: str
    status: str
    observed_at: datetime
    assignee_label: str | None = None


class HandoverCase(Contract):
    id: uuid.UUID
    reference: str
    title: str
    severity: str
    status: str
    assignee_label: str | None = None


class HandoverApproval(Contract):
    id: uuid.UUID
    action: str
    target: str
    requested_by: str
    expires_at: datetime


class HandoverSnapshot(Contract):
    taken_at: datetime
    unresolved_alerts: int = Field(ge=0)
    unassigned_critical_alerts: int = Field(ge=0)
    top_alerts: list[HandoverAlert] = []
    open_cases: int = Field(ge=0)
    cases: list[HandoverCase] = []
    pending_approvals: list[HandoverApproval] = []
    sla_at_risk: list[CaseSlaView] = []
    sla_breached: int = Field(ge=0, default=0)
    my_assignments: int = Field(ge=0, default=0)


class HandoverDraft(Contract):
    snapshot: HandoverSnapshot
    recipients: list[UserRef]


class HandoverCreate(Contract):
    shift_start: datetime
    shift_end: datetime
    summary: Annotated[str, Field(min_length=10, max_length=8000)]
    watch_items: Annotated[list[Annotated[str, Field(min_length=2, max_length=300)]], Field(max_length=30)] = []
    incoming_user_id: uuid.UUID | None = None

    @model_validator(mode="after")
    def _window(self):
        if self.shift_end <= self.shift_start:
            raise ValueError("shift_end must be after shift_start")
        if (self.shift_end - self.shift_start).total_seconds() > 24 * 3600:
            raise ValueError("a shift is at most 24 hours")
        return self


class HandoverView(Contract):
    id: uuid.UUID
    author: ActorRef
    shift_start: datetime
    shift_end: datetime
    summary: str
    watch_items: list[str]
    snapshot: HandoverSnapshot
    incoming_user_id: uuid.UUID | None = None
    incoming_label: str | None = None
    status: Literal["submitted", "acknowledged"]
    acknowledged_by: ActorRef | None = None
    acknowledged_at: datetime | None = None
    acknowledgement_note: str = ""
    created_at: datetime


class HandoverList(Contract):
    items: list[HandoverView]


class HandoverAcknowledge(Contract):
    note: Annotated[str, Field(max_length=2000)] = ""


# ---------------------------------------------------------------- notifications
class NotificationView(Contract):
    id: uuid.UUID
    kind: str
    title: str
    body: str
    link: str
    created_at: datetime
    read_at: datetime | None = None


class NotificationList(Contract):
    items: list[NotificationView]
    unread: int = Field(ge=0)
