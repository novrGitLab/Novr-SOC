"""Clients and administration (consolidation): billing plans and subscriptions, authorized data exports, teams and
memberships, platform analytics, platform health, Wazuh quarantine summary.

Billing: no payment provider is configured. Plans and subscriptions are administrative records; NovrSOC never
claims that a payment was taken, and `payment_provider` is always reported as it is.
Exports: one organization's records, for a named recipient, with a justification, a checksum and an expiry. Every
creation and every download is audited.
Platform health reports measured states only: a component whose state cannot be established is `unknown`.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .common import ActorRef, Contract, Slug


class BillingPlanCreate(Contract):
    code: Annotated[str, Field(pattern=r"^[a-z0-9][a-z0-9-]{1,39}$")]
    name: Annotated[str, Field(min_length=2, max_length=120)]
    description: Annotated[str, Field(max_length=2000)] = ""
    price_minor: Annotated[int, Field(ge=0, le=10**12)] = Field(description="Price in the currency's minor unit (kobo, cents)")
    currency: Annotated[str, Field(pattern=r"^[A-Z]{3}$")] = "NGN"
    billing_interval: Literal["monthly", "annual"] = "monthly"
    max_assets: Annotated[int, Field(ge=1)] | None = None
    max_users: Annotated[int, Field(ge=1)] | None = None
    features: Annotated[list[Annotated[str, Field(max_length=80)]], Field(max_length=40)] = []


class BillingPlanView(BillingPlanCreate):
    id: uuid.UUID
    active: bool
    created_at: datetime


class BillingPlanUpdate(Contract):
    active: bool


class SubscriptionSet(Contract):
    org_id: uuid.UUID
    plan_id: uuid.UUID
    status: Literal["trial", "active", "past_due", "cancelled"]
    renews_at: datetime | None = None
    notes: Annotated[str, Field(max_length=2000)] = ""


class OrgBillingRow(Contract):
    org_id: uuid.UUID
    org_name: str
    plan_code: str | None = None
    plan_name: str | None = None
    status: str | None = None
    renews_at: datetime | None = None
    assets: int = Field(ge=0)
    users: int = Field(ge=0)
    max_assets: int | None = None
    max_users: int | None = None
    over_limit: list[str] = []


class BillingOverview(Contract):
    payment_provider: Literal["not_configured"] = "not_configured"
    note: str
    plans: list[BillingPlanView]
    organizations: list[OrgBillingRow]


DatasetName = Literal["alerts", "cases", "vms_findings", "assets", "audit_events", "ti_indicators"]


class DataExportCreate(Contract):
    dataset: DatasetName
    format: Literal["csv", "json"] = "csv"
    period_start: datetime
    period_end: datetime
    justification: Annotated[str, Field(min_length=10, max_length=1000)]
    recipient: Annotated[str, Field(min_length=2, max_length=200, description="Who receives the export (organization or role)")]
    expires_in_days: Annotated[int, Field(ge=1, le=30)] = 7

    @model_validator(mode="after")
    def _period(self):
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        if (self.period_end - self.period_start).days > 366:
            raise ValueError("an export covers at most one year")
        return self


class DataExportView(Contract):
    id: uuid.UUID
    dataset: DatasetName
    format: Literal["csv", "json"]
    period_start: datetime
    period_end: datetime
    justification: str
    recipient: str
    row_count: int
    truncated: bool
    sha256: str
    requested_by: ActorRef
    created_at: datetime
    expires_at: datetime
    downloads: int
    state: Literal["available", "expired", "revoked"]


class DataExportList(Contract):
    items: list[DataExportView]
    max_rows: int


class TeamCreate(Contract):
    name: Annotated[str, Field(min_length=2, max_length=120)]
    description: Annotated[str, Field(max_length=1000)] = ""


class TeamMemberView(Contract):
    user_id: uuid.UUID
    email: str
    role: str
    team_role: Literal["lead", "member"]


class TeamView(Contract):
    id: uuid.UUID
    name: str
    description: str
    members: list[TeamMemberView]
    created_at: datetime


class TeamList(Contract):
    items: list[TeamView]


class TeamMemberAdd(Contract):
    user_id: uuid.UUID
    team_role: Literal["lead", "member"] = "member"


class MembershipGrant(Contract):
    """Give an existing user of the active organization access to another organization (assignment)."""
    org_id: uuid.UUID
    access_scope: Literal["operations", "reporting"]


class MembershipView(Contract):
    org_id: uuid.UUID
    org_name: str
    role: str
    access_scope: str


class MembershipList(Contract):
    user_id: uuid.UUID
    items: list[MembershipView]


class OnboardingStatus(Contract):
    org_id: uuid.UUID
    org_slug: Slug
    steps: dict[str, bool]
    next_step: str | None = None
    optional_steps: list[str] = Field(default=[], description="Steps that do not count towards completion (not every "
                                      "organization has syslog or agentless sources)")
    completed: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


# ---------------------------------------------------------------- organization management (platform administrators)
OrgStatus = Literal["active", "suspended", "archived"]
IntegrationHealth = Literal["ok", "attention", "not_configured", "inactive"]


class OrgUpdate(Contract):
    """Profile fields; a field left out (null) is unchanged. The slug never changes (it identifies the organization)."""
    name: Annotated[str, Field(min_length=1, max_length=200)] | None = None
    contact_name: Annotated[str, Field(max_length=200)] | None = None
    contact_email: Annotated[str, Field(max_length=254, pattern=r"^$|^[^@\s]+@[^@\s]+$")] | None = None
    timezone: Annotated[str, Field(max_length=64, pattern=r"^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$")] | None = None
    notes: Annotated[str, Field(max_length=4000)] | None = None


class OrgStatusChange(Contract):
    """suspended: members cannot sign in or switch to it; telemetry keeps arriving. archived: kept for the record; it
    must hold no Wazuh group mapping and no live log source first, so no event can reach it."""
    status: OrgStatus
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class OrgIntegrations(Contract):
    wazuh_groups: int = Field(ge=0)
    wazuh_agents: int = Field(ge=0, description="Wazuh agents reconciled into the organization's asset inventory")
    log_sources: int = Field(ge=0)
    log_sources_receiving: int = Field(ge=0, description="Enabled sources with an event in the last hour")
    log_sources_never: int = Field(ge=0, description="Enabled sources that have not sent any event yet")
    log_sources_disabled: int = Field(ge=0)
    service_identities: int = Field(ge=0)
    last_alert_at: datetime | None = None
    health: IntegrationHealth
    notes: list[str] = Field(default=[], description="Why the health is what it is, one line per finding")


class OrgDirectoryRow(Contract):
    id: uuid.UUID
    slug: str
    name: str
    kind: Literal["platform", "client"]
    status: OrgStatus
    status_reason: str = ""
    contact_name: str = ""
    contact_email: str = ""
    timezone: str = "UTC"
    created_at: datetime
    updated_at: datetime | None = None
    users: int = Field(ge=0)
    assets: int = Field(ge=0)
    sites: int = Field(ge=0)
    alerts_7d: int = Field(ge=0)
    open_cases: int = Field(ge=0)
    onboarding_completed: int = Field(ge=0)
    onboarding_total: int = Field(ge=0)
    next_step: str | None = None
    integrations: OrgIntegrations


class OrgDirectory(Contract):
    generated_at: datetime
    items: list[OrgDirectoryRow]
    total: int = Field(ge=0)


class OrgDetail(OrgDirectoryRow):
    notes: str = ""
    archived_at: datetime | None = None
    onboarding: OnboardingStatus


class UserSearchResult(Contract):
    id: uuid.UUID
    email: str
    display_name: str
    status: Literal["active", "disabled"]
    home_org_id: uuid.UUID | None = None
    home_org_name: str | None = None
    role: str | None = None
    memberships: list[MembershipView] = []


class UserSearchList(Contract):
    items: list[UserSearchResult]


class OrgAnalyticsRow(Contract):
    org_id: uuid.UUID
    org_name: str
    kind: str
    status: str
    users: int
    assets: int
    alerts_7d: int
    open_alerts: int
    open_cases: int
    open_findings: int
    critical_findings: int
    last_alert_at: datetime | None = None
    plan_code: str | None = None
    subscription_status: str | None = None


class PlatformAnalytics(Contract):
    generated_at: datetime
    organizations: list[OrgAnalyticsRow]
    totals: dict[str, int]


class ComponentHealth(Contract):
    key: str
    label: str
    state: Literal["ok", "degraded", "failing", "unconfigured", "unknown"]
    detail: str
    checked_at: datetime | None = None


class PlatformHealth(Contract):
    generated_at: datetime
    components: list[ComponentHealth]
    queues: dict[str, Any]
    workers: list[dict[str, Any]]
    failures_24h: list[dict[str, Any]]


class QuarantinedSource(Contract):
    """Events of the Wazuh manager (agent 000) that no live registration could attribute."""
    kind: Literal["syslog", "agentless", "manager_local"]
    value: str = Field(description="The sender IP (syslog), the agentless host, or the manager's local log location")
    reason: str
    events: int = Field(ge=0)
    last_seen_at: datetime


class QuarantineSummary(Contract):
    last_24h: int = Field(ge=0)
    by_reason: dict[str, int]
    unmapped_groups: list[str]
    unattributed_sources: list[QuarantinedSource] = []
