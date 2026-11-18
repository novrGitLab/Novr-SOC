"""NovrSOC Command Center contracts v1 (additive): platform-wide views across organizations.

Nothing here is a copy of tenant data. The API reads each organization's own records inside that organization's
row-level-security context, one organization at a time, and labels every record with its owner. Who may look:
  * a platform administrator (platform:monitor): every organization;
  * platform SOC staff (soc_manager, analyst whose home is the platform organization): their home organization and the
    organizations they are assigned to operate - exactly the ones they could switch into;
  * nobody else. Each view also needs that view's own permission (alerts:read, vms:read, ...). Every view and export is
    audited.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Literal

from pydantic import Field

from .common import Contract

CommandView = Literal["assets", "alerts", "vulnerabilities", "scans", "cases", "intel", "nhai", "soar_runs", "soar_approvals", "reports"]


class CommandOrg(Contract):
    id: uuid.UUID
    slug: str
    name: str
    kind: Literal["platform", "client"]
    status: Literal["active", "suspended", "archived"]


class CommandScope(Contract):
    scope: Literal["platform", "assigned"] = Field(description="platform: every organization; assigned: home + operations assignments")
    organizations: list[CommandOrg]
    views: list[CommandView] = Field(description="The views this person's permissions allow")
    can_export: bool


class OrgPosture(Contract):
    """One organization's security posture, computed from its own records at request time."""
    org: CommandOrg
    posture: Literal["critical", "elevated", "normal", "no_data"]
    posture_reasons: list[str] = []
    assets: int = 0
    open_alerts: int = 0
    alerts_24h: int = 0
    critical_alerts_24h: int = 0
    high_alerts_24h: int = 0
    last_alert_at: datetime | None = None
    open_cases: int = 0
    critical_cases: int = 0
    open_findings: int = 0
    critical_findings: int = 0
    overdue_remediation: int = 0
    scans_running: int = 0
    scans_failed_7d: int = 0
    scan_policy_enabled: bool = False
    intel_matches_7d: int = 0
    nhai_queued: int = 0
    nhai_failed_24h: int = 0
    nhai_awaiting_review: int = 0
    soar_pending_approvals: int = 0
    soar_runs_7d: int = 0
    reports_7d: int = 0


class CommandOverview(Contract):
    generated_at: datetime
    scope: Literal["platform", "assigned"]
    organizations: list[OrgPosture]
    totals: dict[str, int]


class CommandRecord(Contract):
    """One tenant-owned record, labelled with its owner. `fields` holds the view's columns (documented per view)."""
    org: CommandOrg
    id: str
    at: datetime | None = None
    title: str
    severity: str | None = None
    status: str | None = None
    fields: dict[str, Any] = {}


class CommandList(Contract):
    view: CommandView
    generated_at: datetime
    items: list[CommandRecord]
    per_organization: dict[str, int] = Field(description="Records returned per organization slug (before the overall limit)")
    truncated: bool = Field(description="True when an organization had more matching records than were read")
