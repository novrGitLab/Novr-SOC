"""CNII access designation, Reporting and Backup/restore contracts v1 (contract only).

CNII: a designation is an explicit, time-bound grant to ONE user for named sectors (optionally limited to
named organisations). Access requires the cnii:* permission AND an active designation. The designation
check is implemented in Phase 2 (apps/api/app/authz/cnii.py); CNII data endpoints are not.

Reporting (workstream E): report definitions, generated artifacts and schedules, always for one organisation.

Backup/restore (workstream E): platform database backups to EXTERNAL storage and restore drills into a
disposable instance. Restores never target the live database through this contract.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import Contract, IdempotencyKey, Internal, MachineInbound, ShortText

CniiSector = Literal["power", "water", "ict", "finance", "health", "publicadmin", "education", "defence",
                     "transport", "food", "safety", "industrial", "mines"]


# ---------------------------------------------------------------- CNII
class CniiDesignationGrant(Contract):
    """Granted by a super_admin (platform). Audited. Always expires."""
    user_id: uuid.UUID
    sectors: Annotated[list[CniiSector], Field(min_length=1)]
    scope_org_ids: list[uuid.UUID] | None = Field(default=None, description="None = every organisation in those sectors")
    reason: Annotated[str, Field(min_length=3, max_length=500)]
    expires_at: datetime


class CniiDesignation(Contract):
    id: uuid.UUID
    user_id: uuid.UUID
    sectors: list[CniiSector]
    scope_org_ids: list[uuid.UUID] | None
    granted_by: uuid.UUID
    granted_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None

    @model_validator(mode="after")
    def _expiry(self):
        if self.expires_at <= self.granted_at:
            raise ValueError("expires_at must be after granted_at")
        return self


class CniiDesignationRevoke(Contract):
    designation_id: uuid.UUID
    reason: Annotated[str, Field(min_length=3, max_length=500)]


# ---------------------------------------------------------------- Reporting
class ReportType(str, Enum):
    VMS_EXECUTIVE = "vms_executive"
    VMS_TECHNICAL = "vms_technical"
    SOC_MONTHLY = "soc_monthly"
    COMPLIANCE_SCA = "compliance_sca"
    EMAIL_SECURITY = "email_security"
    CNII_SECTOR = "cnii_sector"  # needs a CNII designation in addition to the permission
    ORGANIZATION_SUMMARY = "organization_summary"  # Phase 4: sites, endpoints, alerts and cases of one organization
    EXECUTIVE = "executive"                  # consolidation: posture, incidents, vulnerabilities, SLA, priorities
    SECOPS = "secops"                        # consolidation: alerts, cases, SOAR runs and approvals
    THREAT_INTEL = "threat_intel"            # consolidation: indicators, matches, actors, CVE intelligence
    BRAND_PROTECTION = "brand_protection"    # consolidation: watch subjects, findings, monitoring runs
    SLA = "sla"                              # consolidation: SLA performance
    AUDIT = "audit"                          # consolidation: audit events by action and outcome


class ReportRequest(Contract):
    idempotency_key: IdempotencyKey
    type: ReportType
    period_start: datetime
    period_end: datetime
    format: Literal["pdf", "csv", "json"] = "pdf"

    @model_validator(mode="after")
    def _period(self):
        if self.period_end <= self.period_start:
            raise ValueError("period_end must be after period_start")
        return self


class ReportArtifact(Contract):
    id: uuid.UUID
    type: ReportType
    status: Literal["queued", "generating", "ready", "failed"]
    period_start: datetime
    period_end: datetime
    format: Literal["pdf", "csv", "json"]
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    created_at: datetime
    data_states: dict[str, Literal["ok", "empty", "integration_unconfigured", "error", "local_fixture", "not_permitted"]] = Field(
        default={}, description="Honest state of each section's data source, shown in the report")


class ReportSchedule(Contract):
    id: uuid.UUID
    type: ReportType
    cron: Annotated[str, Field(pattern=r"^[0-9*/,\- ]{9,64}$")]
    timezone: Annotated[str, Field(max_length=64)] = "Africa/Lagos"
    recipient_user_ids: Annotated[list[uuid.UUID], Field(min_length=1, max_length=50)]
    active: bool = True


# ---------------------------------------------------------------- Backup / restore
class BackupKind(str, Enum):
    LOGICAL_DUMP = "logical_dump"
    WAL_ARCHIVE = "wal_archive"


class BackupJob(Internal):
    id: uuid.UUID
    kind: BackupKind
    started_at: datetime
    finished_at: datetime | None = None
    status: Literal["running", "succeeded", "failed"]
    target: Annotated[str, Field(max_length=200, description="External object-storage location label, never on Server 2")]
    size_bytes: int | None = Field(default=None, ge=0)
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None
    encrypted: Literal[True] = True


class RestoreDrillRequest(Contract):
    idempotency_key: IdempotencyKey
    backup_job_id: uuid.UUID
    target: Literal["disposable_instance"] = Field(default="disposable_instance",
                                                   description="The only allowed target; restoring over live data is out of contract")


class RestoreDrillResult(Internal):
    id: uuid.UUID
    backup_job_id: uuid.UUID
    status: Literal["succeeded", "failed"]
    restored_tables: int = Field(ge=0)
    row_count_checks_passed: bool
    duration_seconds: int = Field(ge=0)
    finished_at: datetime


class BackupAgentReport(MachineInbound):
    """Backup agent -> API, authenticated by its service identity (replaces the unauthenticated legacy route)."""
    report_id: IdempotencyKey
    job: BackupJob
    note: ShortText = ""


class ReportList(Contract):
    """Phase 4: the organization's report history (newest first)."""
    items: list[ReportArtifact]


class ReportSection(Contract):
    key: Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")]
    title: ShortText
    state: Literal["ok", "empty", "integration_unconfigured", "error", "local_fixture", "not_permitted"]
    note: ShortText = ""
    data: dict = Field(default={}, description="Section figures; empty whenever state is not ok/local_fixture")


class ReportDetail(ReportArtifact):
    """Phase 4: a generated report with its sections. Unavailable sources are listed as such, never as zero."""
    sections: list[ReportSection] = []
    failure_reason: ShortText = ""


# ---------------------------------------------------------------- Phase 6 pilot (additive): CNII Watch views
class CniiDesignationList(Contract):
    items: list[CniiDesignation]


class CniiOrgProfileSet(Contract):
    org_id: uuid.UUID
    sectors: Annotated[list[CniiSector], Field(min_length=1)]
    criticality: Literal["vital", "high", "moderate"]


class CniiOrgProfile(CniiOrgProfileSet):
    org_name: str
    updated_at: datetime


class CniiOrgProfileList(Contract):
    items: list[CniiOrgProfile]


class CniiSectorRow(Contract):
    org_id: uuid.UUID
    org_name: str
    criticality: Literal["vital", "high", "moderate"]
    open_alerts: int
    critical_alerts_7d: int
    open_cases: int


class CniiSectorOverview(Contract):
    sector: CniiSector
    designation_id: uuid.UUID
    designation_expires_at: datetime
    items: list[CniiSectorRow]


# ---------------------------------------------------------------- consolidation (additive): CNII monitoring scope
class CniiAuthorizationCreate(Contract):
    """The record that authorizes monitoring of designated CNII assets. Without an active one, nothing is monitored."""
    reference: Annotated[str, Field(min_length=3, max_length=200)]
    issuing_authority: Annotated[str, Field(min_length=2, max_length=200)]
    scope_description: Annotated[str, Field(min_length=3, max_length=4000)]
    sectors: Annotated[list[CniiSector], Field(min_length=1)]
    valid_from: datetime
    valid_until: datetime
    document_sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")] | None = None

    @model_validator(mode="after")
    def _validity(self):
        if self.valid_until <= self.valid_from:
            raise ValueError("valid_until must be after valid_from")
        if (self.valid_until - self.valid_from).days > 3 * 366:
            raise ValueError("an authorization is valid for at most three years")
        return self


class CniiAuthorizationView(CniiAuthorizationCreate):
    id: uuid.UUID
    state: Literal["active", "not_yet_valid", "expired", "revoked"]
    recorded_by: str
    revoked_at: datetime | None = None
    revoked_reason: str | None = None
    monitored_assets: int = 0
    created_at: datetime


class CniiAuthorizationList(Contract):
    items: list[CniiAuthorizationView]


class CniiAuthorizationRevoke(Contract):
    reason: Annotated[str, Field(min_length=5, max_length=500)]


class CniiMonitoredAssetCreate(Contract):
    asset_id: uuid.UUID
    authorization_id: uuid.UUID
    sector: CniiSector
    owning_unit: Annotated[str, Field(min_length=2, max_length=200)]
    monitoring: Literal["availability", "vulnerability", "both"] = "both"


class CniiCheckView(Contract):
    id: uuid.UUID
    kind: Literal["availability", "vulnerability_scan"]
    observed_at: datetime
    outcome: Literal["up", "down", "degraded", "not_run"]
    latency_ms: int | None = None
    detail: str
    source: str


class CniiScheduleView(Contract):
    id: uuid.UUID
    check_kind: Literal["availability", "vulnerability_scan"]
    interval_minutes: int
    enabled: bool
    next_due_at: datetime | None = None
    last_run_at: datetime | None = None
    execution: str


class CniiScheduleSet(Contract):
    check_kind: Literal["availability", "vulnerability_scan"]
    interval_minutes: Annotated[int, Field(ge=5, le=43200)]
    enabled: bool = False


class CniiMonitoredAssetView(Contract):
    id: uuid.UUID
    asset_id: uuid.UUID
    asset_name: str
    asset_kind: str
    authorization_id: uuid.UUID
    authorization_reference: str
    authorization_state: Literal["active", "not_yet_valid", "expired", "revoked"]
    sector: CniiSector
    owning_unit: str
    monitoring: Literal["availability", "vulnerability", "both"]
    status: Literal["active", "suspended"]
    open_findings: int
    critical_findings: int
    last_check: CniiCheckView | None = None
    availability_30d: float | None = Field(default=None, description="Share of recorded availability checks that were up; "
                                                                      "None when no check was recorded")
    schedules: list[CniiScheduleView] = []
    created_at: datetime


class CniiMonitoredAssetList(Contract):
    items: list[CniiMonitoredAssetView]


class CniiOverview(Contract):
    generated_at: datetime
    designation_sectors: list[CniiSector]
    authorizations_active: int
    authorizations_expiring_30d: int
    monitored_assets: int
    suspended_assets: int
    by_sector: dict[str, int]
    open_findings: int
    critical_findings: int
    availability_checks_30d: int
    probe: str = Field(description="Whether an availability probe is configured in this installation")


class CniiMonitoredAssetStatus(Contract):
    status: Literal["active", "suspended"]
    reason: Annotated[str, Field(min_length=3, max_length=500)]
