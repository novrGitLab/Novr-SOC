"""VMS contracts v1 (contract only; built by workstreams B (VMS + Greenbone) and C (Wazuh SCA)).

Carried behaviour (legacy VMS, most-tested module):
  * Scope is checked at queue, at claim and at ingest. Observations outside the job's approved scope
    are dropped, never stored.
  * Findings are verified ONLY by scan evidence (lifecycle below); a manual "fixed" is fixed_pending_verification.
  * Greenbone stays behind the VMS worker (gvmd UNIX socket). The API never talks to Greenbone.
  * Asset identity is canonical: one asset row with typed source links (Wazuh agent, scanner observation,
    import), and network addresses are site-scoped.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .common import Contract, IdempotencyKey, Internal, MachineInbound, MachineOutbound, Severity, ShortText, SiteScopedAddress

CVE = Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,7}$")]


# ---------------------------------------------------------------- assets
class AssetSourceType(str, Enum):
    WAZUH_AGENT = "wazuh_agent"
    SCANNER_OBSERVATION = "scanner_observation"
    COLLECTOR_DISCOVERY = "collector_discovery"
    IMPORT = "import"


class AssetSourceLink(Contract):
    type: AssetSourceType
    external_id: Annotated[str, Field(min_length=1, max_length=200, description="e.g. Wazuh agent id '003' (unique per manager+org)")]
    first_seen_at: datetime
    last_seen_at: datetime


class Criticality(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Exposure(str, Enum):
    INTERNAL = "internal"
    DMZ = "dmz"
    INTERNET = "internet"
    UNKNOWN = "unknown"


class Asset(Contract):
    id: uuid.UUID
    org_id: uuid.UUID
    kind: Literal["host", "domain", "web_application", "network_device", "cloud_resource"]
    display_name: ShortText
    addresses: list[SiteScopedAddress] = []
    fqdns: list[ShortText] = []
    criticality: Criticality = Criticality.MEDIUM
    exposure: Exposure = Exposure.UNKNOWN
    sources: list[AssetSourceLink] = []
    tags: list[Annotated[str, Field(max_length=40)]] = []


# ---------------------------------------------------------------- Wazuh endpoints & SCA
class WazuhEndpoint(Contract):
    """Read model of a Wazuh agent mapped to an asset. Ownership comes from the group/source map, never the agent."""
    asset_id: uuid.UUID
    agent_id: Annotated[str, Field(pattern=r"^\d{3,6}$")]
    manager_id: uuid.UUID
    name: ShortText
    os_platform: ShortText | None = None
    os_version: ShortText | None = None
    agent_version: ShortText | None = None
    status: Literal["active", "disconnected", "never_connected", "pending"]
    groups: list[ShortText] = []
    last_keepalive_at: datetime | None = None


class ScaResult(str, Enum):
    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class ScaCheckResult(Contract):
    check_id: int
    title: ShortText
    result: ScaResult
    rationale: Annotated[str, Field(max_length=4000)] = ""
    remediation: Annotated[str, Field(max_length=4000)] = ""
    compliance: dict[Annotated[str, Field(max_length=40)], list[Annotated[str, Field(max_length=40)]]] = Field(
        default={}, description="Framework -> control ids, e.g. {'cis': ['1.1.1'], 'pci_dss': ['2.2']}")


class ScaPolicyResult(Contract):
    """One SCA policy evaluation for one endpoint (Wazuh /sca/{agent_id} + /sca/{agent_id}/checks/{policy})."""
    asset_id: uuid.UUID
    agent_id: str
    policy_id: Annotated[str, Field(min_length=1, max_length=120)]
    policy_name: ShortText
    scanned_at: datetime
    passed: int = Field(ge=0)
    failed: int = Field(ge=0)
    not_applicable: int = Field(ge=0)
    score_percent: Annotated[int, Field(ge=0, le=100)]
    checks: list[ScaCheckResult] = []

    @model_validator(mode="after")
    def _score(self):
        applicable = self.passed + self.failed
        expected = round(100 * self.passed / applicable) if applicable else 0
        if abs(expected - self.score_percent) > 1:
            raise ValueError("score_percent must equal passed / (passed + failed)")
        return self


# ---------------------------------------------------------------- scope & scan jobs
class ScopeEntry(Contract):
    kind: Literal["domain", "ip", "cidr", "url"]
    value: Annotated[str, Field(min_length=1, max_length=253)]
    site_id: uuid.UUID | None = Field(default=None, description="Required for private addresses and ranges")


class ScanActivity(str, Enum):
    DISCOVERY = "discovery"
    PORTS = "ports"
    VULN_NUCLEI = "vuln_nuclei"
    VULN_OPENVAS = "vuln_openvas"


class ScopeApproval(Contract):
    """An organisation-approved scope (P27 model). OpenVAS is allowed only when listed here; never by env var."""
    id: uuid.UUID
    entries: Annotated[list[ScopeEntry], Field(min_length=1)]
    allowed_activities: Annotated[list[ScanActivity], Field(min_length=1)]
    authorization_reference: Annotated[str, Field(min_length=3, max_length=200)]
    approved_by: uuid.UUID
    approved_at: datetime
    valid_until: datetime
    scan_windows: list["ScanWindow"] = []
    revoked_at: datetime | None = None


class ScanWindow(Contract):
    weekday: Annotated[int, Field(ge=0, le=6)]
    start_minute: Annotated[int, Field(ge=0, le=1439)]
    end_minute: Annotated[int, Field(ge=1, le=1440)]
    timezone: Annotated[str, Field(max_length=64)] = "Africa/Lagos"

    @model_validator(mode="after")
    def _order(self):
        if self.end_minute <= self.start_minute:
            raise ValueError("end_minute must be after start_minute")
        return self


class ScanJobRequest(Contract):
    """Human API (vms:scan). Refused unless every target is inside an active ScopeApproval allowing the activity."""
    idempotency_key: IdempotencyKey
    scope_approval_id: uuid.UUID
    activity: ScanActivity
    targets: Annotated[list[ScopeEntry], Field(min_length=1, max_length=4096)]
    profile: Literal["discovery", "standard", "full"] = "standard"


class ScanJobClaim(MachineOutbound):
    """Sent to the VMS worker on claim (atomic, FOR UPDATE SKIP LOCKED). Greenbone config names are worker-side."""
    job_id: uuid.UUID
    activity: ScanActivity
    targets: list[ScopeEntry]
    deadline_at: datetime
    max_runtime_seconds: Annotated[int, Field(ge=60, le=12 * 3600)]
    max_rate_pps: Annotated[int, Field(ge=1, le=1000)] | None = Field(
        default=None, description="The organization's scan-policy packet-rate ceiling; the worker never exceeds it (nor its own)")
    protected_networks: list[str] = Field(default=[], description="Never touched, whatever the targets say (scan policy)")


class ObservationKind(str, Enum):
    HOST = "host"
    SERVICE = "service"
    TECHNOLOGY = "technology"
    FINDING = "finding"


class Observation(Contract):
    kind: ObservationKind
    target: ScopeEntry
    port: Annotated[int, Field(ge=1, le=65535)] | None = None
    protocol: Literal["tcp", "udp"] | None = None
    check_id: Annotated[str, Field(max_length=200)] | None = Field(default=None, description="Scanner check id, e.g. Greenbone NVT OID")
    title: ShortText | None = None
    severity: Severity | None = None
    cvss_v3: Annotated[float, Field(ge=0, le=10)] | None = None
    cves: list[CVE] = []
    evidence_ref: Annotated[str, Field(max_length=200)] | None = None


class ScanResultBatch(MachineInbound):
    """Worker -> API. No org field: the job (and so the organisation) comes from job_id + worker identity."""
    batch_id: IdempotencyKey
    job_id: uuid.UUID
    observations: Annotated[list[Observation], Field(max_length=5000)]
    per_target_outcome: dict[str, Literal["completed", "unreachable", "refused_out_of_scope", "failed", "no_route"]] = {}


# ---------------------------------------------------------------- findings, risk, remediation, verification
class FindingStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    FIXED_PENDING_VERIFICATION = "fixed_pending_verification"
    VERIFIED = "verified"
    REOPENED = "reopened"
    RISK_ACCEPTED = "risk_accepted"


MANUAL_TRANSITIONS: dict[FindingStatus, frozenset[FindingStatus]] = {
    FindingStatus.OPEN: frozenset({FindingStatus.ACKNOWLEDGED, FindingStatus.IN_PROGRESS, FindingStatus.RISK_ACCEPTED}),
    FindingStatus.ACKNOWLEDGED: frozenset({FindingStatus.IN_PROGRESS, FindingStatus.RISK_ACCEPTED}),
    FindingStatus.IN_PROGRESS: frozenset({FindingStatus.FIXED_PENDING_VERIFICATION}),
    FindingStatus.REOPENED: frozenset({FindingStatus.IN_PROGRESS, FindingStatus.ACKNOWLEDGED}),
    FindingStatus.FIXED_PENDING_VERIFICATION: frozenset(),  # only scan evidence moves it on
    FindingStatus.VERIFIED: frozenset(),
    FindingStatus.RISK_ACCEPTED: frozenset({FindingStatus.OPEN}),
}


class RiskScore(Contract):
    """Contextual 0-100 (legacy lib/riskScore.ts inputs). The formula version is part of the result."""
    score: Annotated[int, Field(ge=0, le=100)]
    formula_version: Annotated[str, Field(pattern=r"^\d+\.\d+$")]
    cvss: Annotated[float, Field(ge=0, le=10)] | None = None
    epss: Annotated[float, Field(ge=0, le=1)] | None = None
    kev: bool = False
    exposure: Exposure = Exposure.UNKNOWN
    criticality: Criticality = Criticality.MEDIUM


class Finding(Contract):
    id: uuid.UUID
    asset_id: uuid.UUID
    fingerprint: Annotated[str, Field(min_length=8, max_length=128, description="Stable per asset + check")]
    title: ShortText
    severity: Severity
    status: FindingStatus
    cves: list[CVE] = []
    risk: RiskScore
    first_seen_at: datetime
    last_seen_at: datetime


class FindingTransition(Contract):
    finding_id: uuid.UUID
    to_status: FindingStatus
    reason: Annotated[str, Field(min_length=3, max_length=2000)]

    @model_validator(mode="after")
    def _not_verified(self):
        if self.to_status in (FindingStatus.VERIFIED, FindingStatus.REOPENED):
            raise ValueError("verified/reopened are set only by scan evidence")
        return self


class RemediationTask(Contract):
    id: uuid.UUID
    finding_ids: Annotated[list[uuid.UUID], Field(min_length=1)]
    asset_id: uuid.UUID
    owner_id: uuid.UUID | None = None
    due_at: datetime | None = None
    status: Literal["open", "in_progress", "done", "cancelled"]
    guidance: Annotated[str, Field(max_length=8000)] = ""
    fixed_version: ShortText | None = Field(default=None, description="From patch intelligence (OSV) when known")


class VerificationRecord(Internal):
    """Verification history entry: only a completed, in-scope scan job may verify or reopen a finding."""
    finding_id: uuid.UUID
    scan_job_id: uuid.UUID
    result: Literal["verified_fixed", "still_present", "inconclusive"]
    checked_at: datetime
    evidence_ref: Annotated[str, Field(max_length=200)] | None = None


ScopeApproval.model_rebuild()


# ---------------------------------------------------------------- V2 worker protocol (Phase 5, additive)
class ScanClaimResult(MachineOutbound):
    """Answer to a worker's claim. `job` is present only when a job is handed out. In this release scanning is
    disabled by design, so the API answers `scanning_disabled` and never hands out a job."""
    job: ScanJobClaim | None = None
    reason: Literal["job", "no_job", "scanning_disabled", "policy_disabled", "outside_scan_window", "concurrency_limit"]


class VmsWorkerStatus(Contract):
    identity_name: ShortText
    last_heartbeat_at: datetime
    component_version: str
    state: Literal["ok", "degraded", "failing", "unconfigured"]
    stale: bool


class VmsStatus(Contract):
    """VMS readiness for the active organization: whether scanning may run and which V2 workers have reported."""
    scanning: Literal["disabled", "enabled"]
    reason: ShortText
    workers: list[VmsWorkerStatus] = []


# ---------------------------------------------------------------- Phase 6 pilot (additive): VMS API views
class VmsScopeCreate(Contract):
    """Human API (vms:scope). An approved scope is the only thing a scan may touch."""
    entry: ScopeEntry
    allowed_activities: Annotated[list[ScanActivity], Field(min_length=1)]
    authorization_reference: Annotated[str, Field(min_length=3, max_length=200)]
    valid_days: Annotated[int, Field(ge=1, le=90)] = 30


class VmsScopeView(Contract):
    id: uuid.UUID
    entry: ScopeEntry
    allowed_activities: list[ScanActivity]
    authorization_reference: str
    valid_until: datetime
    created_at: datetime


class VmsScopeList(Contract):
    items: list[VmsScopeView]


class VmsScanCreate(Contract):
    idempotency_key: IdempotencyKey
    scope_id: uuid.UUID
    activity: ScanActivity
    targets: Annotated[list[Annotated[str, Field(min_length=1, max_length=253)]], Field(min_length=1, max_length=256)]
    profile: Literal["discovery", "standard", "full"] = "standard"


class VmsScanView(Contract):
    id: uuid.UUID
    scope_id: uuid.UUID
    activity: ScanActivity
    targets: list[str]
    state: Literal["queued", "running", "completed", "failed", "cancelled"]
    claimed_at: datetime | None = None
    finished_at: datetime | None = None
    outcome: dict = {}
    error: str | None = None
    created_at: datetime
    origin: Literal["manual", "schedule", "rescan", "enrollment"] = "manual"
    progress: dict = Field(default={}, description="targets_total, targets_reported, per-target outcomes, observations")
    asset_ids: list[uuid.UUID] = []


class VmsScanList(Contract):
    items: list[VmsScanView]


class WorkerFinish(MachineInbound):
    outcome: Literal["completed", "failed"]
    detail: Annotated[str, Field(max_length=500)] = ""


class VmsFindingView(Contract):
    id: uuid.UUID
    host: str
    port: int | None = None
    protocol: str | None = None
    check_id: str | None = None
    title: str
    severity: Severity
    cves: list[str] = []
    status: FindingStatus
    priority: Literal["P1", "P2", "P3", "P4"]
    risk: RiskScore
    source: str
    occurrences: int
    first_seen_at: datetime
    last_seen_at: datetime
    remediation_due_at: datetime | None = None
    asset_id: uuid.UUID | None = Field(default=None, description="Consolidation: the canonical asset of the host")
    asset_name: str | None = None
    kev: bool = Field(default=False, description="Consolidation: a CVE of the finding is in the organization's KEV intelligence")


class VmsFindingList(Contract):
    items: list[VmsFindingView]
    total: int


class VmsResultAck(Contract):
    batch_id: str
    observations: int
    new_findings: int
    updated_findings: int
    refused_out_of_scope: int
    replayed: bool = False


class VmsReport(Contract):
    generated_at: datetime
    scanning: Literal["disabled", "enabled"]
    by_priority: dict[str, int]
    by_status: dict[str, int]
    by_severity: dict[str, int]
    overdue_remediation: int
    top_findings: list[VmsFindingView]
    scans_completed_30d: int


# ---------------------------------------------------------------- consolidation (additive)
class VmsScheduleCreate(Contract):
    scope_id: uuid.UUID
    name: Annotated[str, Field(min_length=3, max_length=120)]
    activity: ScanActivity
    targets: Annotated[list[Annotated[str, Field(min_length=1, max_length=253)]], Field(min_length=1, max_length=256)]
    cadence: Literal["daily", "weekly", "monthly"]
    enabled: bool = False


class VmsScheduleView(Contract):
    id: uuid.UUID
    scope_id: uuid.UUID
    name: str
    activity: str
    targets: list[str]
    cadence: str
    enabled: bool
    next_run_at: datetime
    last_job_id: uuid.UUID | None = None
    created_at: datetime
    execution: str


class VmsScheduleList(Contract):
    items: list[VmsScheduleView]


class VmsScheduleUpdate(Contract):
    enabled: bool


class RetestRequest(Contract):
    note: Annotated[str, Field(max_length=2000)] = ""


class VerificationRequestView(Contract):
    id: uuid.UUID
    status: Literal["scan_requested", "blocked_scanning_disabled", "blocked_no_scope", "verified", "still_present", "cancelled"]
    scan_job_id: uuid.UUID | None = None
    requested_label: str
    note: str
    created_at: datetime
    updated_at: datetime


class RemediationTaskView(Contract):
    id: uuid.UUID
    finding_id: uuid.UUID
    finding_title: str
    host: str
    asset_id: uuid.UUID | None = None
    severity: Severity
    priority: str
    status: Literal["open", "in_progress", "done", "cancelled"]
    finding_status: str
    due_at: datetime
    overdue: bool
    assignee_id: uuid.UUID | None = None
    assignee_label: str | None = None
    note: str
    updated_at: datetime


class RemediationTaskList(Contract):
    items: list[RemediationTaskView]
    by_status: dict[str, int] = {}
    overdue: int = 0


class RemediationTaskUpdate(Contract):
    assignee_id: uuid.UUID | None = None
    note: Annotated[str, Field(max_length=2000)] = ""
    status: Literal["open", "in_progress"] | None = None


class FindingCveIntel(Contract):
    cve_id: str
    cvss_v3: float | None = None
    epss: float | None = None
    kev: bool = False
    description: str = ""
    source: str
    captured_at: datetime


class VmsFindingDetail(Contract):
    finding: VmsFindingView
    cve_intel: list[FindingCveIntel] = []
    cves_without_intel: list[str] = []
    remediation: RemediationTaskView | None = None
    verifications: list[VerificationRequestView] = []
    history: list[dict[str, Any]] = []


class RiskAssetRow(Contract):
    asset_id: uuid.UUID | None = None
    name: str
    criticality: str | None = None
    exposure: str | None = None
    open_findings: int
    max_risk: int
    p1: int
    kev: int


class VmsRiskOverview(Contract):
    generated_at: datetime
    by_priority: dict[str, int]
    by_severity: dict[str, int]
    kev_findings: int
    internet_facing_findings: int
    overdue: int
    assets: list[RiskAssetRow]
    formula: str


class ServiceRow(Contract):
    asset_id: uuid.UUID
    asset_name: str
    port: int
    protocol: str
    name: str
    product: str
    version: str
    source: str
    last_seen_at: datetime


class ServiceList(Contract):
    items: list[ServiceRow]
    by_product: dict[str, int] = {}


# ---------------------------------------------------------------- organization scan policy and enrollment (additive)
class PolicyWindow(Contract):
    """A weekly window in the policy's timezone during which scans of the organization may run."""
    weekday: Annotated[int, Field(ge=0, le=6, description="0 = Monday")]
    start_minute: Annotated[int, Field(ge=0, le=1439)]
    end_minute: Annotated[int, Field(ge=1, le=1440)]

    @model_validator(mode="after")
    def _order(self):
        if self.end_minute <= self.start_minute:
            raise ValueError("end_minute must be after start_minute")
        return self


class VmsScanPolicyUpdate(Contract):
    """The organization's standing scan authorization (vms:scope). Enabling requires an authorization reference and at
    least one window. auto_enroll enrolls imported assets that fall inside an approved scope; it never widens a scope."""
    enabled: bool
    auto_enroll: bool = False
    enroll_activity: ScanActivity = ScanActivity.PORTS
    rescan_interval_days: Annotated[int, Field(ge=1, le=90)] = 7
    protected_networks: Annotated[list[Annotated[str, Field(min_length=3, max_length=49)]], Field(max_length=64)] = []
    windows: Annotated[list[PolicyWindow], Field(max_length=28)] = []
    timezone: Annotated[str, Field(min_length=1, max_length=64)] = "UTC"
    max_targets_per_scan: Annotated[int, Field(ge=1, le=256)] = 32
    max_rate_pps: Annotated[int, Field(ge=1, le=1000)] = 100
    max_concurrent_scans: Annotated[int, Field(ge=1, le=4)] = 1
    address_max_age_hours: Annotated[int, Field(ge=1, le=720)] = 72
    authorization_reference: Annotated[str, Field(max_length=200)] = ""


class VmsScanPolicy(VmsScanPolicyUpdate):
    configured: bool = Field(description="False until the organization saves a policy (the defaults shown are not in force)")
    installation_mode: Literal["disabled", "local_test_targets", "authorized_scopes"]
    in_window_now: bool
    updated_by_label: str | None = None
    updated_at: datetime | None = None


EnrollmentStatus = Literal["enrolled", "eligible", "excluded_protected", "outside_scope", "public_address", "shared_address",
                           "stale_address", "no_address", "unverified_source", "manual_exclusion"]


class VmsEnrollmentView(Contract):
    asset_id: uuid.UUID
    asset_name: str
    hostname: str | None = None
    address: str | None = None
    sources: list[str] = []
    status: EnrollmentStatus
    reason: str
    scope_id: uuid.UUID | None = None
    scope_value: str | None = None
    evaluated_at: datetime
    last_scanned_at: datetime | None = None
    last_job_id: uuid.UUID | None = None
    open_findings: int = 0


class VmsEnrollmentList(Contract):
    items: list[VmsEnrollmentView]
    by_status: dict[str, int]
    evaluated_at: datetime | None = None


class VmsEnrollmentExclusion(Contract):
    excluded: bool
    reason: Annotated[str, Field(min_length=3, max_length=500)]


class VmsEnrollmentEvaluation(Contract):
    evaluated: int
    by_status: dict[str, int]
    scans_queued: int = 0
