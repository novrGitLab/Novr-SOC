"""Email Security and Brand Protection contracts v1 (contract only; workstream D).

Email Security carries the legacy behaviour: TXT-verified domain ownership, SPF/DKIM/DMARC inspection,
DMARC aggregate ingestion from verified domains only, phishing look-alike detection, provider
connectors. Every record is organisation-owned (no DEFAULT_ORG fallback; staff switch via X-Org-Id).

Brand Protection replaces the legacy in-memory, cross-tenant lists with persistent, organisation-owned
watch subjects and findings. Monitoring runs as scheduled jobs (BUILD LATER), not ad-hoc lookups.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field

from .common import Contract, IdempotencyKey, MachineInbound, Severity, ShortText

Domain = Annotated[str, Field(min_length=3, max_length=253, pattern=r"^([a-z0-9](-?[a-z0-9])*\.)+[a-z]{2,63}$")]


# ---------------------------------------------------------------- Email Security
class EmailDomain(Contract):
    id: uuid.UUID
    domain: Domain
    verification: Literal["pending", "verified", "failed"]
    verification_txt_name: ShortText
    dmarc_policy: Literal["none", "quarantine", "reject", "missing"] | None = None
    spf_valid: bool | None = None
    dkim_selectors_found: list[Annotated[str, Field(max_length=63)]] = []
    last_checked_at: datetime | None = None


class DmarcAggregateReport(Contract):
    id: uuid.UUID
    domain_id: uuid.UUID
    reporter: ShortText
    report_id: Annotated[str, Field(max_length=200)]
    period_start: datetime
    period_end: datetime
    messages_total: int = Field(ge=0)
    messages_failing: int = Field(ge=0)


class GatewayVerdict(MachineInbound):
    """Mail gateway -> API, authenticated by the gateway's service identity (replaces the shared EMAIL_PROXY_TOKEN)."""
    verdict_id: IdempotencyKey
    message_id: Annotated[str, Field(max_length=998)]
    recipient_domain: Domain
    verdict: Literal["deliver", "quarantine", "reject"]
    reasons: list[ShortText] = []
    received_at: datetime


class PhishingCandidate(Contract):
    id: uuid.UUID
    domain: Domain
    resembles: Domain
    similarity: Annotated[float, Field(ge=0, le=1)]
    risk: Severity
    status: Literal["new", "investigating", "confirmed", "dismissed", "takedown_requested"]
    first_seen_at: datetime


# ---------------------------------------------------------------- Brand Protection
class WatchSubjectType(str, Enum):
    BRAND_NAME = "brand_name"
    DOMAIN = "domain"
    EXECUTIVE = "executive"
    SOCIAL_ACCOUNT = "social_account"
    MOBILE_APP = "mobile_app"
    CODE_REPOSITORY_TERM = "code_repository_term"


class WatchSubject(Contract):
    id: uuid.UUID
    type: WatchSubjectType
    value: Annotated[str, Field(min_length=2, max_length=200)]
    active: bool = True
    created_at: datetime


class WatchSubjectCreate(Contract):
    type: WatchSubjectType
    value: Annotated[str, Field(min_length=2, max_length=200)]
    consent_reference: Annotated[str, Field(min_length=3, max_length=200)] | None = Field(
        default=None, description="Required for EXECUTIVE subjects (personal data, NDPA)")


class BrandFinding(Contract):
    id: uuid.UUID
    subject_id: uuid.UUID
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,40}$", description="e.g. crtsh, rdap, app_store, code_search, leak_site")]
    url: Annotated[str, Field(max_length=2048)] | None = None
    summary: Annotated[str, Field(max_length=2000)]
    severity: Severity
    status: Literal["new", "triaged", "actioned", "dismissed"]
    observed_at: datetime


class MonitoringRun(Contract):
    id: uuid.UUID
    subject_id: uuid.UUID
    started_at: datetime
    finished_at: datetime | None = None
    outcome: Literal["completed", "source_unconfigured", "rate_limited", "failed"] | None = None
    new_findings: int = Field(ge=0, default=0)


# ---------------------------------------------------------------- Phase 6 pilot (additive): API views
class EmailDomainCreate(Contract):
    domain: Domain


class EmailDomainList(Contract):
    items: list[EmailDomain]


class DmarcUpload(Contract):
    """An aggregate (RUA) report as XML text, uploaded by a user or the test adapter. DTDs and entities are refused."""
    xml: Annotated[str, Field(min_length=50, max_length=2_000_000)]
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,40}$")] = "upload"


class DmarcRecord(Contract):
    source_ip: str
    count: int = Field(ge=0)
    disposition: str
    dkim: str
    spf: str
    header_from: str


class DmarcReportView(DmarcAggregateReport):
    domain: Domain
    published_policy: str | None = None
    records: list[DmarcRecord] = []
    source: str


class DmarcReportList(Contract):
    items: list[DmarcReportView]


class WatchSubjectList(Contract):
    items: list[WatchSubject]


class BrandFindingView(BrandFinding):
    value: str
    evidence: dict = {}


class BrandFindingList(Contract):
    items: list[BrandFindingView]


class BrandFindingTriage(Contract):
    status: Literal["triaged", "actioned", "dismissed"]
    note: Annotated[str, Field(max_length=2000)] = ""


class MonitoringRunList(Contract):
    items: list[MonitoringRun]
