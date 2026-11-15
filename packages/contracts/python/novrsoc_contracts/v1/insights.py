"""Threat Insights contracts v1 (contract only; workstream F).

Threat Insights is organisation-relevant intelligence derived from the organisation's OWN telemetry,
assets and findings, plus vetted external indicators. It is not a standalone TI product, has no MISP
service, and never shares one organisation's data with another.

AI (explanations, summaries, drafts) lives in v1/nhai.py (Novr Human-Assisted Intelligence) and the
inference service in v1/ai_gateway.py.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from datetime import date
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator

from .common import Contract, ResourceRef, Severity, ShortText


class Tlp(str, Enum):
    CLEAR = "clear"
    GREEN = "green"
    AMBER = "amber"
    AMBER_STRICT = "amber_strict"
    RED = "red"


class IndicatorType(str, Enum):
    IPV4 = "ipv4"
    IPV6 = "ipv6"
    DOMAIN = "domain"
    URL = "url"
    SHA256 = "sha256"
    CVE = "cve"


class Indicator(Contract):
    type: IndicatorType
    value: Annotated[str, Field(min_length=1, max_length=2048)]
    tlp: Tlp
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,60}$")]
    first_seen_at: datetime
    confidence: Annotated[int, Field(ge=0, le=100)]


class InsightMatch(Contract):
    """An indicator matched against THIS organisation's evidence."""
    id: uuid.UUID
    indicator: Indicator
    matched: ResourceRef
    matched_at: datetime
    severity: Severity
    verdict: Literal["unreviewed", "true_positive", "false_positive", "benign"] = "unreviewed"


class BehaviouralSignal(Contract):
    """A deviation from the organisation's own baseline (behavioural analytics, BUILD LATER)."""
    id: uuid.UUID
    entity: ResourceRef
    metric: Annotated[str, Field(pattern=r"^[a-z0-9_.]{2,80}$")]
    baseline: float
    observed: float
    window_start: datetime
    window_end: datetime
    model_version: Annotated[str, Field(max_length=40)]


class InsightFeedback(Contract):
    match_id: uuid.UUID
    verdict: Literal["true_positive", "false_positive", "benign"]
    note: ShortText = ""

    @model_validator(mode="after")
    def _note_for_fp(self):
        if self.verdict == "false_positive" and len(self.note.strip()) < 3:
            raise ValueError("a false-positive verdict needs a note")
        return self


# ---------------------------------------------------------------- Phase 5 (additive): the Threat Insights engine
# Deterministic, organization-scoped: an indicator belongs to ONE organization (shared feeds are imported per
# organization, keeping their provenance). Matching is exact on normalized values; no model is involved.

class IndicatorProvenance(Contract):
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,60}$")]
    source_ref: ShortText = Field(default="", description="The source's own id (e.g. a STIX id or feed record)")
    imported_by: ShortText = ""
    imported_at: datetime


class IndicatorRecord(Contract):
    id: uuid.UUID
    type: IndicatorType
    value: Annotated[str, Field(min_length=1, max_length=2048, description="Normalized value used for matching")]
    tlp: Tlp
    confidence: Annotated[int, Field(ge=0, le=100)]
    valid_from: datetime
    valid_until: datetime | None = None
    stix_id: Annotated[str, Field(pattern=r"^indicator--[0-9a-f-]{36}$")]
    provenance: IndicatorProvenance


class IndicatorImport(Contract):
    """Either plain indicators or a STIX 2.1 bundle (only `indicator` objects with a single-comparison pattern on a
    supported observable are accepted; anything else is reported as skipped, never guessed)."""
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,60}$")]
    tlp: Tlp = Tlp.AMBER
    indicators: Annotated[list[Indicator], Field(max_length=5000)] = []
    stix_bundle: dict | None = None


class IndicatorImportResult(Contract):
    imported: int = Field(ge=0)
    unchanged: int = Field(ge=0)
    skipped: list[Annotated[str, Field(max_length=300)]] = []


class IndicatorList(Contract):
    items: list[IndicatorRecord]


class Observable(Contract):
    """A normalized value extracted deterministically from one stored alert."""
    type: IndicatorType
    value: Annotated[str, Field(min_length=1, max_length=2048)]
    source_field: Annotated[str, Field(pattern=r"^[A-Za-z0-9_.\[\]]{1,80}$")]


class MatchConfidence(Contract):
    """How the match confidence was computed (deterministic policy, explained)."""
    score: Annotated[int, Field(ge=0, le=100)]
    band: Literal["low", "medium", "high"]
    reasons: list[Annotated[str, Field(max_length=200)]]


class InsightMatchView(Contract):
    id: uuid.UUID
    indicator: IndicatorRecord
    alert_id: uuid.UUID
    observable: Observable
    matched_at: datetime
    confidence: MatchConfidence
    verdict: Literal["unreviewed", "true_positive", "false_positive", "benign"]


class InsightMatchList(Contract):
    items: list[InsightMatchView]


class MatchRunResult(Contract):
    alerts_scanned: int = Field(ge=0)
    observables: int = Field(ge=0)
    new_matches: int = Field(ge=0)


class CorrelationGroup(Contract):
    """Alerts of ONE organization that share a basis within a window."""
    key: Annotated[str, Field(max_length=300)]
    basis: Literal["shared_observable", "same_agent_and_rule"]
    alert_ids: list[uuid.UUID]
    first_seen_at: datetime
    last_seen_at: datetime
    max_severity: Severity


class CorrelationList(Contract):
    window_hours: int
    items: list[CorrelationGroup]


# ---------------------------------------------------------------- Phase 6 pilot (additive): STIX store, TAXII feed ingest
class StixIngest(Contract):
    """A STIX 2.1 bundle for the organization: uploaded by a user, or delivered by the Server 1 TAXII feeder (its
    organization-bound ti_feeder identity decides the organization; the body has none)."""
    source: Annotated[str, Field(pattern=r"^[a-z0-9_.-]{2,60}$")]
    collection: Annotated[str, Field(max_length=200)] = ""
    bundle: dict


class StixIngestResult(Contract):
    objects_received: int = Field(ge=0)
    objects_stored: int = Field(ge=0)
    indicators_imported: int = Field(ge=0)
    relationships: int = Field(ge=0)
    rejected: list[Annotated[str, Field(max_length=300)]] = []


class RelatedObject(Contract):
    stix_id: str
    type: str
    name: str
    relationship_type: str
    edge: Literal["outgoing", "incoming"]


class IndicatorContext(Contract):
    indicator: IndicatorRecord
    related: list[RelatedObject]


class FeedRun(Contract):
    id: uuid.UUID
    source: str
    collection: str
    objects_received: int
    objects_stored: int
    indicators_imported: int
    rejected: int
    received_at: datetime


class FeedRunList(Contract):
    items: list[FeedRun]


# ---------------------------------------------------------------- consolidation (additive): threat actors
Attribution = Literal["verified", "suspected", "unknown"]


class ActorSource(Contract):
    name: Annotated[str, Field(min_length=2, max_length=200)]
    url: Annotated[str, Field(max_length=500)] = ""
    published: date | None = None


class ThreatActorCreate(Contract):
    """An actor profile. `verified` needs at least one cited source; `unknown` attribution carries confidence 0.
    Nothing is pre-loaded; NovrSOC never names an actor on its own."""
    name: Annotated[str, Field(min_length=2, max_length=120)]
    aliases: Annotated[list[Annotated[str, Field(min_length=1, max_length=120)]], Field(max_length=30)] = []
    attribution: Attribution
    confidence: Annotated[int, Field(ge=0, le=100)] = 0
    description: Annotated[str, Field(max_length=8000)] = ""
    motivations: Annotated[list[Annotated[str, Field(max_length=80)]], Field(max_length=10)] = []
    target_sectors: Annotated[list[Annotated[str, Field(max_length=80)]], Field(max_length=20)] = []
    target_regions: Annotated[list[Annotated[str, Field(max_length=80)]], Field(max_length=20)] = []
    techniques: Annotated[list[Annotated[str, Field(pattern=r"^T\d{4}(\.\d{3})?$")]], Field(max_length=100)] = []
    first_seen: date | None = None
    last_seen: date | None = None
    sources: Annotated[list[ActorSource], Field(max_length=50)] = []

    @model_validator(mode="after")
    def _attribution(self):
        if self.attribution == "verified" and not self.sources:
            raise ValueError("a verified attribution cites at least one source")
        if self.attribution == "unknown" and self.confidence != 0:
            raise ValueError("an unknown attribution has confidence 0")
        return self


class ActorLinkCreate(Contract):
    link_type: Literal["indicator", "cve", "case", "alert", "asset"]
    ref_id: Annotated[str, Field(min_length=1, max_length=200)]
    association: Literal["verified", "suspected"]
    rationale: Annotated[str, Field(min_length=3, max_length=2000)]


class ActorLinkView(ActorLinkCreate):
    id: uuid.UUID
    created_label: str
    created_at: datetime
    exists: bool = Field(description="False when the linked record is no longer visible in this organization")


class ThreatActorView(ThreatActorCreate):
    id: uuid.UUID
    created_label: str
    created_at: datetime
    updated_at: datetime
    links: list[ActorLinkView] = []
    observed_in_organization: bool = Field(default=False, description="True only when a VERIFIED link ties the actor to "
                                                                      "this organization's own records")


class ThreatActorList(Contract):
    items: list[ThreatActorView]


# ---------------------------------------------------------------- consolidation (additive): CVE intelligence
class CveRecordIn(Contract):
    cve_id: Annotated[str, Field(pattern=r"^CVE-\d{4}-\d{4,7}$")]
    cvss_v3: Annotated[float, Field(ge=0, le=10)] | None = None
    cvss_vector: Annotated[str, Field(max_length=200)] | None = None
    epss: Annotated[float, Field(ge=0, le=1)] | None = None
    kev: bool = False
    kev_added: date | None = None
    published: date | None = None
    description: Annotated[str, Field(max_length=4000)] = ""


class CveImport(Contract):
    """Import CVE intelligence from a file the analyst obtained (records, or a CISA KEV catalog JSON document).
    NovrSOC does not fetch feeds itself here; the Server 1 feeder can deliver STIX vulnerabilities."""
    source: Annotated[str, Field(min_length=2, max_length=80)]
    records: Annotated[list[CveRecordIn], Field(max_length=5000)] = []
    kev_catalog: dict[str, Any] | None = None


class CveImportResult(Contract):
    imported: int
    skipped: list[str] = []


class CveIntelView(Contract):
    cve_id: str
    cvss_v3: float | None = None
    cvss_vector: str | None = None
    epss: float | None = None
    kev: bool
    kev_added: date | None = None
    published: date | None = None
    description: str
    source: str
    captured_at: datetime
    snapshots: int = Field(ge=1)
    open_findings: int = Field(ge=0, description="This organization's open VMS findings that name the CVE")
    affected_assets: int = Field(ge=0)
    actors: list[str] = Field(default=[], description="Actors linked to the CVE in this organization, with their association")


class CveIntelList(Contract):
    items: list[CveIntelView]
    finding_cves_without_intel: list[str] = Field(default=[], description="CVEs in open findings with no intelligence record")


class SnapshotCreate(Contract):
    kind: Literal["cvss", "ioc"]
    subject: Annotated[str, Field(min_length=1, max_length=300, description="A CVE id, or an indicator id")]
    reason: Annotated[str, Field(max_length=500)] = ""


class SnapshotView(Contract):
    id: uuid.UUID
    kind: Literal["cvss", "ioc"]
    subject: str
    content: dict[str, Any]
    sha256: str
    reason: str
    captured_label: str
    captured_at: datetime


class SnapshotList(Contract):
    items: list[SnapshotView]
