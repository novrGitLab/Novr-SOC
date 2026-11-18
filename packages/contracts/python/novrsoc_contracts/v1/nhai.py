"""Novr Human-Assisted Intelligence (NHAI) contracts v1.

Operating principle: **AI analyses and recommends. Human analysts validate and approve consequential actions.**

Rules carried by these models (tested in packages/contracts/tests/test_nhai_gateway.py):
  * Every NHAI request is made by a signed-in user in their ACTIVE organisation. Requests carry no
    organisation field; the API assembles the context bundle server-side, from that organisation only.
  * Every statement the model makes cites evidence from the bundle ("E1", "E2", ...). A statement whose
    citations are missing or not in the bundle is dropped and counted, never shown as fact.
  * Results are DRAFTS. They become usable (e.g. a case note) only through an explicit human review.
  * A recommendation may name an action, but the AI never executes it. Consequential actions
    (v1/soar.CONSEQUENTIAL_ACTIONS) always require a human approval through the SOAR approval flow.
  * Inference is local (Ollama through the AI Gateway). Candidate models: qwen3:4b, qwen2.5:3b.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Literal

from pydantic import Field, model_validator

from .common import ActorRef, Contract, Internal, ResourceRef
from .soar import CONSEQUENTIAL_ACTIONS, ActionType

NHAI_NAME = "Novr Human-Assisted Intelligence"
NHAI_CANDIDATE_MODELS = ("qwen3:4b", "qwen2.5:3b")

CitationId = Annotated[str, Field(pattern=r"^E[1-9][0-9]{0,3}$", description="Evidence key within one bundle")]


class NhaiTask(str, Enum):
    ALERT_EXPLANATION = "alert_explanation"
    BEHAVIOURAL_INSIGHT_SUMMARY = "behavioural_insight_summary"
    INVESTIGATION_ASSISTANCE = "investigation_assistance"
    CASE_NOTE_DRAFT = "case_note_draft"
    FINDING_EXPLANATION = "finding_explanation"   # consolidation: a VMS finding, with CVE intelligence and the asset
    ASSET_SUMMARY = "asset_summary"               # consolidation: one canonical asset across SIEM, VMS and intelligence
    CHAT_ANSWER = "chat_answer"                   # consolidation: NovrChat prose over retrieved, cited records


# ---------------------------------------------------------------- requests (human API; org = active org)
class AlertExplanationRequest(Contract):
    alert_id: uuid.UUID


class FindingExplanationRequest(Contract):
    finding_id: uuid.UUID


class AssetSummaryRequest(Contract):
    asset_id: uuid.UUID


class CaseAssistanceRequest(Contract):
    """Investigation assistance for one case: its linked alerts (authoritative severities), notes, timeline and the
    Threat Insights matches of those alerts. A draft for the analyst; it never changes the case."""
    case_id: uuid.UUID


class BehaviouralInsightSummaryRequest(Contract):
    entity: ResourceRef
    window_start: datetime
    window_end: datetime

    @model_validator(mode="after")
    def _window(self):
        if self.window_end <= self.window_start:
            raise ValueError("window_end must be after window_start")
        if (self.window_end - self.window_start).days > 31:
            raise ValueError("a behavioural summary covers at most 31 days")
        return self


class InvestigationAssistRequest(Contract):
    case_id: uuid.UUID
    question: Annotated[str, Field(min_length=3, max_length=2000)]


class CaseNoteDraftRequest(Contract):
    case_id: uuid.UUID
    note_kind: Literal["progress", "handover", "closure"]
    evidence_ids: Annotated[list[uuid.UUID], Field(max_length=100)] = Field(
        default=[], description="Optional: limit the bundle to these case evidence items")


# ---------------------------------------------------------------- organisation-scoped context
class EvidenceItem(Contract):
    """One piece of evidence the model may cite. Built server-side from the active organisation only."""
    citation_id: CitationId
    ref: ResourceRef
    observed_at: datetime | None = None
    excerpt: Annotated[str, Field(max_length=4000)]
    redacted: bool = Field(default=False, description="True when secrets/PII were removed before inclusion")


class ContextBundle(Internal):
    """What the model sees. Never crosses organisations; sent only to the local inference backend."""
    bundle_id: uuid.UUID
    org_id: uuid.UUID
    task: NhaiTask
    subject: ResourceRef
    evidence: Annotated[list[EvidenceItem], Field(min_length=1, max_length=200)]
    assembled_at: datetime
    assembled_for: uuid.UUID = Field(description="The requesting user (audit)")

    @model_validator(mode="after")
    def _unique_citations(self):
        ids = [e.citation_id for e in self.evidence]
        if len(ids) != len(set(ids)):
            raise ValueError("citation ids must be unique within a bundle")
        return self


# ---------------------------------------------------------------- structured results
class Citation(Contract):
    citation_id: CitationId
    ref: ResourceRef
    excerpt: Annotated[str, Field(max_length=1000)]


class Statement(Contract):
    text: Annotated[str, Field(min_length=1, max_length=2000)]
    citation_ids: Annotated[list[CitationId], Field(min_length=1, max_length=20)]


class Recommendation(Contract):
    text: Annotated[str, Field(min_length=1, max_length=2000)]
    citation_ids: Annotated[list[CitationId], Field(min_length=1, max_length=20)]
    action: ActionType | None = None
    requires_human_approval: bool
    executes_automatically: Literal[False] = False

    @model_validator(mode="after")
    def _approval(self):
        if self.action is not None and self.action.value in CONSEQUENTIAL_ACTIONS and not self.requires_human_approval:
            raise ValueError("a consequential action always requires human approval")
        return self


class ModelRef(Contract):
    name: str
    provider: Literal["ollama_local"] = "ollama_local"
    digest: Annotated[str, Field(pattern=r"^[0-9a-f]{12,64}$")] | None = None


class HumanReview(Contract):
    reviewer: ActorRef
    decision: Literal["accept", "accept_with_edits", "reject"]
    note: Annotated[str, Field(max_length=2000)] = ""
    reviewed_at: datetime

    @model_validator(mode="after")
    def _human(self):
        if self.reviewer.type != "user" or self.reviewer.id is None:
            raise ValueError("a review is made by a named human user")
        if self.decision == "reject" and len(self.note.strip()) < 3:
            raise ValueError("a rejection needs a note")
        return self


class SeverityAssessment(Contract):
    """Phase 5 (additive): the model's evidence-grounded view of an alert's severity. Advisory only: it never
    changes a stored severity; an analyst decides."""
    proposed: Literal["critical", "high", "medium", "low"]
    agrees_with_stored: bool | None = None
    rationale: Annotated[str, Field(min_length=1, max_length=2000)]
    citation_ids: Annotated[list[CitationId], Field(min_length=1, max_length=20)]
    uncertainty: Literal["low", "medium", "high"]


class NhaiResult(Contract):
    id: uuid.UUID
    task: NhaiTask
    subject: ResourceRef
    status: Literal["draft", "accepted", "rejected", "superseded"] = "draft"
    model: ModelRef
    summary: Annotated[str, Field(min_length=1, max_length=4000)]
    statements: list[Statement] = []
    recommendations: list[Recommendation] = []
    citations: list[Citation]
    confidence: Literal["low", "medium", "high"]
    limitations: list[Annotated[str, Field(max_length=500)]] = []
    unsupported_statements_dropped: int = Field(ge=0, default=0)
    generated_at: datetime
    latency_ms: int = Field(ge=0)
    review: HumanReview | None = None
    severity_assessment: SeverityAssessment | None = None
    missing_evidence: list[Annotated[str, Field(max_length=300)]] = Field(
        default=[], description="Phase 5: evidence that would change the assessment and is not in the bundle. Always "
        "includes the gaps found by the deterministic checker, whatever the model said")
    validation_notes: list[Annotated[str, Field(max_length=300)]] = Field(
        default=[], description="Phase 5: every deterministic adjustment made to the model output (confidence cap, "
        "dropped statements, severity disagreement), so a reviewer sees exactly what was changed and why")

    @model_validator(mode="after")
    def _integrity(self):
        known = {c.citation_id for c in self.citations}
        cited = [*self.statements, *self.recommendations, *([self.severity_assessment] if self.severity_assessment else [])]
        for s in cited:
            missing = set(s.citation_ids) - known
            if missing:
                raise ValueError(f"cites evidence not in the result: {sorted(missing)}")
        if self.status in ("accepted", "rejected") and self.review is None:
            raise ValueError("accepted/rejected results need a human review")
        if self.status == "draft" and self.review is not None:
            raise ValueError("a reviewed result is not a draft")
        if self.review is not None:
            expect = "rejected" if self.review.decision == "reject" else "accepted"
            if self.status != expect:
                raise ValueError("status must match the review decision")
        return self


class CaseNoteDraft(Contract):
    result_id: uuid.UUID
    case_id: uuid.UUID
    note_kind: Literal["progress", "handover", "closure"]
    body_markdown: Annotated[str, Field(min_length=1, max_length=8000)]
    citations: list[Citation]


class CaseNoteAcceptance(Contract):
    """An analyst turns a draft into a real case note (possibly edited). Only this writes to the case."""
    result_id: uuid.UUID
    final_body_markdown: Annotated[str, Field(min_length=1, max_length=8000)]
    review: HumanReview


class ModelOutput(Internal):
    """The JSON shape the model is asked to produce (validated before anything is stored or shown)."""
    summary: Annotated[str, Field(min_length=1, max_length=4000)]
    statements: list[Statement] = []
    recommendations: list[Recommendation] = []
    confidence: Literal["low", "medium", "high"]
    limitations: list[Annotated[str, Field(max_length=500)]] = []
    severity_assessment: SeverityAssessment | None = None
    missing_evidence: list[Annotated[str, Field(max_length=300)]] = []


# ---------------------------------------------------------------- asynchronous jobs (Phase 5, additive)
NhaiJobStatus = Literal["queued", "running", "succeeded", "failed", "timed_out"]


class NhaiJob(Contract):
    """One asynchronous NHAI request. Inference runs in a separate worker; the API only queues and reads jobs.
    `result` is present only when `status` is `succeeded`; `error_code` explains every other final state."""
    id: uuid.UUID
    task: NhaiTask
    subject: ResourceRef
    status: NhaiJobStatus
    requested_by: ActorRef
    queued_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    deadline_at: datetime
    attempts: int = Field(ge=0)
    error_code: Annotated[str, Field(pattern=r"^[a-z_]{2,40}$")] | None = None
    result: NhaiResult | None = None


class NhaiJobList(Contract):
    items: list[NhaiJob]


class NhaiReviewRequest(Contract):
    """A human decision on a succeeded job's draft (nhai:review). The reviewer is the signed-in user."""
    decision: Literal["accept", "accept_with_edits", "reject"]
    note: Annotated[str, Field(max_length=2000)] = ""


def ground(output: ModelOutput, bundle: ContextBundle) -> tuple[list[Statement], list[Recommendation], int]:
    """Keep only statements/recommendations whose every citation exists in the bundle; return the count
    dropped. Used by the API before building an NhaiResult."""
    known = {e.citation_id for e in bundle.evidence}
    st = [s for s in output.statements if set(s.citation_ids) <= known]
    rc = [r for r in output.recommendations if set(r.citation_ids) <= known]
    dropped = (len(output.statements) - len(st)) + (len(output.recommendations) - len(rc))
    return st, rc, dropped


def ground_severity(output: ModelOutput, bundle: ContextBundle) -> tuple[SeverityAssessment | None, int]:
    """Phase 5: keep the severity assessment only when every citation exists in the bundle (else drop, count 1)."""
    sa = output.severity_assessment
    if sa is None:
        return None, 0
    known = {e.citation_id for e in bundle.evidence}
    return (sa, 0) if set(sa.citation_ids) <= known else (None, 1)
