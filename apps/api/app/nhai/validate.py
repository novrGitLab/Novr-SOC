"""Deterministic validation of NHAI model output (Phase 5, workstream F). The model proposes; this module decides
what may be shown, and records every change it makes in `validation_notes`.

Rules (in order):
  1. Strict JSON object only (a ```json fence is tolerated); then strict schema validation (ModelOutput, extra fields
     refused). Anything else fails the job (`invalid_model_output`).
  2. Grounding: statements, recommendations and the severity assessment must cite evidence ids that exist in the
     bundle; uncited items are dropped and counted.
  3. No fabricated indicators: every IP, domain, URL, SHA-256 or CVE in the output must appear in the bundle's
     evidence text. A statement or recommendation with an unknown one is dropped; a summary or severity rationale
     with one fails the job (`ungrounded_ioc`).
  4. Authoritative Wazuh severity: the model's severity is advisory and never replaces it. A proposal LOWER than the
     Wazuh severity is flagged (agrees_with_stored = false, uncertainty raised to high, a limitation added).
  5. Conservative confidence: the model's confidence is capped. Never `high` from this model class; `low` when the
     model disagrees downward with Wazuh, when grounding dropped anything, or when the bundle has fewer than 3
     evidence items. Overconfidence is noted.
  6. Missing evidence: the deterministic gaps (evidence.missing_evidence) are always added to the model's list.
  7. Recommendations never execute: requires_human_approval is forced true and executes_automatically is false.
"""
from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone

from pydantic import ValidationError

from app.insights.engine import TEXT_IPV4, TEXT_SHA256, TEXT_URL, normalize
from app.nhai.evidence import missing_evidence_for
from novrsoc_contracts.v1.nhai import (Citation, ContextBundle, ModelOutput, ModelRef, NhaiResult, ground, ground_severity)

RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
CONF = {"low": 1, "medium": 2, "high": 3}
MODEL_CONFIDENCE_CEILING = "medium"   # a 3B CPU model's self-assessed confidence is never taken as "high"
TEXT_DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|ru|cn|info|biz|xyz|top|online|site|ng|uk|de|co)\b", re.I)
TEXT_CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)


class OutputRejected(Exception):
    def __init__(self, code: str, detail: str):
        super().__init__(detail)
        self.code = code


def _iocs(text: str) -> set[tuple[str, str]]:
    found = set()
    for kind, pat in (("ipv4", TEXT_IPV4), ("sha256", TEXT_SHA256), ("url", TEXT_URL), ("domain", TEXT_DOMAIN), ("cve", TEXT_CVE)):
        for m in pat.finditer(text or ""):
            n = normalize(kind, m.group(0).rstrip(").,;"))
            if n:
                found.add((kind, n))
    return found


def _grounded_values(bundle: ContextBundle) -> set[str]:
    values = set()
    for e in bundle.evidence:
        values |= {v for _, v in _iocs(e.excerpt)}
        values.add(e.ref.id.lower())
    return values


def parse_output(text: str) -> ModelOutput:
    t = (text or "").strip()
    if t.startswith("```"):
        t = re.sub(r"^```(?:json)?\s*|\s*```$", "", t)
    try:
        data = json.loads(t)
    except ValueError:
        raise OutputRejected("invalid_model_output", "The model did not return a JSON object") from None
    if not isinstance(data, dict):
        raise OutputRejected("invalid_model_output", "The model did not return a JSON object")
    try:
        return ModelOutput.model_validate(data)
    except ValidationError as e:
        raise OutputRejected("invalid_model_output", f"The model output does not match the schema ({e.error_count()} error(s))") from None


def validate(text: str, bundle: ContextBundle, *, authoritative_severity: str | None, model: str, latency_ms: int,
             result_id: uuid.UUID | None = None) -> NhaiResult:
    out = parse_output(text)
    notes: list[str] = []
    known = _grounded_values(bundle)

    statements, recommendations, dropped = ground(out, bundle)
    severity, sev_dropped = ground_severity(out, bundle)
    dropped += sev_dropped
    if dropped:
        notes.append(f"{dropped} item(s) dropped: they cited evidence that is not in the bundle.")

    def unknown(t: str) -> set[str]:
        return {v for _, v in _iocs(t)} - known

    bad = unknown(out.summary) | (unknown(severity.rationale) if severity else set())
    if bad:
        raise OutputRejected("ungrounded_ioc", f"The model named {len(bad)} indicator(s) that are not in the evidence")
    keep_s = [s for s in statements if not unknown(s.text)]
    keep_r = [r for r in recommendations if not unknown(r.text)]
    ioc_dropped = (len(statements) - len(keep_s)) + (len(recommendations) - len(keep_r))
    if ioc_dropped:
        notes.append(f"{ioc_dropped} item(s) dropped: they named indicators that are not in the evidence.")
        dropped += ioc_dropped
    keep_r = [r.model_copy(update={"requires_human_approval": True}) for r in keep_r]

    limitations = list(out.limitations)
    downward = False
    if severity is not None and authoritative_severity is None:
        notes.append("This subject has no authoritative severity; the model's severity is advisory only.")
        severity = severity.model_copy(update={"agrees_with_stored": None})
    elif severity is not None:
        downward = RANK[severity.proposed] < RANK[authoritative_severity]
        upward = RANK[severity.proposed] > RANK[authoritative_severity]
        update = {"agrees_with_stored": severity.proposed == authoritative_severity}
        if downward:
            update["uncertainty"] = "high"
            limitations.append(f"The model proposed {severity.proposed}, lower than the Wazuh severity {authoritative_severity}. "
                               "The Wazuh detection is authoritative and stands; an analyst decides.")
            notes.append("Severity disagreement (lower than Wazuh): flagged, uncertainty raised to high; nothing changed.")
        elif upward:
            notes.append("The model proposed a higher severity than Wazuh: advisory only, for analyst review.")
        severity = severity.model_copy(update=update)

    cap = MODEL_CONFIDENCE_CEILING
    if downward or dropped or len(bundle.evidence) < 3:
        cap = "low"
    confidence = out.confidence if CONF[out.confidence] <= CONF[cap] else cap
    if confidence != out.confidence:
        notes.append(f"Confidence lowered from {out.confidence} to {confidence} by the conservative confidence policy.")

    gaps = missing_evidence_for(bundle)
    model_gaps = [g for g in out.missing_evidence if g.strip()]
    if len(model_gaps) < 2:
        notes.append("The model's missing-evidence assessment was inadequate; the deterministic checker's gaps were added.")
    merged = list(dict.fromkeys([*model_gaps, *gaps]))

    cited = {c for s in keep_s for c in s.citation_ids} | {c for r in keep_r for c in r.citation_ids} | \
            (set(severity.citation_ids) if severity else set())
    citations = [Citation(citation_id=e.citation_id, ref=e.ref, excerpt=e.excerpt[:1000]) for e in bundle.evidence
                 if e.citation_id in cited or e.citation_id == "E1"]
    return NhaiResult(id=result_id or uuid.uuid4(), task=bundle.task, subject=bundle.subject, status="draft",
                      model=ModelRef(name=model), summary=out.summary, statements=keep_s, recommendations=keep_r,
                      citations=citations, confidence=confidence, limitations=limitations[:20],
                      unsupported_statements_dropped=dropped, generated_at=datetime.now(timezone.utc), latency_ms=latency_ms,
                      severity_assessment=severity, missing_evidence=merged[:30], validation_notes=notes)


def output_schema() -> dict:
    """The JSON schema given to the model (Ollama `format`)."""
    return ModelOutput.model_json_schema()

