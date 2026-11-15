"""NHAI (Novr Human-Assisted Intelligence) and AI Gateway contract invariants."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from novrsoc_contracts.v1 import ai_gateway as gw
from novrsoc_contracts.v1 import nhai
from novrsoc_contracts.v1.common import ActorRef, ResourceRef

NOW = datetime.now(timezone.utc)
SUBJ = ResourceRef(type="alert", id="a-1")
CIT = [nhai.Citation(citation_id="E1", ref=ResourceRef(type="alert", id="a-1"), excerpt="rule 5710 sshd brute force")]


def result(**kw):
    base = dict(id=uuid.uuid4(), task="alert_explanation", subject=SUBJ, model=nhai.ModelRef(name="qwen3:4b"),
                summary="Repeated SSH failures from one source.", citations=CIT, confidence="medium",
                generated_at=NOW, latency_ms=900,
                statements=[nhai.Statement(text="42 failed logins in 5 minutes", citation_ids=["E1"])])
    base.update(kw)
    return nhai.NhaiResult(**base)


def test_principle_and_candidate_models_are_declared():
    assert nhai.NHAI_NAME == "Novr Human-Assisted Intelligence"
    assert nhai.NHAI_CANDIDATE_MODELS == ("qwen3:4b", "qwen2.5:3b")


def test_nhai_requests_never_carry_an_organisation():
    for m in (nhai.AlertExplanationRequest, nhai.BehaviouralInsightSummaryRequest, nhai.InvestigationAssistRequest,
              nhai.CaseNoteDraftRequest):
        assert not ({"org_id", "organization_id", "tenant_id"} & set(m.model_fields)), m.__name__
    with pytest.raises(ValidationError):
        nhai.AlertExplanationRequest(alert_id=uuid.uuid4(), org_id=str(uuid.uuid4()))


def test_every_statement_cites_evidence_present_in_the_result():
    result()
    with pytest.raises(ValidationError, match="cites evidence not in the result"):
        result(statements=[nhai.Statement(text="claim", citation_ids=["E7"])])
    with pytest.raises(ValidationError):
        nhai.Statement(text="uncited claim", citation_ids=[])


def test_ungrounded_model_output_is_dropped_and_counted():
    bundle = nhai.ContextBundle(bundle_id=uuid.uuid4(), org_id=uuid.uuid4(), task="alert_explanation", subject=SUBJ,
                                evidence=[nhai.EvidenceItem(citation_id="E1", ref=SUBJ, excerpt="x")],
                                assembled_at=NOW, assembled_for=uuid.uuid4())
    out = nhai.ModelOutput(summary="s", confidence="low", statements=[
        nhai.Statement(text="grounded", citation_ids=["E1"]), nhai.Statement(text="invented", citation_ids=["E9"])])
    st, rc, dropped = nhai.ground(out, bundle)
    assert [s.text for s in st] == ["grounded"] and dropped == 1
    with pytest.raises(ValidationError, match="unique"):
        nhai.ContextBundle(**{**bundle.model_dump(), "evidence": [bundle.evidence[0], bundle.evidence[0]]})


def test_ai_never_executes_and_consequential_actions_need_human_approval():
    with pytest.raises(ValidationError, match="human approval"):
        nhai.Recommendation(text="block the source", citation_ids=["E1"], action="block_ip", requires_human_approval=False)
    r = nhai.Recommendation(text="block the source", citation_ids=["E1"], action="block_ip", requires_human_approval=True)
    assert r.executes_automatically is False
    with pytest.raises(ValidationError):
        nhai.Recommendation(text="x", citation_ids=["E1"], requires_human_approval=False, executes_automatically=True)


def test_results_are_drafts_until_a_named_human_reviews_them():
    assert result().status == "draft"
    with pytest.raises(ValidationError, match="human review"):
        result(status="accepted")
    reviewer = ActorRef(type="user", id=uuid.uuid4())
    ok = result(status="accepted", review=nhai.HumanReview(reviewer=reviewer, decision="accept", reviewed_at=NOW))
    assert ok.review.reviewer.type == "user"
    with pytest.raises(ValidationError, match="named human"):
        nhai.HumanReview(reviewer=ActorRef(type="service", id=uuid.uuid4()), decision="accept", reviewed_at=NOW)
    with pytest.raises(ValidationError, match="status must match"):
        result(status="accepted", review=nhai.HumanReview(reviewer=reviewer, decision="reject", note="wrong", reviewed_at=NOW))


def test_gateway_keys_serve_one_lane_and_tenant_binding_follows_the_lane():
    q = gw.Quota(requests_per_minute=30, tokens_per_day=50_000, max_concurrency=1)
    with pytest.raises(ValidationError, match="exactly one lane"):
        gw.GatewayKeyCreate(name="worker", scopes=["inference:general", "analysis:security"], allowed_models=["qwen3:4b"],
                            quota=q, expires_at=NOW + timedelta(days=30), purpose="internal enrichment worker")
    base = dict(key_id=uuid.uuid4(), name="k", prefix="ngk_0123abcd", allowed_models=["qwen3:4b"], quota=q,
                created_by=uuid.uuid4(), created_at=NOW, expires_at=NOW + timedelta(days=1))
    with pytest.raises(ValidationError, match="bound to exactly one organisation"):
        gw.GatewayKey(**base, lane="security_analysis", org_id=None)
    with pytest.raises(ValidationError, match="carries no organisation"):
        gw.GatewayKey(**base, lane="general", org_id=uuid.uuid4())
    with pytest.raises(ValidationError):
        gw.GatewayKeyIssued(key_id=uuid.uuid4(), key="sk-plaintext", expires_at=NOW)


def test_usage_events_are_attributed_and_never_hold_prompt_text():
    assert not ({"prompt", "messages", "text", "output"} & set(gw.UsageEvent.model_fields))
    with pytest.raises(ValidationError, match="attributed to a key or a user"):
        gw.UsageEvent(request_id="r", occurred_at=NOW, lane="general", model="qwen2.5:3b", outcome="ok")
    with pytest.raises(ValidationError, match="organisation"):
        gw.UsageEvent(request_id="r", occurred_at=NOW, lane="security_analysis", model="qwen3:4b", outcome="ok", user_id=uuid.uuid4())
    with pytest.raises(ValidationError, match="reject_reason"):
        gw.UsageEvent(request_id="r", occurred_at=NOW, lane="general", model="m:1", outcome="rejected", key_id=uuid.uuid4())


def test_general_inference_cannot_smuggle_tenant_context():
    assert not ({"org_id", "context", "evidence", "case_id", "alert_id"} & set(gw.GeneralInferenceRequest.model_fields))
    with pytest.raises(ValidationError):
        gw.GeneralInferenceRequest(model="qwen2.5:3b", messages=[{"role": "user", "content": "hi"}], org_id=str(uuid.uuid4()))
    with pytest.raises(ValidationError):
        gw.GeneralInferenceRequest(model="qwen2.5:3b", messages=[{"role": "user", "content": "hi"}], max_tokens=100_000)
