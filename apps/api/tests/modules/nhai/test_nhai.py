"""NHAI engine (Phase 5, workstream F): deterministic validation, asynchronous jobs, review, isolation, timeouts.
Inference is the deterministic TestInferenceAdapter or scripted outputs; no real model is contacted."""
import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.ai_gateway.core import Gateway
from app.connectors.base import ConnectorUnavailable
from app.connectors.inference import TestInferenceAdapter
from app.main import create_app
from app.nhai import worker
from app.nhai.validate import OutputRejected, validate
from novrsoc_contracts.v1.ai_gateway import Lane, LanePolicy
from novrsoc_contracts.v1.common import ResourceRef
from novrsoc_contracts.v1.nhai import ContextBundle, EvidenceItem, NhaiTask
from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation
from tests.modules.conftest import Client

E1 = json.dumps({"rule_id": "5710", "rule_level": 10, "rule_description": "sshd: non-existent user", "siem_severity_authoritative": "high",
                 "agent_id": "001", "agent_name": "alpha-web-01", "agent_groups": ["nv-alpha-servers"], "source_ip": "203.0.113.50",
                 "mitre_techniques": ["T1110"], "observed_at": "2026-11-10T09:00:00+00:00"})


def bundle(n_items=4):
    items = [EvidenceItem(citation_id="E1", ref=ResourceRef(type="alert", id=str(uuid.uuid4())), excerpt=E1),
             EvidenceItem(citation_id="E2", ref=ResourceRef(type="alert_log", id="x"), excerpt="sshd: Invalid user admin from 203.0.113.50"),
             EvidenceItem(citation_id="E3", ref=ResourceRef(type="observables", id="x"), excerpt="ipv4=203.0.113.50 (from src_ip)"),
             EvidenceItem(citation_id="E4", ref=ResourceRef(type="correlation", id="001:5710"), excerpt="3 other alert(s) ...")][:n_items]
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=uuid.uuid4(), task=NhaiTask.ALERT_EXPLANATION,
                         subject=ResourceRef(type="alert", id="a"), evidence=items, assembled_at=datetime.now(timezone.utc),
                         assembled_for=uuid.uuid4())


def out(**kw):
    base = {"summary": "Repeated SSH login attempts with a non-existent user from 203.0.113.50.",
            "statements": [{"text": "The source 203.0.113.50 tried user admin.", "citation_ids": ["E2"]}],
            "recommendations": [], "confidence": "high", "limitations": [],
            "severity_assessment": {"proposed": "low", "rationale": "Single failed attempt.", "citation_ids": ["E2"], "uncertainty": "low"},
            "missing_evidence": []}
    base.update(kw)
    return json.dumps(base)


# ---------------------------------------------------------------- deterministic validation
def test_benchmark_case_low_severity_high_confidence_is_contained():
    """The Server 1 benchmark: valid JSON, low severity with high confidence, inadequate missing-evidence list."""
    r = validate(out(), bundle(), authoritative_severity="high", model="qwen2.5:3b", latency_ms=80_820)
    sa = r.severity_assessment
    assert sa.proposed == "low" and sa.agrees_with_stored is False and sa.uncertainty == "high"
    assert r.confidence == "low"                                         # never high; low when it disagrees downward
    assert any("NovrSIEM detection is authoritative" in x for x in r.limitations)
    assert len(r.missing_evidence) >= 3 and any("Endpoint context" in g for g in r.missing_evidence)
    assert any("inadequate" in n for n in r.validation_notes) and any("Confidence lowered" in n for n in r.validation_notes)
    assert r.status == "draft" and r.review is None


def test_confidence_ceiling_and_agreement():
    r = validate(out(severity_assessment={"proposed": "high", "rationale": "Brute force pattern.", "citation_ids": ["E1", "E4"],
                                          "uncertainty": "medium"}), bundle(), authoritative_severity="high", model="m", latency_ms=1)
    assert r.confidence == "medium" and r.severity_assessment.agrees_with_stored is True
    thin = validate(out(confidence="medium", severity_assessment=None), bundle(2), authoritative_severity="high", model="m", latency_ms=1)
    assert thin.confidence == "low"                                      # fewer than 3 evidence items


def test_fabricated_indicators_are_refused():
    with pytest.raises(OutputRejected) as e:
        validate(out(summary="Traffic to 198.51.100.66 and evil-c2.example.com was seen."), bundle(),
                 authoritative_severity="high", model="m", latency_ms=1)
    assert e.value.code == "ungrounded_ioc"
    r = validate(out(statements=[{"text": "Also contacted 192.0.2.99.", "citation_ids": ["E2"]},
                                 {"text": "Source was 203.0.113.50.", "citation_ids": ["E3"]}]), bundle(),
                 authoritative_severity="high", model="m", latency_ms=1)
    assert [s.text for s in r.statements] == ["Source was 203.0.113.50."] and r.unsupported_statements_dropped == 1


def test_uncited_items_are_dropped_and_schema_is_strict():
    r = validate(out(statements=[{"text": "Unsupported claim.", "citation_ids": ["E9"]}]), bundle(),
                 authoritative_severity="high", model="m", latency_ms=1)
    assert r.statements == [] and r.unsupported_statements_dropped == 1
    for bad in ("not json", "[1, 2]", out(extra_field=1), out(confidence="certain"),
                out(recommendations=[{"text": "Isolate the host.", "citation_ids": ["E1"], "action": "isolate_agent",
                                      "requires_human_approval": False}])):
        with pytest.raises(OutputRejected) as e:
            validate(bad, bundle(), authoritative_severity="high", model="m", latency_ms=1)
        assert e.value.code == "invalid_model_output"
    fenced = validate("```json\n" + out() + "\n```", bundle(), authoritative_severity="high", model="m", latency_ms=1)
    assert fenced.summary


def test_recommendations_never_execute():
    r = validate(out(recommendations=[{"text": "Block the source after review.", "citation_ids": ["E3"], "action": "block_ip",
                                       "requires_human_approval": True}]), bundle(), authoritative_severity="high", model="m", latency_ms=1)
    assert r.recommendations[0].requires_human_approval is True and r.recommendations[0].executes_automatically is False


# ---------------------------------------------------------------- jobs, worker, review
@pytest.fixture(scope="module")
def nhai_app(fixture_settings):
    return create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))


def gw(backend, timeout=60):
    return Gateway(backend, policies={Lane.SECURITY_ANALYSIS: LanePolicy(
        lane=Lane.SECURITY_ANALYSIS, allowed_models=[TestInferenceAdapter.MODEL], timeout_seconds=timeout,
        max_input_chars=64_000, max_output_tokens=384, max_concurrency=1)})


def drain(app_engine, settings, backend, timeout=60):
    statuses = []
    while (s := worker.run_once(app_engine, settings, gw(backend, timeout), TestInferenceAdapter.MODEL, "test-worker")) is not None:
        statuses.append(s)
    return statuses


def _alpha_alert(c):
    return c.get("/api/v1/soc/alerts?limit=200").json()["items"][0]["id"]


def test_alert_explanation_job_lifecycle_review_and_audit(nhai_app, fixture_alerts, fixture_settings, app_engine, owner, world):
    a = Client(nhai_app, "analyst_a")
    alert_id = _alpha_alert(a)
    r = a.post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id})
    assert r.status_code == 202 and r.json()["status"] == "queued"
    job_id = r.json()["id"]
    again = a.post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id})
    assert again.status_code == 200 and again.json()["id"] == job_id      # one active job per subject
    with owner.begin() as c:
        stored = c.execute(text("SELECT bundle FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": job_id}).scalar()
    assert stored["org_id"] == str(world.alpha) and stored["evidence"][0]["citation_id"] == "E1"
    assert "hunter2" not in json.dumps(stored)
    assert "succeeded" in drain(app_engine, fixture_settings, TestInferenceAdapter())
    job = a.get(f"/api/v1/nhai/jobs/{job_id}").json()
    res = job["result"]
    assert job["status"] == "succeeded" and res["status"] == "draft" and res["model"]["name"] == "test-adapter"
    assert res["confidence"] == "low" and res["missing_evidence"] and res["citations"][0]["citation_id"] == "E1"
    assert any("not a model analysis" in x for x in res["limitations"])
    assert a.post(f"/api/v1/nhai/jobs/{job_id}/review", {"decision": "reject", "note": ""}).status_code == 422
    rv = a.post(f"/api/v1/nhai/jobs/{job_id}/review", {"decision": "accept", "note": "Matches the log."})
    assert rv.status_code == 200 and rv.json()["result"]["status"] == "accepted"
    assert rv.json()["result"]["review"]["reviewer"]["id"] == str(world.users["analyst_a"])
    assert a.post(f"/api/v1/nhai/jobs/{job_id}/review", {"decision": "accept"}).status_code == 409
    actions = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"NHAI_JOB_QUEUED", "NHAI_JOB_FINISHED", "NHAI_RESULT_REVIEWED"} <= actions


def test_isolation_and_permissions(nhai_app, fixture_alerts):
    a, b = Client(nhai_app, "analyst_a"), Client(nhai_app, "manager_b")
    alert_id = _alpha_alert(a)
    job_id = a.post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id}).json()["id"]
    assert b.get(f"/api/v1/nhai/jobs/{job_id}").status_code == 404
    assert b.post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id}).status_code == 404   # alpha's alert
    assert all(j["id"] != job_id for j in b.get("/api/v1/nhai/jobs").json()["items"])
    assert Client(nhai_app, "exec_a").get("/api/v1/nhai/jobs").status_code == 403
    assert Client(nhai_app, "portal_a").post("/api/v1/nhai/alert-explanations", {"alert_id": alert_id}).status_code == 403
    assert b.post(f"/api/v1/nhai/jobs/{job_id}/review", {"decision": "accept"}).status_code == 404


def test_unconfigured_backend_refuses_honestly(fixture_app, fixture_alerts, as_user):
    r = as_user("analyst_a").post("/api/v1/nhai/alert-explanations", {"alert_id": _alpha_alert(as_user("analyst_a"))})
    assert r.status_code == 503 and r.json()["error"]["code"] == "integration_unconfigured"


def _fresh_job(nhai_app, owner):
    a = Client(nhai_app, "analyst_a")
    with owner.begin() as c:   # finish any active job so a new one can be queued for the same alert
        c.execute(text("UPDATE novrsoc.nhai_jobs SET status = 'failed', error_code = 'test_reset', lease_until = NULL "
                       "WHERE status IN ('queued', 'running')"))
    return a.post("/api/v1/nhai/alert-explanations", {"alert_id": _alpha_alert(a)}).json()["id"]


def _status(owner, job_id):
    with owner.begin() as c:
        return tuple(c.execute(text("SELECT status, error_code, attempts FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": job_id}).one())


def test_timeout_retries_then_times_out(nhai_app, fixture_alerts, fixture_settings, app_engine, owner):
    job_id = _fresh_job(nhai_app, owner)
    slow = TestInferenceAdapter(delay_seconds=1.5)
    assert worker.run_once(app_engine, fixture_settings, gw(slow, timeout=1), TestInferenceAdapter.MODEL, "w") == "queued"
    assert worker.run_once(app_engine, fixture_settings, gw(slow, timeout=1), TestInferenceAdapter.MODEL, "w") == "timed_out"
    assert _status(owner, job_id) == ("timed_out", "timeout", 2)


def test_backend_unavailable_retries_then_fails_and_bad_output_fails(nhai_app, fixture_alerts, fixture_settings, app_engine, owner):
    job_id = _fresh_job(nhai_app, owner)
    down = TestInferenceAdapter(fail=ConnectorUnavailable("OLLAMA could not be reached"))
    assert drain(app_engine, fixture_settings, down) == ["queued", "failed"]
    assert _status(owner, job_id)[:2] == ("failed", "backend_unavailable")
    job2 = _fresh_job(nhai_app, owner)
    liar = TestInferenceAdapter(script=out(summary="Beaconing to 198.51.100.200 detected."))
    assert drain(app_engine, fixture_settings, liar) == ["failed"]
    assert _status(owner, job2)[:2] == ("failed", "ungrounded_ioc")


def test_lease_expiry_requeues_and_deadline_times_out(nhai_app, fixture_alerts, app_engine, owner):
    job_id = _fresh_job(nhai_app, owner)
    with app_engine.begin() as c:
        claimed = c.execute(text("SELECT job_id FROM novrsoc.nhai_claim_job('crashed-worker', 60)")).scalar()
    assert str(claimed) == job_id
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.nhai_jobs SET lease_until = now() - interval '1 second' WHERE id = :i"), {"i": job_id})
    with app_engine.begin() as c:
        c.execute(text("SELECT novrsoc.nhai_expire_jobs()"))
    assert _status(owner, job_id)[0] == "queued"
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.nhai_jobs SET deadline_at = now() - interval '1 second' WHERE id = :i"), {"i": job_id})
    with app_engine.begin() as c:
        c.execute(text("SELECT novrsoc.nhai_expire_jobs()"))
    assert _status(owner, job_id)[:2] == ("timed_out", "deadline_exceeded")


def test_jobs_are_tenant_isolated(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.nhai_jobs", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "task": "alert_explanation", "subject_type": "alert",
                                                  "subject_id": str(uuid.uuid4()), "requested_by": world.users["analyst_a"],
                                                  "deadline_at": datetime.now(timezone.utc) + timedelta(hours=1), "bundle": "{}"},
                            update_set="error_code = 'tampered'")
