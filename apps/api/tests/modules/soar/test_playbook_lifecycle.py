"""Playbook lifecycle (no run before approval, no self-approval, validation errors block approval, versions retire),
execution policy limits, the emergency stop, the operations centre and the AI activity record."""
import uuid

from sqlalchemy import text

from app.connectors.inference import TestInferenceAdapter
from app.main import create_app
from tests.conftest import audit_actions
from tests.modules.conftest import Client
from tests.modules.nhai.test_nhai import drain
from tests.modules.soar.test_soar_engine import PLAYBOOK, approve_playbook


def _case(a):
    alert = next(x for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"] if x["rule_id"] == "5712")
    return a.post("/api/v1/soc/cases", {"alert_ids": [alert["id"]], "title": "Lifecycle case", "severity": "high", "source": "alert",
                                        "source_id": f"lc-{uuid.uuid4().hex}"}).json()["case_id"]


def _run(a, pb, case, mode="dry_run"):
    return a.post("/api/v1/soar/runs", {"idempotency_key": f"run-{uuid.uuid4().hex}", "playbook_id": pb["id"], "playbook_version": pb["version"],
                                        "case_id": case, "mode": mode, "justification": "Contain the brute force source."})


def test_draft_cannot_run_and_the_author_cannot_approve(as_user, world, fixture_alerts, owner):
    m, a, admin = as_user("manager"), as_user("analyst_a"), as_user("admin")
    pb = m.post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": f"lc-{uuid.uuid4().hex[:6]}"}, org=world.alpha).json()
    assert pb["status"] == "draft" and pb["validation"]["valid"] is True and pb["validation"]["warnings"]
    case = _case(a)
    r = _run(a, pb, case)
    assert r.status_code == 409 and r.json()["error"]["code"] == "playbook_not_approved"
    assert m.post(f"/api/v1/soar/playbooks/{pb['id']}/submit", {}, org=world.alpha).status_code == 409        # not validated yet
    m.post(f"/api/v1/soar/playbooks/{pb['id']}/validate", {}, org=world.alpha)
    m.post(f"/api/v1/soar/playbooks/{pb['id']}/submit", {}, org=world.alpha)
    self_ = m.post(f"/api/v1/soar/playbooks/{pb['id']}/review", {"decision": "approve", "note": "my own"}, org=world.alpha)
    assert self_.status_code == 403
    assert "SOAR_PLAYBOOK_SELF_APPROVAL_REFUSED" in {e["action"] for e in audit_actions(owner, org=world.alpha)}
    rej = admin.post(f"/api/v1/soar/playbooks/{pb['id']}/review", {"decision": "reject", "note": "Add an enrichment step first."},
                     org=world.alpha).json()
    assert rej["status"] == "draft" and rej["review_note"].startswith("Add")
    v1 = approve_playbook(m, admin, pb, org=world.alpha)
    assert v1["approved_by"]["label"].startswith("admin@") and _run(a, v1, case).status_code == 201
    v2 = m.post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": pb["name"], "title": "Contain SSH brute force (v2)"}, org=world.alpha).json()
    assert v2["version"] == 2 and v2["status"] == "draft"
    approve_playbook(m, admin, v2, org=world.alpha)
    versions = {v["version"]: v["status"] for v in a.get(f"/api/v1/soar/playbooks/{pb['name']}/versions").json()["items"]}
    assert versions == {2: "approved", 1: "retired"}
    assert _run(a, v1, case).json()["error"]["code"] == "playbook_not_approved"          # a retired version no longer runs


def test_validation_errors_block_submission(as_user, world):
    m = as_user("manager")
    bad = {**PLAYBOOK, "name": f"bad-{uuid.uuid4().hex[:6]}", "steps": [{"step_key": "disable", "action": "disable_account"}]}
    pb = m.post("/api/v1/soar/playbooks", bad, org=world.alpha).json()
    assert pb["validation"]["valid"] is False and "account" in pb["validation"]["errors"][0]
    assert m.post(f"/api/v1/soar/playbooks/{pb['id']}/validate", {}, org=world.alpha).json()["status"] == "draft"
    assert m.post(f"/api/v1/soar/playbooks/{pb['id']}/submit", {}, org=world.alpha).status_code == 409


def test_execution_policy_limits_and_emergency_stop(as_user, world, fixture_alerts, owner):
    m, a, admin = as_user("manager"), as_user("analyst_a"), as_user("admin")
    m.put("/api/v1/soar/policy", {"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"], "max_runs_per_hour": 500},
          org=world.alpha)
    only_dry = m.post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": f"dry-{uuid.uuid4().hex[:6]}",
                                                 "execution_policy": {"modes": ["dry_run"], "min_case_severity": "high"}}, org=world.alpha).json()
    only_dry = approve_playbook(m, admin, only_dry, org=world.alpha)
    case = _case(a)
    r = _run(a, only_dry, case, mode="live")
    assert r.status_code == 409 and r.json()["error"]["code"] == "mode_not_allowed"
    low_alert = a.get("/api/v1/soc/alerts?limit=200").json()["items"][-1]["id"]
    low = a.post("/api/v1/soc/cases", {"alert_ids": [low_alert], "title": "Low case", "severity": "low", "source": "alert",
                                       "source_id": f"low-{uuid.uuid4().hex}"}).json()["case_id"]
    assert _run(a, only_dry, low).json()["error"]["code"] == "severity_below_policy"
    run = _run(a, only_dry, case).json()
    approval = next(s["approval_id"] for s in run["steps"] if s["step_key"] == "block")
    assert a.post("/api/v1/soar/emergency-stop", {"active": True, "reason": "Analyst cannot stop"}).status_code == 403
    on = m.post("/api/v1/soar/emergency-stop", {"active": True, "reason": "Suspected misfire during an incident"}, org=world.alpha).json()
    assert on["emergency_stop"] is True
    stopped = _run(a, only_dry, case)
    assert stopped.status_code == 409 and stopped.json()["error"]["code"] == "emergency_stop"
    blocked = admin.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "Approve the block"}, org=world.alpha)
    assert blocked.status_code == 409 and blocked.json()["error"]["code"] == "emergency_stop"
    ops = a.get("/api/v1/soar/operations").json()
    assert ops["emergency_stop"] is True and ops["awaiting_approval"] >= 1 and ops["human_intervention"] >= 1
    assert any(t["action"] == "SOAR_EMERGENCY_STOP" and t["category"] == "policy" for t in ops["timeline"])
    m.post("/api/v1/soar/emergency-stop", {"active": False, "reason": "Incident reviewed, resuming"}, org=world.alpha)
    assert _run(a, only_dry, case).status_code == 201
    m.put("/api/v1/soar/policy", {"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"], "max_runs_per_hour": 1},
          org=world.alpha)
    limited = _run(a, only_dry, case)
    assert limited.status_code == 429 and limited.json()["error"]["code"] == "run_limit"
    m.put("/api/v1/soar/policy", {"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"], "max_runs_per_hour": 500},
          org=world.alpha)
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"SOAR_EMERGENCY_STOP", "SOAR_EMERGENCY_STOP_LIFTED", "SOAR_RUN_REFUSED"} <= acts


def test_ai_activity_is_recorded_and_kept_apart_from_execution(fixture_settings, fixture_alerts, app_engine, world):
    app = create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))
    a = Client(app, "analyst_a")
    alert = a.get("/api/v1/soc/alerts?limit=200").json()["items"][2]["id"]
    job = a.post("/api/v1/nhai/alert-explanations", {"alert_id": alert}).json()
    assert "succeeded" in drain(app_engine, fixture_settings, TestInferenceAdapter())
    items = [i for i in a.get("/api/v1/soar/ai-activity?limit=200").json()["items"] if i["nhai_job_id"] == job["id"]]
    kinds = {i["kind"] for i in items}
    assert {"analysis_requested", "analysis_completed", "recommendation"} <= kinds
    rec = next(i for i in items if i["kind"] == "recommendation")
    assert rec["details"]["executes_automatically"] is False and rec["details"]["requires_human_approval"] is True
    assert a.post(f"/api/v1/nhai/jobs/{job['id']}/review", {"decision": "accept", "note": "Matches the log."}).status_code == 200
    assert any(i["kind"] == "review" and i["nhai_job_id"] == job["id"] for i in a.get("/api/v1/soar/ai-activity?kind=review").json()["items"])
    ops = a.get("/api/v1/soar/operations").json()
    assert any(t["category"] == "ai_analysis" for t in ops["timeline"])
    assert all(t["category"] != "execution" or not t["action"].startswith("AI_") for t in ops["timeline"])
    assert Client(app, "manager_b").get("/api/v1/soar/ai-activity").json()["items"] == [] or \
        all(i["nhai_job_id"] != job["id"] for i in Client(app, "manager_b").get("/api/v1/soar/ai-activity").json()["items"])
    with app_engine.connect() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, false)"), {"v": str(world.alpha)})
        try:
            c.execute(text("UPDATE novrsoc.ai_activity SET summary = 'tampered'"))
            raise AssertionError("ai_activity must be append-only")
        except Exception as e:
            assert "permission denied" in str(e) or "append-only" in str(e)
