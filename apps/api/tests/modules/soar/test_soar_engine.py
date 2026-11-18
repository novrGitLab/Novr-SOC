"""SOAR engine (Server 2) with the real bridge code in-process (simulated adapter: nothing is executed).
Covers policy authorization, evidence-bound targets, approvals (permission, no self-approval, expiry), dispatch with
signed receipts, idempotent re-dispatch, live-mode gating and cross-tenant denial at the API and at the bridge."""
import importlib
import json
import sys
import uuid
from pathlib import Path

import httpx
import pytest
from sqlalchemy import text

from app.soar import bridge_client
from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation

BRIDGE_DIR = Path(__file__).resolve().parents[5] / "services" / "edge" / "response_bridge"
sys.path.insert(0, str(BRIDGE_DIR))
bridge_core = importlib.import_module("novrsoc_bridge.core")
KEY = b"s" * 48


@pytest.fixture
def bridge(monkeypatch, world):
    """An in-process Server 1 bridge authorizing ONLY alpha's servers group, behind a fake network."""
    adapter = bridge_core.SimulatedAdapter({"001": ["nv-alpha-servers"], "002": ["nv-alpha-servers"], "004": ["nv-beta-servers"]})
    cfg = {"actions": ["block_ip", "isolate_agent"], "never_block": [],
           "tenants": {str(world.alpha): {"actions": ["block_ip", "isolate_agent"], "agent_groups": ["nv-alpha-servers"]}}}
    b = bridge_core.Bridge(cfg, {"server2-soar": KEY}, adapter)
    state = {"down": False}

    def handler(req: httpx.Request):
        if state["down"]:
            raise httpx.ConnectError("bridge down", request=req)
        status, headers, body = b.handle(dict(req.headers), req.content)
        return httpx.Response(status, headers=headers, content=body)
    monkeypatch.setattr(bridge_client, "factory", lambda settings: bridge_client.BridgeClient(
        "http://127.0.0.1:8650", "server2-soar", KEY, transport=httpx.MockTransport(handler)))
    return adapter, state


PLAYBOOK = {"name": "", "title": "Contain SSH brute force source", "triggers": {"rule_ids": ["5712"], "min_level": 7},
            "steps": [{"step_key": "enrich", "action": "enrich_iocs"}, {"step_key": "task", "action": "create_task", "parameters": {"title": "Review auth logs"}},
                      {"step_key": "notify", "action": "notify_email"}, {"step_key": "block", "action": "block_ip"}],
            "execution_policy": {"modes": ["dry_run", "live"]}}


def approve_playbook(author, approver, pb, org=None):
    """Consolidation lifecycle: the author validates and submits; ANOTHER soar:manage holder approves."""
    v = author.post(f"/api/v1/soar/playbooks/{pb['id']}/validate", {}, org=org)
    assert v.status_code == 200 and v.json()["status"] == "validated", v.text
    s = author.post(f"/api/v1/soar/playbooks/{pb['id']}/submit", {}, org=org)
    assert s.status_code == 200 and s.json()["status"] == "pending_approval", s.text
    r = approver.post(f"/api/v1/soar/playbooks/{pb['id']}/review", {"decision": "approve", "note": "Steps and policy reviewed."}, org=org)
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    return r.json()


def _setup(as_user, world, fixture_alerts, *, actions=("block_ip",), groups=("nv-alpha-servers",), live=False):
    m, a = as_user("manager"), as_user("analyst_a")
    assert m.c.put("/api/v1/soar/policy", json={"allowed_actions": list(actions), "allowed_agent_groups": list(groups),
                                                "live_enabled": live, "approval_ttl_minutes": 60},
                   headers={"X-CSRF-Token": m.csrf, "X-Org-Id": str(world.alpha)}).status_code == 200
    pb = m.post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": f"ssh-{uuid.uuid4().hex[:6]}"}, org=world.alpha).json()
    pb = approve_playbook(m, as_user("admin"), pb, org=world.alpha)
    alert = next(x for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"] if x["rule_id"] == "5712")
    case = a.post("/api/v1/soc/cases", {"alert_ids": [alert["id"]], "title": "SSH brute force", "severity": "high",
                                        "source": "alert", "source_id": f"soar-{uuid.uuid4().hex}"}).json()["case_id"]
    return m, a, pb, case


def _run(a, pb, case, mode="dry_run"):
    return a.post("/api/v1/soar/runs", {"idempotency_key": f"run-{uuid.uuid4().hex}", "playbook_id": pb["id"],
                                        "playbook_version": pb["version"], "case_id": case, "mode": mode,
                                        "justification": "Source is brute forcing SSH on a production server."})


def test_recommendation_approval_and_simulated_receipt(bridge, as_user, world, fixture_alerts, owner):
    adapter, _ = bridge
    m, a, pb, case = _setup(as_user, world, fixture_alerts)
    rec = a.get(f"/api/v1/soar/recommendations?case_id={case}").json()["items"]
    mine = next(r for r in rec if r["playbook"]["id"] == pb["id"])
    assert mine["proposed_targets"] == {"block": "203.0.113.45"} and "rule 5712" in mine["matched_on"][0]
    run = _run(a, pb, case).json()
    states = {s["step_key"]: s["state"] for s in run["steps"]}
    assert states == {"enrich": "succeeded", "task": "succeeded", "notify": "skipped_not_configured", "block": "awaiting_approval"}
    assert run["state"] == "awaiting_approval" and adapter.executed == []
    approval = next(s["approval_id"] for s in run["steps"] if s["step_key"] == "block")
    assert a.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "looks fine"}).status_code == 403  # analyst
    done = m.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "Confirmed in logs"}, org=world.alpha).json()
    block = next(s for s in done["steps"] if s["step_key"] == "block")
    assert block["state"] == "dry_run" and block["receipt"]["status"] == "dry_run" and block["receipt"]["adapter"] == "simulated"
    assert done["state"] == "succeeded" and adapter.executed == []                     # dry run: nothing executed
    assert m.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "again"}, org=world.alpha).status_code == 409
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"SOAR_RUN_REQUESTED", "SOAR_APPROVAL_REQUESTED", "SOAR_APPROVAL_DECIDED", "SOAR_STEP_EXECUTED"} <= acts


def test_live_mode_needs_policy_then_executes_once_on_the_simulated_adapter(bridge, as_user, world, fixture_alerts, owner):
    adapter, state = bridge
    m, a, pb, case = _setup(as_user, world, fixture_alerts)
    refused = _run(a, pb, case, mode="live").json()
    assert next(s for s in refused["steps"] if s["step_key"] == "block")["state"] == "refused_by_policy"
    assert "SOAR_LIVE_REFUSED" in {e["action"] for e in audit_actions(owner, org=world.alpha)}
    m, a, pb, case = _setup(as_user, world, fixture_alerts, live=True)
    run = _run(a, pb, case, mode="live").json()
    approval = next(s["approval_id"] for s in run["steps"] if s["step_key"] == "block")
    state["down"] = True                                                               # bridge unreachable
    pending = m.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "Contain now"}, org=world.alpha).json()
    step = next(s for s in pending["steps"] if s["step_key"] == "block")
    assert step["state"] == "dispatched" and pending["state"] == "running" and adapter.executed == []
    state["down"] = False
    again = m.post(f"/api/v1/soar/steps/{step['id']}/dispatch", {}, org=world.alpha).json()
    step2 = next(s for s in again["steps"] if s["step_key"] == "block")
    assert step2["state"] == "succeeded" and step2["receipt"]["status"] == "executed" and step2["request_id"] == step["request_id"]
    assert len(adapter.executed) == 1 and adapter.executed[0]["arguments"] == ["203.0.113.45"]


def test_no_self_approval_expiry_and_policy_refusals(bridge, as_user, world, fixture_alerts, owner):
    m, a, pb, case = _setup(as_user, world, fixture_alerts)
    own = m.post("/api/v1/soar/runs", {"idempotency_key": f"run-{uuid.uuid4().hex}", "playbook_id": pb["id"], "playbook_version": 1,
                                       "case_id": case, "justification": "Manager runs and tries to approve it."}, org=world.alpha).json()
    approval = next(s["approval_id"] for s in own["steps"] if s["step_key"] == "block")
    r = m.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "mine"}, org=world.alpha)
    assert r.status_code == 403 and "Self-approval" in r.json()["error"]["message"]
    run = _run(a, pb, case).json()
    ap2 = next(s["approval_id"] for s in run["steps"] if s["step_key"] == "block")
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.soar_approvals SET expires_at = now() - interval '1 minute' WHERE id = :i"), {"i": ap2})
    assert m.post(f"/api/v1/soar/approvals/{ap2}/decision", {"decision": "approve", "reason": "late"}, org=world.alpha).status_code == 409
    assert next(s for s in as_user("analyst_a").get(f"/api/v1/soar/runs/{run['id']}").json()["steps"] if s["step_key"] == "block")["state"] == "expired"
    m, a, pb, case = _setup(as_user, world, fixture_alerts, actions=())               # empty allow-list
    assert next(s for s in _run(a, pb, case).json()["steps"] if s["step_key"] == "block")["state"] == "refused_by_policy"
    m, a, pb, case = _setup(as_user, world, fixture_alerts, groups=("nv-alpha-workstations",))
    blocked = next(s for s in _run(a, pb, case).json()["steps"] if s["step_key"] == "block")
    assert blocked["state"] == "refused_by_policy" and "groups" in blocked["message"]


def test_cross_tenant_denial_at_the_api_and_at_the_bridge(bridge, as_user, world, fixture_alerts):
    adapter, _ = bridge
    m, a, pb, case = _setup(as_user, world, fixture_alerts)
    run = _run(a, pb, case).json()
    approval = next(s["approval_id"] for s in run["steps"] if s["step_key"] == "block")
    b = as_user("manager_b")
    assert b.get(f"/api/v1/soar/runs/{run['id']}").status_code == 404
    assert b.post(f"/api/v1/soar/approvals/{approval}/decision", {"decision": "approve", "reason": "not mine"}).status_code == 404
    assert all(x["id"] != approval for x in b.get("/api/v1/soar/approvals").json()["items"])
    assert b.post("/api/v1/soar/runs", {"idempotency_key": f"run-{uuid.uuid4().hex}", "playbook_id": pb["id"], "playbook_version": 1,
                                        "case_id": case, "justification": "Beta tries alpha's playbook and case."}).status_code == 404
    # Beta configures its own policy and playbook; the BRIDGE does not authorize beta at all.
    bm = as_user("manager_b")
    bm.c.put("/api/v1/soar/policy", json={"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-beta-servers"]},
             headers={"X-CSRF-Token": bm.csrf})
    pbb = bm.post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": f"beta-{uuid.uuid4().hex[:6]}"}).json()
    pbb = approve_playbook(bm, as_user("admin"), pbb, org=world.beta)
    alert = next(x for x in bm.get("/api/v1/soc/alerts").json()["items"] if x["agent_id"] == "004")
    case_b = bm.post("/api/v1/soc/cases", {"alert_ids": [alert["id"]], "title": "Beta brute force", "severity": "medium",
                                           "source": "alert", "source_id": f"b-{uuid.uuid4().hex}"}).json()["case_id"]
    runb = as_user("analyst_b").post("/api/v1/soar/runs", {"idempotency_key": f"run-{uuid.uuid4().hex}", "playbook_id": pbb["id"],
                                                           "playbook_version": 1, "case_id": case_b, "mode": "dry_run",
                                                           "justification": "Beta wants to block the source."}).json()
    apb = next(s["approval_id"] for s in runb["steps"] if s["step_key"] == "block")
    out = bm.post(f"/api/v1/soar/approvals/{apb}/decision", {"decision": "approve", "reason": "go ahead"}).json()
    assert "steps" in out, out
    blk = next(s for s in out["steps"] if s["step_key"] == "block")
    assert blk["state"] == "failed" and blk["receipt"]["reason"] == "action_not_authorized" and adapter.executed == []


def test_permissions_and_isolation(as_user, owner, app_engine, world):
    assert as_user("exec_a").get("/api/v1/soar/playbooks").status_code == 403
    assert as_user("analyst_a").post("/api/v1/soar/playbooks", {**PLAYBOOK, "name": "x-nope"}).status_code == 403
    assert as_user("analyst_a").c.put("/api/v1/soar/policy", json={"allowed_actions": [], "allowed_agent_groups": []},
                                      headers={"X-CSRF-Token": as_user("analyst_a").csrf}).status_code == 403
    assert_tenant_isolation(owner, app_engine, table="novrsoc.soar_playbooks", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "name": f"iso-{uuid.uuid4().hex[:6]}", "version": 1,
                                                  "title": "isolation", "steps": json.dumps([])}, update_set="enabled = false")


def test_response_groups_must_be_the_organizations_own_and_never_a_collection_group(as_user, world, mapped, owner, db, monkeypatch, capsys):
    """A response may only reach agents the organization owns: `default` (every new agent of every tenant) and another
    organization's group are refused; the bridge tenants entry is derived from the stored policy, read-only."""
    import json as _json
    from app import cli
    m = as_user("manager")
    put = lambda groups: m.c.put("/api/v1/soar/policy", json={"allowed_actions": ["block_ip"], "allowed_agent_groups": groups},  # noqa: E731
                                 headers={"X-CSRF-Token": m.csrf, "X-Org-Id": str(world.alpha)})
    r = put(["default"])
    assert r.status_code == 422 and r.json()["error"]["code"] == "collection_group_not_allowed"
    r = put(["nv-beta-servers"])                                     # beta's group
    assert r.status_code == 422 and r.json()["error"]["code"] == "group_not_mapped"
    assert put(["nv-alpha-servers"]).status_code == 200
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    capsys.readouterr()
    assert cli.soar_bridge_tenant("t-alpha") == 0
    out = _json.loads(capsys.readouterr().out)
    assert out["tenants_entry"] == {str(world.alpha): {"actions": ["block_ip"], "agent_groups": ["nv-alpha-servers"]}}
    assert out["bridge_must_keep"] == {"adapter": "simulated", "allow_live": False}
    assert cli.soar_bridge_tenant("t-gamma") == 1                    # no policy: nothing to authorize
