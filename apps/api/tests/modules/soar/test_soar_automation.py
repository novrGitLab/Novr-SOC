"""NovrSOAR policy-driven orchestration with the real bridge code in-process (simulated adapter: nothing is executed).

Covers: off by default and never reaching back before it was switched on; automatic case creation and joining;
pre-authorized block_ip dispatched without a per-event approval, with the exact signed payload and the signed receipt
stored (the reproducible simulated procedure, dry run and live-on-the-simulated-adapter); confidence threshold and
protected targets; emergency stop; idempotency across repeated cycles; policy validation; tenant isolation."""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.soar import automation
from tests.conftest import audit_actions
from tests.modules.soar.test_soar_engine import approve_playbook, bridge  # noqa: F401  (fixture)

AUTO_PLAYBOOK = {"title": "Block brute-force source automatically", "triggers": {"rule_ids": ["5763"], "min_level": 7},
                 "steps": [{"step_key": "enrich", "action": "enrich_iocs"}, {"step_key": "block", "action": "block_ip"}],
                 "execution_policy": {"modes": ["dry_run", "live"], "automatic": True}}


def _policy(m, world, *, enabled=True, cases=False, pre=("block_ip",), conf=60, protected=(), live=False, status=200):
    r = m.c.put("/api/v1/soar/policy", json={
        "allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"], "live_enabled": live, "approval_ttl_minutes": 60,
        "max_runs_per_hour": 500,
        "automation": {"enabled": enabled, "case_creation": cases, "case_min_severity": "high", "pre_authorized_actions": list(pre),
                       "min_confidence": conf, "max_dispatches_per_hour": 50, "protected_targets": list(protected)}},
        headers={"X-CSRF-Token": m.csrf, "X-Org-Id": str(world.alpha)})
    assert r.status_code == status, r.text
    return r.json()


def _alert(owner, org, src_ip, *, rule="5763", level=10, severity="high", agent="001"):
    with owner.begin() as c:
        return c.execute(text("""INSERT INTO novrsoc.alerts (org_id, source, external_id, rule_id, rule_level, rule_description, severity,
                                   agent_id, agent_name, agent_groups, src_ip, observed_at, raw)
                                 VALUES (:o, 'wazuh', :x, :r, :lvl, 'sshd: brute force trying to get access to the system.', :sev,
                                         :a, 'alpha-web-01', ARRAY['nv-alpha-servers'], CAST(:ip AS inet), :t, '{}'::jsonb)
                                 RETURNING id"""),
                         {"o": org, "x": f"auto-{uuid.uuid4().hex}", "r": rule, "lvl": level, "sev": severity, "a": agent, "ip": src_ip,
                          "t": datetime.now(timezone.utc)}).scalar()


def _cycle(app_engine, settings, org):
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
        return automation.process(c, settings, org)


def _automatic_playbook(as_user, world, **ep):
    m = as_user("manager")
    body = {**AUTO_PLAYBOOK, "name": f"auto-{uuid.uuid4().hex[:6]}",
            "execution_policy": {**AUTO_PLAYBOOK["execution_policy"], **ep}}
    pb = m.post("/api/v1/soar/playbooks", body, org=world.alpha).json()
    assert any("Automatic" in w for w in pb["validation"]["warnings"]), pb["validation"]
    return approve_playbook(m, as_user("admin"), pb, org=world.alpha)


def _event(owner, alert_id, playbook=""):
    with owner.connect() as c:
        return c.execute(text("SELECT * FROM novrsoc.soar_automation_events WHERE alert_id = :a AND playbook_name = :p"),
                         {"a": alert_id, "p": playbook}).first()


@pytest.fixture
def auto_off(as_user, world, mapped, owner):
    """Every test starts without automatic playbooks and leaves alpha's automation off (other tests run job cycles)."""
    def retire():
        with owner.begin() as c:
            c.execute(text("""UPDATE novrsoc.soar_playbooks SET status = 'retired', retired_at = now()
                              WHERE org_id = :o AND status = 'approved' AND (execution_policy->>'automatic')::boolean"""), {"o": world.alpha})
    retire()
    yield
    _policy(as_user("manager"), world, enabled=False, cases=False, pre=())
    retire()


def test_off_by_default_and_never_reaches_back(as_user, world, owner, app_engine, fixture_settings, fixture_app, auto_off):
    m = as_user("manager")
    _policy(m, world, enabled=False, cases=False, pre=())
    before = _alert(owner, world.alpha, "203.0.113.70")
    assert _cycle(app_engine, fixture_settings, world.alpha)["alerts"] == 0          # off: nothing considered
    pol = _policy(m, world, enabled=True, cases=True)
    assert pol["automation"]["enabled"] and pol["automation_since"]
    assert _cycle(app_engine, fixture_settings, world.alpha)["alerts"] == 0          # the earlier alert is never acted on
    assert _event(owner, before) is None


def test_pre_authorized_block_ip_runs_without_approval_simulated_procedure(bridge, as_user, world, owner, app_engine,  # noqa: F811
                                                                           fixture_settings, fixture_app, auto_off):
    adapter, _ = bridge
    m = as_user("manager")
    _policy(m, world, conf=60)
    pb = _automatic_playbook(as_user, world)
    alert = _alert(owner, world.alpha, "203.0.113.77")
    r = _cycle(app_engine, fixture_settings, world.alpha)
    assert r["runs"] >= 1 and r["cases"] >= 1, r
    ev = _event(owner, alert, pb["name"])
    assert ev.decision == "run_started" and ev.confidence == 60 and ev.run_id and ev.case_id
    assert _event(owner, alert).decision == "case_created"
    run = m.get(f"/api/v1/soar/runs/{ev.run_id}", org=world.alpha).json()
    assert run["origin"] == "automatic" and run["requested_by"]["type"] == "system" and run["confidence"] == 60
    assert run["trigger_alert_id"] == str(alert) and run["mode"] == "dry_run"                 # live is off in the policy
    block = next(s for s in run["steps"] if s["step_key"] == "block")
    assert block["authorization"] == "policy" and block["state"] == "dry_run", block
    # The exact payload signed and sent to NovrSOAR, and the signed receipt (reproducible procedure, docs/public/SOAR_AUTOMATION.md)
    req = block["request"]
    assert req["action"] == "block_ip" and req["target"] == "203.0.113.77" and req["agent_id"] == "001" and req["mode"] == "dry_run"
    assert req["authorization"] == "policy" and req["approved_by"] == "policy" and req["org_id"] == str(world.alpha)
    assert req["request_id"] == block["request_id"] and req["approval_id"] == block["approval_id"]
    assert block["receipt"]["status"] == "dry_run" and block["receipt"]["adapter"] == "simulated" and block["receipt"]["command"] == "firewall-drop"
    assert adapter.executed == []                                                             # dry run: nothing executed
    case = m.get(f"/api/v1/soc/cases/{ev.case_id}", org=world.alpha).json()
    assert case["source"] == "automation" and any(a["id"] == str(alert) for a in case["alerts"])
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"SOAR_AUTOMATIC_RUN", "SOAR_POLICY_AUTHORIZED", "SOAR_AUTOMATIC_CASE", "SOAR_STEP_EXECUTED"} <= acts
    # Idempotent: replaying the same alerts (cursor rewound) never starts a second run for the same alert and playbook.
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.soar_policies SET automation_cursor_at = automation_since, automation_cursor_id = NULL WHERE org_id = :o"),
                  {"o": world.alpha})
    _cycle(app_engine, fixture_settings, world.alpha)
    with owner.connect() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.soar_runs WHERE trigger_alert_id = :a"), {"a": alert}).scalar() == 1
    ops = m.get("/api/v1/soar/operations", org=world.alpha).json()
    assert ops["automation_enabled"] and ops["automatic_runs_24h"] >= 1 and ops["policy_authorized_24h"] >= 1


def test_live_on_the_simulated_adapter_records_the_command_once(bridge, as_user, world, owner, app_engine,  # noqa: F811
                                                                fixture_settings, fixture_app, auto_off):
    adapter, _ = bridge
    _policy(as_user("manager"), world, conf=60, live=True)
    pb = _automatic_playbook(as_user, world, modes=["live"])
    alert = _alert(owner, world.alpha, "203.0.113.78")
    _cycle(app_engine, fixture_settings, world.alpha)
    run = as_user("manager").get(f"/api/v1/soar/runs/{_event(owner, alert, pb['name']).run_id}", org=world.alpha).json()
    block = next(s for s in run["steps"] if s["step_key"] == "block")
    assert run["mode"] == "live" and block["state"] == "succeeded" and block["receipt"]["status"] == "executed"
    assert block["receipt"]["adapter"] == "simulated"                                         # recorded, nothing executed for real
    assert {"command": "firewall-drop", "agent_id": "001", "arguments": ["203.0.113.78"]} in adapter.executed


def test_below_threshold_waits_for_a_person_protected_targets_and_emergency_stop(bridge, as_user, world, owner, app_engine,  # noqa: F811
                                                                                 fixture_settings, fixture_app, auto_off):
    adapter, _ = bridge
    m = as_user("manager")
    _policy(m, world, conf=90, protected=("198.51.100.0/24",))
    pb = _automatic_playbook(as_user, world)
    low_conf = _alert(owner, world.alpha, "203.0.113.79")
    shielded = _alert(owner, world.alpha, "198.51.100.9")
    _cycle(app_engine, fixture_settings, world.alpha)
    run = m.get(f"/api/v1/soar/runs/{_event(owner, low_conf, pb['name']).run_id}", org=world.alpha).json()
    block = next(s for s in run["steps"] if s["step_key"] == "block")
    assert block["state"] == "awaiting_approval" and "below the pre-authorization threshold" in block["message"]
    done = m.post(f"/api/v1/soar/approvals/{block['approval_id']}/decision", {"decision": "approve", "reason": "Checked: hostile"},
                  org=world.alpha).json()
    approved = next(s for s in done["steps"] if s["step_key"] == "block")
    assert approved["authorization"] == "human" and approved["state"] == "dry_run" and approved["request"]["approved_by"] != "policy"
    run2 = m.get(f"/api/v1/soar/runs/{_event(owner, shielded, pb['name']).run_id}", org=world.alpha).json()
    assert "protected target" in next(s for s in run2["steps"] if s["step_key"] == "block")["message"]
    # Emergency stop: the automation records the skip and starts nothing.
    assert m.post("/api/v1/soar/emergency-stop", {"active": True, "reason": "Containment paused for review"}, org=world.alpha).status_code == 200
    try:
        stopped = _alert(owner, world.alpha, "203.0.113.80")
        _cycle(app_engine, fixture_settings, world.alpha)
        ev = _event(owner, stopped, pb["name"])
        assert ev.decision == "skipped_emergency_stop" and ev.run_id is None
    finally:
        m.post("/api/v1/soar/emergency-stop", {"active": False, "reason": "Review finished, resuming"}, org=world.alpha)
    assert adapter.executed == []


def test_case_creation_opens_then_joins_and_ignores_low_severity(as_user, world, owner, app_engine, fixture_settings, fixture_app, auto_off):
    _policy(as_user("manager"), world, enabled=False, cases=True, pre=())
    rule = f"9{uuid.uuid4().int % 100000:05d}"
    first = _alert(owner, world.alpha, "203.0.113.81", rule=rule)
    second = _alert(owner, world.alpha, "203.0.113.82", rule=rule)
    low = _alert(owner, world.alpha, "203.0.113.83", rule=rule, severity="low", level=3)
    _cycle(app_engine, fixture_settings, world.alpha)
    e1, e2 = _event(owner, first), _event(owner, second)
    assert e1.decision == "case_created" and e2.decision == "case_joined" and e1.case_id == e2.case_id
    assert _event(owner, low) is None
    events = as_user("analyst_a").get("/api/v1/soar/automation/events").json()
    assert events["case_creation"] and any(i["alert_id"] == str(first) for i in events["items"])
    assert all(i["alert_id"] != str(first) for i in as_user("analyst_b").get("/api/v1/soar/automation/events").json()["items"])


def test_policy_validation(as_user, world, auto_off):
    m = as_user("manager")
    r = m.c.put("/api/v1/soar/policy", json={"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"],
                                             "automation": {"enabled": True, "pre_authorized_actions": ["isolate_agent"]}},
                headers={"X-CSRF-Token": m.csrf, "X-Org-Id": str(world.alpha)})
    assert r.status_code == 422 and "allowed actions" in r.json()["error"]["message"]
    r = m.c.put("/api/v1/soar/policy", json={"allowed_actions": ["block_ip"], "allowed_agent_groups": ["nv-alpha-servers"],
                                             "automation": {"enabled": True, "pre_authorized_actions": ["enrich_iocs"]}},
                headers={"X-CSRF-Token": m.csrf, "X-Org-Id": str(world.alpha)})
    assert r.status_code == 422
    _policy(m, world, protected=("not a target!",), status=422)
    _policy(m, world, protected=("10.0.0.0/8", "001", "svc.backup"))
    bad = m.post("/api/v1/soar/playbooks", {**AUTO_PLAYBOOK, "name": f"auto-{uuid.uuid4().hex[:6]}", "triggers": {}}, org=world.alpha).json()
    assert not bad["validation"]["valid"] and any("needs triggers" in e for e in bad["validation"]["errors"])


# ---------------------------------------------------------------- 0019 -> 0020 -> 0019 with live data
def test_0020_upgrades_in_place_keeps_manual_runs_and_rolls_back_cleanly(db):
    import secrets

    from alembic import command
    from sqlalchemy import create_engine
    from sqlalchemy.exc import IntegrityError

    from app import devseed
    from tests.conftest import PASSWORD, _with_db, alembic_config, drop_database, make_database
    name = f"novrsoc_mig20_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    url = _with_db(db.owner_url, name)
    cfg, eng = alembic_config(url), create_engine(url)
    try:
        command.upgrade(cfg, "0019_org_portals_onboarding")
        with eng.begin() as c:                                                      # the 0019 installation's data
            org = devseed.create_org(c, "soar-co", "Soar Co")
            uid = devseed.create_user(c, "soar@test.novrsoc.invalid", PASSWORD, "soc_manager", org)
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            c.execute(text("""INSERT INTO novrsoc.soar_policies (org_id, allowed_actions, allowed_agent_groups) VALUES (:o, '{block_ip}', '{g1}')"""),
                      {"o": org})
            pb = c.execute(text("""INSERT INTO novrsoc.soar_playbooks (org_id, name, version, title, steps, triggers, created_by)
                                   VALUES (:o, 'legacy-pb', 1, 'Legacy playbook', '[]'::jsonb, '{}'::jsonb, :u) RETURNING id"""),
                           {"o": org, "u": uid}).scalar()
            case = c.execute(text("""INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id)
                                     VALUES (:o, 'Legacy case', 'high', 'manual', 'm-1') RETURNING id"""), {"o": org}).scalar()
            c.execute(text("""INSERT INTO novrsoc.soar_runs (org_id, playbook_id, playbook_version, case_id, mode, state, idempotency_key,
                                                           requested_by, requested_label)
                              VALUES (:o, :p, 1, :c, 'dry_run', 'succeeded', 'legacy-run-0000001', :u, 'soar@test')"""),
                      {"o": org, "p": pb, "c": case, "u": uid})
        command.upgrade(cfg, "0020_soar_automation")
        with eng.begin() as c:
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            assert c.execute(text("SELECT origin FROM novrsoc.soar_runs")).scalar() == "manual"
            pol = c.execute(text("SELECT automation_enabled, case_creation, auto_actions FROM novrsoc.soar_policies")).one()
            assert (pol.automation_enabled, pol.case_creation, list(pol.auto_actions)) == (False, False, [])   # off after upgrade
            run = c.execute(text("""INSERT INTO novrsoc.soar_runs (org_id, playbook_id, playbook_version, case_id, mode, state, idempotency_key,
                                                                 requested_label, origin, confidence)
                                    VALUES (:o, :p, 1, :c, 'dry_run', 'succeeded', 'auto-run-000000001', 'NovrSOAR automation', 'automatic', 90)
                                    RETURNING id"""), {"o": org, "p": pb, "c": case}).scalar()
            step = c.execute(text("""INSERT INTO novrsoc.soar_steps (org_id, run_id, position, step_key, action, target, state)
                                     VALUES (:o, :r, 0, 'block', 'block_ip', '203.0.113.9', 'dry_run') RETURNING id"""), {"o": org, "r": run}).scalar()
            c.execute(text("""INSERT INTO novrsoc.soar_approvals (org_id, step_id, action, target, justification, requested_label, decision,
                                                                decided_label, expires_at, auth_kind)
                              VALUES (:o, :s, 'block_ip', '203.0.113.9', 'Pre-authorized by policy', 'NovrSOAR automation', 'approve',
                                      'automation policy', now(), 'policy')"""), {"o": org, "s": step})
        with pytest.raises(IntegrityError):                                         # a manual run still needs its person
            with eng.begin() as c:
                c.execute(text("""INSERT INTO novrsoc.soar_runs (org_id, playbook_id, playbook_version, case_id, mode, state, idempotency_key)
                                  VALUES (:o, :p, 1, :c, 'dry_run', 'pending', 'no-person-00000001')"""), {"o": org, "p": pb, "c": case})
        with pytest.raises(IntegrityError):                                         # a policy authorization is always an approval, never a person's
            with eng.begin() as c:
                c.execute(text("""UPDATE novrsoc.soar_approvals SET decided_by = :u WHERE auth_kind = 'policy'"""), {"u": uid})
        command.downgrade(cfg, "0019_org_portals_onboarding")
        with eng.begin() as c:
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            assert [r[0] for r in c.execute(text("SELECT idempotency_key FROM novrsoc.soar_runs"))] == ["legacy-run-0000001"]
            assert c.execute(text("SELECT count(*) FROM novrsoc.soar_approvals")).scalar() == 0
            tables = {r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc'"))}
            assert "soar_automation_events" not in tables
        command.upgrade(cfg, "head")                                                # and forward again
    finally:
        eng.dispose()
        drop_database(db.admin_url, name)
