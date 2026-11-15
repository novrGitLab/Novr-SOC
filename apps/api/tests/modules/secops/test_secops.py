"""Security operations: SLA policies, live state, escalation (on demand and by the jobs worker), shift handover with
acknowledgement rules, notifications (own only), alert and case assignment."""
import uuid

from sqlalchemy import text

from app.jobs import run_cycle
from tests.conftest import audit_actions

POLICIES = {"policies": [{"severity": "critical", "response_minutes": 15, "resolution_minutes": 240, "escalate_before_minutes": 10},
                         {"severity": "high", "response_minutes": 60, "resolution_minutes": 1440}]}


def _case(a, alert_id, sev="high"):
    r = a.post("/api/v1/soc/cases", {"alert_ids": [alert_id], "title": "SLA test case", "severity": sev, "source": "alert",
                                      "source_id": f"sla-{uuid.uuid4().hex}"})
    assert r.status_code == 201, r.text
    return r.json()["case_id"]


def test_sla_policy_due_times_states_and_escalation(as_user, fixture_alerts, world, owner, app_engine, fixture_settings):
    m, a = as_user("manager"), as_user("analyst_a")
    assert a.put("/api/v1/secops/sla/policies", POLICIES).status_code == 403                 # sla:manage
    assert m.put("/api/v1/secops/sla/policies", POLICIES, org=world.alpha).status_code == 200
    alert = a.get("/api/v1/soc/alerts?limit=200").json()["items"][0]["id"]
    cid = _case(a, alert, "high")
    case = a.get(f"/api/v1/soc/cases/{cid}").json()
    assert case["sla_response_due_at"] and case["sla_resolution_due_at"] and case["sla_state"] == "on_track"
    a.post(f"/api/v1/soc/cases/{cid}/notes", {"body": "Triage started.", "kind": "note"})
    assert a.get(f"/api/v1/soc/cases/{cid}").json()["first_response_at"]
    row = next(i for i in a.get("/api/v1/secops/sla/status").json()["items"] if i["case_id"] == cid)
    assert row["response_state"] == "met" and row["resolution_state"] == "on_track"
    with owner.begin() as c:                                                             # the resolution target has passed
        c.execute(text("UPDATE novrsoc.cases SET sla_resolution_due_at = now() - interval '1 minute' WHERE id = :i"), {"i": cid})
    row = next(i for i in a.get("/api/v1/secops/sla/status").json()["items"] if i["case_id"] == cid)
    assert row["resolution_state"] == "breached"
    out = m.post("/api/v1/secops/sla/escalate", {}, org=world.alpha).json()
    assert out["escalated"] >= 1 and out["notified"] >= 1
    assert m.post("/api/v1/secops/sla/escalate", {}, org=world.alpha).json()["escalated"] == 0   # once per case
    kinds = [e["kind"] for e in a.get(f"/api/v1/soc/cases/{cid}").json()["timeline"]]
    assert "sla_escalated" in kinds
    notes = m.get("/api/v1/secops/notifications", org=world.alpha).json()
    assert any(n["kind"] == "sla_escalation" and cid in n["link"] for n in notes["items"])
    # the jobs worker runs the same escalation for a case that later breaches
    cid2 = _case(a, alert, "critical")
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.cases SET sla_response_due_at = now() - interval '1 minute' WHERE id = :i"), {"i": cid2})
    totals = run_cycle(app_engine, fixture_settings)
    assert totals["errors"] == 0 and totals["escalated"] >= 1
    assert "sla_escalated" in [e["kind"] for e in a.get(f"/api/v1/soc/cases/{cid2}").json()["timeline"]]
    perf = a.get("/api/v1/secops/sla/performance?days=30").json()
    high = next(r for r in perf["rows"] if r["severity"] == "high")
    assert high["cases"] >= 1 and high["resolution_breached"] >= 1
    assert "SLA_POLICY_UPDATED" in {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_no_policy_is_never_counted_as_met(as_user, fixture_alerts):
    b = as_user("analyst_b")
    alert = b.get("/api/v1/soc/alerts").json()["items"][0]["id"]
    cid = b.post("/api/v1/soc/cases", {"alert_ids": [alert], "title": "No policy case", "severity": "medium", "source": "alert",
                                       "source_id": f"np-{uuid.uuid4().hex}"}).json()["case_id"]
    c = b.get(f"/api/v1/soc/cases/{cid}").json()
    assert c["sla_state"] == "no_policy" and c["sla_response_due_at"] is None


def test_assignment_needs_an_organization_member(as_user, fixture_alerts, world):
    a = as_user("analyst_a")
    me = a.get("/api/v1/auth/me").json()["user"]["id"]
    outsider = as_user("analyst_b").get("/api/v1/auth/me").json()["user"]["id"]
    alert = a.get("/api/v1/soc/alerts?limit=200").json()["items"][1]["id"]
    assert a.post(f"/api/v1/soc/alerts/{alert}/assign", {"assignee_id": outsider}).status_code == 422
    r = a.post(f"/api/v1/soc/alerts/{alert}/assign", {"assignee_id": me}).json()
    assert r["assignee_id"] == me and r["assignee_label"] == "analyst_a@test.novrsoc.invalid"
    assert any(x["id"] == alert for x in a.get("/api/v1/soc/alerts?assigned=me&limit=200").json()["items"])
    cid = _case(a, alert)
    det = a.post(f"/api/v1/soc/cases/{cid}/assign", {"assignee_id": me, "note": "taking it"}).json()
    assert det["assignee_id"] == me and det["timeline"][-1]["kind"] == "assigned"
    assert as_user("exec_a").post(f"/api/v1/soc/cases/{cid}/assign", {"assignee_id": me}).status_code == 403


def test_shift_handover_snapshot_and_acknowledgement(as_user, fixture_alerts, world, owner):
    a, m = as_user("analyst_a"), as_user("manager")
    draft = a.get("/api/v1/secops/handovers/draft").json()
    assert draft["snapshot"]["unresolved_alerts"] >= 0 and draft["recipients"]
    incoming = next(r for r in draft["recipients"] if r["email"].startswith("manager@"))
    body = {"shift_start": "2026-11-14T08:00:00Z", "shift_end": "2026-11-14T16:00:00Z",
            "summary": "Quiet shift; SSH brute force on alpha-web-01 still open.", "watch_items": ["Watch 203.0.113.45"],
            "incoming_user_id": incoming["id"]}
    assert a.post("/api/v1/secops/handovers", {**body, "shift_end": "2026-11-15T16:00:00Z"}).status_code == 422   # > 24 h
    h = a.post("/api/v1/secops/handovers", body).json()
    assert h["status"] == "submitted" and h["snapshot"]["taken_at"] and h["incoming_label"] == incoming["email"]
    assert a.post(f"/api/v1/secops/handovers/{h['id']}/acknowledge", {"note": "self"}).status_code == 403        # not the author
    other = as_user("analyst_assigned")                                                  # another staff member of alpha? (beta only)
    assert other.post(f"/api/v1/secops/handovers/{h['id']}/acknowledge", {}).status_code in (403, 404)
    ack = m.post(f"/api/v1/secops/handovers/{h['id']}/acknowledge", {"note": "Picked up."}, org=world.alpha).json()
    assert ack["status"] == "acknowledged" and ack["acknowledged_by"]["label"].startswith("manager@")
    assert m.post(f"/api/v1/secops/handovers/{h['id']}/acknowledge", {}, org=world.alpha).status_code == 409
    assert any(n["kind"] == "handover_acknowledged" for n in a.get("/api/v1/secops/notifications").json()["items"])
    assert as_user("manager_b").get("/api/v1/secops/handovers").json()["items"] == [] or \
        all(x["id"] != h["id"] for x in as_user("manager_b").get("/api/v1/secops/handovers").json()["items"])
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"HANDOVER_SUBMITTED", "HANDOVER_ACKNOWLEDGED"} <= acts


def test_notifications_are_private_to_their_user(as_user, world, owner):
    a = as_user("analyst_a")
    me = a.get("/api/v1/auth/me").json()["user"]["id"]
    with owner.begin() as c:
        c.execute(text("""INSERT INTO novrsoc.notifications (org_id, user_id, kind, title) VALUES (:o, :u, 'test_note', 'for analyst_a only')"""),
                  {"o": world.alpha, "u": me})
    assert any(n["title"] == "for analyst_a only" for n in a.get("/api/v1/secops/notifications").json()["items"])
    assert all(n["title"] != "for analyst_a only" for n in as_user("exec_a").get("/api/v1/secops/notifications").json()["items"])
    assert a.post("/api/v1/secops/notifications/read", {}).json()["unread"] == 0
