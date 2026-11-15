"""SOC foundation: ingest (organization from group map, quarantine, dedupe), alerts, alert-to-case, cases."""
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed
from app.modules.soc.service import severity_from_level
from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation


def _batch(alert_id, groups, level=10, agent="001"):
    return {"batch_id": f"batch-{uuid.uuid4().hex}", "alerts": [{
        "id": alert_id, "timestamp": datetime.now(timezone.utc).isoformat(),
        "rule": {"id": "5712", "level": level, "description": "test rule", "mitre_ids": ["T1110"]},
        "agent": {"id": agent, "name": "host", "groups": groups}, "src_ip": "203.0.113.9", "raw": {"full_log": "x"}}]}


def test_severity_mapping_matches_the_legacy_thresholds():
    assert [severity_from_level(x) for x in (0, 6, 7, 9, 10, 12, 13, 16)] == \
           ["low", "low", "medium", "medium", "high", "high", "critical", "critical"]


def test_fixture_alerts_were_attributed_by_group_map_and_unmapped_quarantined(owner, fixture_alerts):
    assert (fixture_alerts.accepted, fixture_alerts.quarantined) == (5, 1)
    with owner.connect() as c:
        q = c.execute(text("SELECT reason, agent_groups FROM novrsoc.alert_quarantine WHERE external_id = 'fx-1731576300.1006'")).one()
    assert q.reason == "no_organization_for_groups" and q.agent_groups == ["lab-unmapped"]


def test_forwarder_ingest_derives_org_dedupes_and_quarantines(fixture_app, forwarder_token, world, mapped, as_user):
    c = TestClient(fixture_app)
    h = {"Authorization": f"Bearer {forwarder_token}"}
    xid = f"wz-{uuid.uuid4().hex}"
    r = c.post("/api/v1/soc/ingest/alerts", json=_batch(xid, ["nv-beta-servers"]), headers=h)
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert c.post("/api/v1/soc/ingest/alerts", json=_batch(xid, ["nv-beta-servers"]), headers=h).json()["duplicates"] == 1
    amb = c.post("/api/v1/soc/ingest/alerts", json=_batch(f"wz-{uuid.uuid4().hex}", ["nv-alpha-servers", "nv-beta-servers"]), headers=h)
    assert amb.json()["quarantined"] == 1, "groups of two organizations are ambiguous: quarantined, never guessed"
    ids = [a["external_id"] for a in as_user("manager_b").get("/api/v1/soc/alerts?limit=200").json()["items"]]
    assert xid in ids
    assert xid not in [a["external_id"] for a in as_user("analyst_a").get("/api/v1/soc/alerts?limit=200").json()["items"]]
    bad = c.post("/api/v1/soc/ingest/alerts", json={**_batch(xid, ["nv-beta-servers"]), "org_id": str(world.alpha)}, headers=h)
    assert bad.status_code == 422, "an organization in the payload is rejected, never trusted"


def test_only_a_platform_forwarder_with_scope_may_ingest(fixture_app, owner, world, mapped):
    with owner.begin() as c:
        _, tenant_fwd = devseed.create_service_identity(c, world.alpha, "forwarder", "tenant-fwd", scopes=["alerts:ingest"])
        _, collector = devseed.create_service_identity(c, world.platform, "collector", "c", scopes=["alerts:ingest"])
    client = TestClient(fixture_app)
    for tok in (tenant_fwd, collector):
        r = client.post("/api/v1/soc/ingest/alerts", json=_batch(f"x-{uuid.uuid4().hex}", ["nv-alpha-servers"]),
                        headers={"Authorization": f"Bearer {tok}"})
        assert r.status_code == 403
    assert client.post("/api/v1/soc/ingest/alerts", json=_batch("y", ["nv-alpha-servers"])).status_code == 401
    assert any(e["action"] == "ALERT_INGEST_REFUSED" for e in audit_actions(owner))


def test_alert_list_detail_filters_and_isolation(fixture_alerts, as_user):
    a = as_user("analyst_a")
    lst = a.get("/api/v1/soc/alerts").json()
    assert lst["total"] >= 4 and all(i["source"] in ("local_fixture", "wazuh") for i in lst["items"])
    crit = a.get("/api/v1/soc/alerts?severity=critical").json()["items"]
    assert crit and all(i["severity"] == "critical" for i in crit)
    one = crit[0]["id"]
    d = a.get(f"/api/v1/soc/alerts/{one}").json()
    assert d["agent_groups"] == ["nv-alpha-workstations"] and d["rule_level"] == 13
    assert as_user("manager_b").get(f"/api/v1/soc/alerts/{one}").status_code == 404
    assert as_user("portal_a").get("/api/v1/soc/alerts").status_code == 403
    assert as_user("exec_a").get("/api/v1/soc/alerts").status_code == 403


def test_triage_requires_permission_and_is_audited(owner, world, fixture_alerts, as_user):
    a = as_user("analyst_a")
    aid = a.get("/api/v1/soc/alerts?severity=medium").json()["items"][0]["id"]
    r = a.post(f"/api/v1/soc/alerts/{aid}/status", {"status": "acknowledged", "reason": "looking"})
    assert r.status_code == 200 and r.json()["status"] == "acknowledged"
    assert as_user("manager_b").post(f"/api/v1/soc/alerts/{aid}/status", {"status": "closed"}).status_code == 404
    assert any(e["resource_id"] == aid for e in audit_actions(owner, org=world.alpha, action="ALERT_STATUS_CHANGED"))


def test_alert_to_case_workflow_dedupe_timeline_and_closing(owner, world, fixture_alerts, as_user):
    a = as_user("analyst_a")
    alert = a.get("/api/v1/soc/alerts?severity=high").json()["items"][0]
    body = {"alert_ids": [alert["id"]], "title": f"Investigate {alert['rule_description'][:40]}", "severity": "high",
            "source": "alert", "source_id": alert["id"]}
    r = a.post("/api/v1/soc/cases", body)
    assert r.status_code == 201 and r.json()["created"] is True
    case_id = r.json()["case_id"]
    again = a.post("/api/v1/soc/cases", body).json()
    assert again["case_id"] == case_id and again["created"] is False and again["linked_alert_ids"] == []
    assert a.get(f"/api/v1/soc/alerts/{alert['id']}").json()["case_id"] == case_id
    assert a.get(f"/api/v1/soc/alerts/{alert['id']}").json()["status"] == "in_progress"

    d = a.post(f"/api/v1/soc/cases/{case_id}/notes", {"body": "Source IP is a known scanner."}).json()
    assert [e["kind"] for e in d["timeline"]] == ["created", "alert_linked", "note"]
    assert d["reference"].startswith("CASE-") and len(d["alerts"]) == 1
    assert a.post(f"/api/v1/soc/cases/{case_id}/status", {"status": "resolved"}).json()["status"] == "resolved"
    assert a.post(f"/api/v1/soc/cases/{case_id}/status", {"status": "resolved"}).status_code == 409
    assert as_user("exec_reporting").post(f"/api/v1/soc/cases/{case_id}/status", {"status": "closed"}).status_code == 403
    no_note = as_user("manager").post(f"/api/v1/soc/cases/{case_id}/status", {"status": "closed"}, org=world.alpha)
    assert no_note.status_code == 422 and no_note.json()["error"]["code"] == "closure_note_required"
    closed = as_user("manager").post(f"/api/v1/soc/cases/{case_id}/status", {"status": "closed", "note": "Reviewed: benign admin activity."},
                                     org=world.alpha)
    assert closed.status_code == 200 and closed.json()["closed_at"]
    assert any(e["resource_id"] == case_id for e in audit_actions(owner, org=world.alpha, action="CASE_CREATED"))


def test_cases_never_cross_organizations(world, fixture_alerts, as_user):
    a, b = as_user("analyst_a"), as_user("manager_b")
    alpha_alert = a.get("/api/v1/soc/alerts").json()["items"][0]["id"]
    r = b.post("/api/v1/soc/cases", {"alert_ids": [alpha_alert], "title": "smuggle", "severity": "low",
                                     "source": "alert", "source_id": alpha_alert})
    assert r.status_code == 404, "beta cannot open a case on alpha's alert"
    alpha_cases = [c["id"] for c in a.get("/api/v1/soc/cases").json()["items"]]
    for cid in alpha_cases:
        assert b.get(f"/api/v1/soc/cases/{cid}").status_code == 404
        assert b.post(f"/api/v1/soc/cases/{cid}/notes", {"body": "x"}).status_code == 404
    assert all(c["id"] not in alpha_cases for c in b.get("/api/v1/soc/cases").json()["items"])


@pytest.mark.parametrize("severity", ["info"])
def test_case_severity_info_is_rejected(fixture_alerts, as_user, severity):
    a = as_user("analyst_a")
    aid = a.get("/api/v1/soc/alerts").json()["items"][0]["id"]
    r = a.post("/api/v1/soc/cases", {"alert_ids": [aid], "title": "info case", "severity": severity, "source": "alert",
                                     "source_id": f"x-{aid}"})
    assert r.status_code == 422


def test_soc_tables_are_tenant_isolated(owner, app_engine, world, fixture_alerts):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.alerts", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "source": "wazuh", "external_id": f"iso-{uuid.uuid4().hex}",
                                                  "rule_level": 3, "severity": "low", "observed_at": datetime.now(timezone.utc)},
                            update_set="status = 'closed'")
    assert_tenant_isolation(owner, app_engine, table="novrsoc.cases", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "title": "iso case", "severity": "low", "source": "manual",
                                                  "source_id": f"iso-{uuid.uuid4().hex}"},
                            update_set="title = 'tampered'")


def test_quarantine_is_platform_only_and_case_links_cannot_cross_orgs(owner, app_engine, world, fixture_alerts):
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        assert c.execute(text("SELECT count(*) FROM novrsoc.alert_quarantine")).scalar() == 0
    with owner.connect() as c:
        alpha_alert = c.execute(text("SELECT id FROM novrsoc.alerts WHERE org_id = :o LIMIT 1"), {"o": world.alpha}).scalar()
        beta_case = c.execute(text("""INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id)
                                      VALUES (:o, 'beta case', 'low', 'manual', :s) RETURNING id"""),
                              {"o": world.beta, "s": uuid.uuid4().hex}).scalar()
        c.commit()
    from sqlalchemy.exc import IntegrityError
    with pytest.raises(IntegrityError):
        with owner.begin() as c:  # even the owner (no RLS) cannot link a beta case to an alpha alert
            c.execute(text("INSERT INTO novrsoc.case_alerts (case_id, alert_id, org_id) VALUES (:c, :a, :o)"),
                      {"c": beta_case, "a": alpha_alert, "o": world.beta})
