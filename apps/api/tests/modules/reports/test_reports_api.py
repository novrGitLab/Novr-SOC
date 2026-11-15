"""Reports foundation: honest source states, idempotency, history, downloads, permissions, isolation."""
import csv
import hashlib
import io
import uuid
from datetime import datetime, timedelta, timezone

from tests.helpers.rls import assert_tenant_isolation

NOW = datetime.now(timezone.utc)


def _req(fmt="json", key=None, rtype="organization_summary"):
    return {"idempotency_key": key or f"rep-{uuid.uuid4().hex}", "type": rtype, "format": fmt,
            "period_start": (NOW - timedelta(days=30)).isoformat(), "period_end": (NOW + timedelta(days=1)).isoformat()}


def test_report_states_are_honest_with_unconfigured_wazuh(app, world, mapped, fixture_alerts, as_user):
    r = as_user("analyst_a", app).post("/api/v1/reports", _req())
    assert r.status_code == 201
    rep = r.json()
    states = {s["key"]: s["state"] for s in rep["sections"]}
    assert states["endpoints"] == "integration_unconfigured"
    ep = next(s for s in rep["sections"] if s["key"] == "endpoints")
    assert ep["data"] == {}, "an unavailable source carries no figures, not zeros"
    assert states["alerts"] == "ok" and rep["data_states"] == states and len(rep["sha256"]) == 64
    alerts = next(s for s in rep["sections"] if s["key"] == "alerts")
    assert "local fixture alerts" in alerts["note"]


def test_report_with_fixture_source_is_labelled(world, mapped, as_user):
    rep = as_user("analyst_a").post("/api/v1/reports", _req()).json()
    ep = next(s for s in rep["sections"] if s["key"] == "endpoints")
    assert ep["state"] == "local_fixture" and ep["data"]["count"] == 3 and "not live" in ep["note"]


def test_sources_the_requester_cannot_read_are_not_permitted_never_empty(app_engine, fixture_settings, world, fixture_alerts):
    from sqlalchemy import text
    from app.auth.deps import Principal
    from app.modules.reports import build_organization_summary
    limited = Principal(user_id=uuid.uuid4(), email="limited@test.invalid", display_name="", role="executive", home=None,
                        memberships=[], org_id=world.alpha, cross_org=False, permissions=frozenset({"org:read", "reports:read"}))
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        sections = build_organization_summary(c, limited, fixture_settings, NOW - timedelta(days=30), NOW + timedelta(days=1))
    states = {s.key: s.state for s in sections}
    assert states == {"organization": "ok", "sites": "not_permitted", "endpoints": "not_permitted",
                      "alerts": "not_permitted", "cases": "not_permitted"}
    assert all(s.data == {} for s in sections if s.state == "not_permitted")


def test_executives_read_reports_but_cannot_request_them(world, as_user):
    rep = as_user("exec_a").post("/api/v1/reports", _req())
    assert rep.status_code == 403, "executives read reports but cannot request them"
    analyst_rep = as_user("analyst_a").post("/api/v1/reports", _req()).json()
    seen_by_exec = as_user("exec_a").get(f"/api/v1/reports/{analyst_rep['id']}")
    assert seen_by_exec.status_code == 200
    mgr = as_user("manager_b").post("/api/v1/reports", _req()).json()
    assert {s["key"] for s in mgr["sections"]} >= {"organization", "sites", "endpoints", "alerts", "cases"}


def test_idempotency_history_and_isolation(world, as_user):
    a = as_user("analyst_a")
    key = f"rep-{uuid.uuid4().hex}"
    first = a.post("/api/v1/reports", _req(key=key)).json()
    second = a.post("/api/v1/reports", _req(key=key)).json()
    assert first["id"] == second["id"]
    assert first["id"] in [r["id"] for r in a.get("/api/v1/reports").json()["items"]]
    b = as_user("manager_b")
    assert b.get(f"/api/v1/reports/{first['id']}").status_code == 404
    assert b.get(f"/api/v1/reports/{first['id']}/download").status_code == 404
    assert first["id"] not in [r["id"] for r in b.get("/api/v1/reports").json()["items"]]


def test_unavailable_types_and_formats_are_refused(as_user):
    a = as_user("analyst_a")
    r = a.post("/api/v1/reports", _req(fmt="pdf"))
    assert r.status_code == 422 and r.json()["error"]["code"] == "format_unavailable"
    # Consolidation: every report type exists now; each reads actual records and labels every source state.
    r = a.post("/api/v1/reports", _req(rtype="vms_executive"))
    assert r.status_code == 201 and {s["key"] for s in r.json()["sections"]} == {"exposure", "activity", "scans"}
    assert as_user("portal_a").get("/api/v1/reports").status_code == 403


def test_downloads_are_checksummed(as_user):
    a = as_user("analyst_a")
    j = a.post("/api/v1/reports", _req("json")).json()
    d = a.get(f"/api/v1/reports/{j['id']}/download")
    assert d.status_code == 200 and hashlib.sha256(d.content).hexdigest() == j["sha256"] == d.headers["x-content-sha256"]
    c = a.post("/api/v1/reports", _req("csv")).json()
    rows = list(csv.reader(io.StringIO(a.get(f"/api/v1/reports/{c['id']}/download").text)))
    assert rows[0] == ["section", "state", "metric", "value"]
    assert any(r[0] == "endpoints" and r[1] == "local_fixture" for r in rows[1:])


def test_report_requests_are_tenant_isolated(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.report_requests", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "report_type": "organization_summary",
                                                  "idempotency_key": f"iso-{uuid.uuid4().hex}", "period_start": NOW - timedelta(days=1),
                                                  "period_end": NOW, "format": "json", "status": "ready"},
                            update_set="status = 'failed'")
