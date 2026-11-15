"""Executive overview and security posture: explainable measurements, missing data never scored, role limits shown as
not_permitted, the score withheld when coverage is too low, gaps from real configuration."""


def test_overview_measures_are_explainable_and_never_invented(as_user, fixture_alerts):
    a = as_user("analyst_a")
    ov = a.get("/api/v1/posture/overview").json()
    assert ov["organization"] and ov["kpis"] and ov["measures"]
    for m in ov["measures"]:
        assert m["formula"] and m["weight"] > 0
        if m["state"] == "ok":
            assert m["denominator"] and m["value"] == round(100 * m["numerator"] / m["denominator"], 1)
        else:
            assert m["value"] is None and m["reason"]
    s = ov["score"]
    assert set(s["contributing"]).isdisjoint(s["excluded"])
    if s["state"] == "insufficient_data":
        assert s["score"] is None and s["coverage_percent"] < 50
    assert {src["connector"] for src in ov["sources"]} >= {"wazuh_manager", "ollama"}


def test_role_limits_are_not_permitted_not_zero(as_user):
    e = as_user("exec_a")
    ov = e.get("/api/v1/posture/overview").json()
    m = {x["key"]: x for x in ov["measures"]}
    assert m["sla_response"]["state"] == "not_permitted" and m["alert_triage"]["state"] == "not_permitted"
    assert "sla_response" in ov["score"]["excluded"]
    kpi = {x["key"]: x for x in ov["kpis"]}
    assert kpi["open_incidents"]["state"] == "not_permitted" and kpi["open_incidents"]["value"] is None
    assert as_user("portal_a").get("/api/v1/posture/overview").status_code == 200   # org:read; every section not permitted
    pm = {x["key"]: x["state"] for x in as_user("portal_a").get("/api/v1/posture/overview").json()["measures"]}
    assert set(pm.values()) == {"not_permitted"}


def test_empty_organization_withholds_the_score_and_lists_gaps(as_user, world):
    admin = as_user("admin")
    pa = admin.get("/api/v1/posture/assessment", org=world.gamma).json()
    assert pa["score"]["state"] == "insufficient_data" and pa["score"]["score"] is None
    keys = {g["key"] for g in pa["gaps"]}
    assert {"no_sla", "no_wazuh_mapping", "no_response_policy", "no_recovery_plan"} <= keys
    assert pa["compliance"]["source"]["state"] in ("unconfigured", "local_fixture", "connected", "unavailable")
    assert [a["key"] for a in pa["areas"]] == ["coverage", "exposure", "remediation", "detection_response", "email"]
