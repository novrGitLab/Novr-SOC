"""Threat Insights engine (Phase 5, workstream F): deterministic, organization-scoped."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import text

from app.insights import engine
from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation

NOW = datetime(2026, 11, 13, tzinfo=timezone.utc)


@pytest.mark.parametrize("kind,value,expected", [
    ("ipv4", " 203.0.113.9 ", "203.0.113.9"), ("ipv4", "203.0.113.999", None), ("ipv4", "2001:db8::1", None),
    ("ipv6", "2001:DB8:0:0::1", "2001:db8::1"), ("domain", "Evil.Example.COM.", "evil.example.com"),
    ("domain", "not a domain", None), ("url", "HTTPS://Evil.example.com/x?y=1", "https://evil.example.com/x?y=1"),
    ("url", "ftp://x.example.com/", None), ("sha256", "A" * 64, "a" * 64), ("sha256", "abc", None),
    ("cve", "cve-2024-3094", "CVE-2024-3094"), ("cve", "CVE-24-1", None)])
def test_normalize_never_guesses(kind, value, expected):
    assert engine.normalize(kind, value) == expected


def test_observables_from_decoded_fields_then_bounded_text():
    raw = {"data": {"srcip": "203.0.113.9", "url": "http://bad.example.com/p", "hostname": "Bad.Example.com"},
           "syscheck": {"sha256_after": "B" * 64},
           "full_log": "conn from 198.51.100.7 to http://c2.example.net/x and 203.0.113.9 " + "x" * 20_000 + " 192.0.2.55"}
    obs = engine.extract_observables(raw, src_ip="203.0.113.9")
    got = [(o.type.value, o.value, o.source_field) for o in obs]
    assert got[0] == ("ipv4", "203.0.113.9", "src_ip")
    assert ("url", "http://bad.example.com/p", "data.url") in got and ("domain", "bad.example.com", "data.hostname") in got
    assert ("sha256", "b" * 64, "syscheck.sha256_after") in got
    assert ("ipv4", "198.51.100.7", "full_log") in got and ("url", "http://c2.example.net/x", "full_log") in got
    assert not any(v == "192.0.2.55" for _, v, _ in got)                 # beyond the bounded scan
    end = engine.extract_observables({"full_log": "blocked 198.51.100.8. Version 1.2.3.4.5 is not an IP"})
    assert [o.value for o in end] == ["198.51.100.8"]                     # sentence-final IP found; dotted runs ignored
    assert len([g for g in got if g[1] == "203.0.113.9"]) == 1           # de-duplicated


def test_confidence_policy_is_conservative_and_explained():
    fresh = engine.confidence(90, NOW - timedelta(days=1), None, "amber", "data.srcip", NOW)
    assert (fresh.score, fresh.band) == (90, "high")
    old_text = engine.confidence(90, NOW - timedelta(days=400), None, "amber", "full_log", NOW)
    assert (old_text.score, old_text.band) == (45, "medium") and len(old_text.reasons) == 3
    expired = engine.confidence(100, NOW - timedelta(days=10), NOW - timedelta(days=1), "red", "data.srcip", NOW)
    assert expired.score <= 30 and expired.band == "low"


def test_stix_round_trip_and_rejection_of_complex_patterns():
    bundle = {"type": "bundle", "id": "bundle--1", "objects": [
        {"type": "indicator", "spec_version": "2.1", "id": "indicator--a", "pattern": "[ipv4-addr:value = '203.0.113.9']",
         "pattern_type": "stix", "valid_from": "2026-11-01T00:00:00Z", "confidence": 80,
         "object_marking_refs": [engine.TLP_MARKING["green"]]},
        {"type": "indicator", "spec_version": "2.1", "id": "indicator--b",
         "pattern": "[ipv4-addr:value = '1.2.3.4'] OR [domain-name:value = 'x.example.com']", "pattern_type": "stix",
         "valid_from": "2026-11-01T00:00:00Z"},
        {"type": "indicator", "id": "indicator--c", "pattern": "alert tcp any", "pattern_type": "snort", "valid_from": "2026-11-01T00:00:00Z"},
        {"type": "malware", "id": "malware--d"}]}
    found, skipped = engine.parse_stix_bundle(bundle)
    assert [(i.type.value, i.value, i.confidence, i.tlp.value) for i, _, _ in found] == [("ipv4", "203.0.113.9", 80, "green")]
    assert len(skipped) == 2
    assert engine.parse_stix_bundle({"type": "nope"})[1] == ["not a STIX 2.1 bundle"]


# ---------------------------------------------------------------- API
def _alert(owner, org, xid, src_ip, full_log="", agent="001", rule="5710", when=None):
    with owner.begin() as c:
        return c.execute(text("""INSERT INTO novrsoc.alerts (org_id, source, external_id, rule_id, rule_level, rule_description, severity,
                                   agent_id, agent_name, agent_groups, src_ip, observed_at, raw)
                                 VALUES (:o, 'wazuh', :x, :r, 10, 'test', 'high', :a, 'h', '{}', CAST(:ip AS inet), :t, CAST(:raw AS jsonb))
                                 RETURNING id"""),
                         {"o": org, "x": xid, "r": rule, "a": agent, "ip": src_ip, "t": when or datetime.now(timezone.utc),
                          "raw": f'{{"full_log": "{full_log}"}}'}).scalar()


def test_import_match_correlate_and_isolate(owner, world, as_user):
    a, b = as_user("analyst_a"), as_user("manager_b")
    tag = uuid.uuid4().hex[:6]
    r = a.post("/api/v1/insights/indicators", {"source": f"feed-{tag}", "indicators": [
        {"type": "ipv4", "value": "203.0.113.77", "tlp": "amber", "source": "feed", "first_seen_at": "2026-11-01T00:00:00Z", "confidence": 85},
        {"type": "domain", "value": "not valid!", "tlp": "amber", "source": "feed", "first_seen_at": "2026-11-01T00:00:00Z", "confidence": 50}]})
    assert r.status_code == 200 and r.json()["imported"] == 1 and len(r.json()["skipped"]) == 1
    again = a.post("/api/v1/insights/indicators", {"source": f"feed-{tag}", "indicators": [
        {"type": "ipv4", "value": "203.0.113.77", "tlp": "amber", "source": "feed", "first_seen_at": "2026-11-01T00:00:00Z", "confidence": 85}]})
    assert again.json()["unchanged"] == 1
    a1 = _alert(owner, world.alpha, f"ti-{tag}-1", "203.0.113.77")
    a2 = _alert(owner, world.alpha, f"ti-{tag}-2", "198.51.100.1", full_log="seen 203.0.113.77 again")
    _alert(owner, world.beta, f"ti-{tag}-3", "203.0.113.77")             # beta's alert: never matched with alpha's indicator
    run = a.post("/api/v1/insights/match?hours=1").json()
    assert run["new_matches"] >= 2
    assert a.post("/api/v1/insights/match?hours=1").json()["new_matches"] == 0      # idempotent
    matches = a.get("/api/v1/insights/matches").json()["items"]
    mine = {m["alert_id"]: m for m in matches if m["indicator"]["value"] == "203.0.113.77"}
    assert set(mine) >= {str(a1), str(a2)}
    assert mine[str(a1)]["confidence"]["band"] == "high" and mine[str(a2)]["confidence"]["score"] == 70  # free text: -15
    assert b.post("/api/v1/insights/match?hours=1").json()["new_matches"] == 0    # beta has no indicators
    assert b.get("/api/v1/insights/matches").json()["items"] == []
    corr = a.get("/api/v1/insights/correlations?hours=1").json()["items"]
    shared = next(g for g in corr if g["key"] == "ipv4:203.0.113.77")
    assert set(shared["alert_ids"]) >= {str(a1), str(a2)}
    bundle = a.get("/api/v1/insights/stix").json()
    assert bundle["type"] == "bundle" and any(o["type"] == "sighting" for o in bundle["objects"])
    ind = next(o for o in bundle["objects"] if o["type"] == "indicator" and "203.0.113.77" in o["pattern"])
    assert ind["spec_version"] == "2.1" and ind["external_references"][0]["source_name"] == f"feed-{tag}"
    mid = mine[str(a1)]["id"]
    assert a.post(f"/api/v1/insights/matches/{mid}/verdict", {"match_id": mid, "verdict": "false_positive"}).status_code == 422
    assert a.post(f"/api/v1/insights/matches/{mid}/verdict", {"match_id": mid, "verdict": "true_positive"}).status_code == 200
    assert b.post(f"/api/v1/insights/matches/{mid}/verdict", {"match_id": mid, "verdict": "benign"}).status_code == 404
    assert {"TI_INDICATORS_IMPORTED", "TI_MATCH_RUN", "TI_MATCH_VERDICT"} <= {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_permissions(as_user):
    assert as_user("portal_a").get("/api/v1/insights/indicators").status_code == 403
    assert as_user("exec_a").get("/api/v1/insights/indicators").status_code == 200
    assert as_user("exec_a").post("/api/v1/insights/match").status_code == 403


def test_tables_are_tenant_isolated(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.ti_indicators", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "type": "ipv4", "value": f"192.0.2.{uuid.uuid4().int % 250}",
                                                  "tlp": "amber", "confidence": 50, "valid_from": NOW,
                                                  "stix_id": f"indicator--{uuid.uuid4()}", "source": f"iso-{uuid.uuid4().hex[:6]}"},
                            update_set="confidence = 1")
