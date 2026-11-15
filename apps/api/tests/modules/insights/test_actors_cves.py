"""Threat actors (explicit attribution, verified links only to records of the organization), CVE intelligence (KEV
catalog import, correlation with findings), checksummed CVSS/IOC snapshots, isolation."""
import hashlib
import json
import uuid

from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation

SRC = [{"name": "Vendor report", "url": "https://example.org/report", "published": "2026-01-10"}]


def test_attribution_rules_and_verified_links(as_user, fixture_alerts, world, owner):
    a = as_user("analyst_a")
    assert a.post("/api/v1/insights/actors", {"name": "Nameless", "attribution": "verified"}).status_code == 422    # no source
    assert a.post("/api/v1/insights/actors", {"name": "Nameless", "attribution": "unknown", "confidence": 40}).status_code == 422
    sus = a.post("/api/v1/insights/actors", {"name": f"Cluster-{uuid.uuid4().hex[:4]}", "attribution": "suspected", "confidence": 30,
                                             "techniques": ["T1110"]}).json()
    alert = a.get("/api/v1/soc/alerts?limit=200").json()["items"][0]["id"]
    r = a.post(f"/api/v1/insights/actors/{sus['id']}/links", {"link_type": "alert", "ref_id": alert, "association": "verified",
                                                              "rationale": "Same infrastructure"})
    assert r.status_code == 422                                                         # verified link needs a verified actor
    sus = a.post(f"/api/v1/insights/actors/{sus['id']}/links", {"link_type": "alert", "ref_id": alert, "association": "suspected",
                                                                "rationale": "Same SSH dictionary"}).json()
    assert sus["observed_in_organization"] is False and sus["links"][0]["exists"] is True
    ver = a.post("/api/v1/insights/actors", {"name": f"Group-{uuid.uuid4().hex[:4]}", "attribution": "verified", "confidence": 70,
                                             "sources": SRC}).json()
    ver = a.post(f"/api/v1/insights/actors/{ver['id']}/links", {"link_type": "alert", "ref_id": alert, "association": "verified",
                                                                "rationale": "Confirmed by IR"}).json()
    assert ver["observed_in_organization"] is True
    assert a.post(f"/api/v1/insights/actors/{ver['id']}/links", {"link_type": "case", "ref_id": str(uuid.uuid4()), "association": "suspected",
                                                                 "rationale": "unknown case"}).status_code == 404
    beta_alert = as_user("analyst_b").get("/api/v1/soc/alerts").json()["items"][0]["id"]
    assert a.post(f"/api/v1/insights/actors/{ver['id']}/links", {"link_type": "alert", "ref_id": beta_alert, "association": "suspected",
                                                                 "rationale": "another tenant"}).status_code == 404
    assert as_user("analyst_b").get("/api/v1/insights/actors").json()["items"] == [] or \
        all(x["id"] != ver["id"] for x in as_user("analyst_b").get("/api/v1/insights/actors").json()["items"])
    assert as_user("exec_a").post("/api/v1/insights/actors", {"name": "x1", "attribution": "unknown"}).status_code == 403
    assert {"TI_ACTOR_CREATED", "TI_ACTOR_LINKED"} <= {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_actor_table_isolation(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.ti_threat_actors", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "name": f"iso-{uuid.uuid4().hex[:6]}", "attribution": "unknown"},
                            update_set="description = 'tampered'")


def test_cve_intelligence_and_snapshots(as_user, world):
    a = as_user("analyst_a")
    cve = f"CVE-2031-{uuid.uuid4().int % 90000 + 10000}"
    out = a.post("/api/v1/insights/cves/import", {"source": "analyst-file", "records": [{"cve_id": cve, "cvss_v3": 9.8, "epss": 0.97}],
                                                  "kev_catalog": {"vulnerabilities": [{"cveID": cve, "dateAdded": "2031-01-02"},
                                                                                      {"cveID": "not-a-cve"}]}}).json()
    assert out["imported"] == 2 and out["skipped"]
    row = next(x for x in a.get(f"/api/v1/insights/cves?q={cve}").json()["items"] if x["cve_id"] == cve)
    assert row["snapshots"] == 2 and row["kev"] is True and row["open_findings"] == 0
    snap = a.post("/api/v1/insights/snapshots", {"kind": "cvss", "subject": cve, "reason": "Evidence for case review"}).json()
    canonical = json.dumps(snap["content"], sort_keys=True, default=str)
    assert hashlib.sha256(canonical.encode()).hexdigest() == snap["sha256"] and len(snap["content"]["records"]) == 2
    assert a.post("/api/v1/insights/snapshots", {"kind": "cvss", "subject": "CVE-2000-0001"}).status_code == 404
    ind = a.post("/api/v1/insights/indicators", {"source": "analyst", "indicators": [{"type": "ipv4", "value": "198.51.100.77", "tlp": "amber",
                                                                                     "source": "analyst", "first_seen_at": "2026-11-01T00:00:00Z",
                                                                                     "confidence": 60}]})
    assert ind.status_code == 200
    iid = next(i["id"] for i in a.get("/api/v1/insights/indicators").json()["items"] if i["value"] == "198.51.100.77")
    ioc = a.post("/api/v1/insights/snapshots", {"kind": "ioc", "subject": iid}).json()
    assert ioc["content"]["indicator"]["value"] == "198.51.100.77" and ioc["subject"] == iid
    assert all(x["cve_id"] != cve for x in as_user("analyst_b").get("/api/v1/insights/cves").json()["items"])
    assert as_user("analyst_b").get(f"/api/v1/insights/snapshots?subject={cve}").json()["items"] == []
