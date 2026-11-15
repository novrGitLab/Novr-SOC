"""STIX 2.1 / TAXII 2.1 interoperability: TAXII test server -> Server 1 feeder (real code) -> real API ingest -> store,
relationships, indicator import -> deterministic match -> NHAI evidence with STIX context. Offline."""
import importlib
import sys
import uuid
from pathlib import Path

from fastapi.testclient import TestClient

from app import devseed
from novrsoc_contracts import stix21

TI = Path(__file__).resolve().parents[5] / "services" / "edge" / "threat_intel"
sys.path[:0] = [str(TI), str(TI / "tests")]
feeder = importlib.import_module("novrsoc_ti.feeder")
taxii = importlib.import_module("novrsoc_ti.taxii")
server = importlib.import_module("taxii_test_server")


class SinkViaTestClient:
    def __init__(self, app):
        self.c = TestClient(app)

    def deliver(self, token, source, collection, objects):
        r = self.c.post("/api/v1/insights/ingest/stix", json={"source": source, "collection": collection,
                                                              "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}},
                        headers={"Authorization": f"Bearer {token}"})
        if r.status_code != 200:
            raise taxii.TaxiiError(f"NovrSOC API refused the bundle ({r.status_code})", r.status_code)
        return r.json()


def test_stix_validator_cases():
    ok = server.DEMO_BUNDLE_OBJECTS[:3]
    objs, rej = stix21.normalize_bundle({"type": "bundle", "id": "bundle--x", "objects": ok + [
        {**ok[1], "spec_version": "2.0"}, {**ok[2], "target_ref": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad"},
        {**ok[0], "id": "malware--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f"}, {"type": "x-custom", "id": "x"}]})
    assert len(objs) == 3 and len(rej) == 4
    assert stix21.validate_object({**ok[0], "valid_until": "2026-10-01T00:00:00Z"}) == ["valid_until must be a timestamp after valid_from"]
    assert stix21.normalize_bundle([]) == ([], ["not a STIX 2.1 bundle"])


def test_taxii_feed_to_api_to_match_to_nhai_evidence(fixture_app, fixture_alerts, owner, world, as_user, tmp_path):
    with owner.begin() as c:
        _, token = devseed.create_service_identity(c, world.alpha, "ti_feeder", "alpha-taxii", scopes=["intel:ingest"])
    (tmp_path / "t").write_text(token)
    cfg = {"api_url": "http://127.0.0.1:1", "state_file": str(tmp_path / "state.json"),
           "sources": [{"name": "demo-isac", "api_root": None, "collection_id": server.COLLECTION, "user": server.USER,
                        "token_file": str(tmp_path / "t"), "enabled": True, "page_size": 2}]}
    with server.TaxiiTestServer() as srv:
        cfg["sources"][0]["api_root"] = srv.url + "/api1/"
        out = feeder.run_once(cfg, lambda e, f: None, client_factory=lambda s: taxii.TaxiiClient(server.USER, server.PASSWORD, allow_loopback_http=True),
                              sink=SinkViaTestClient(fixture_app))["demo-isac"]
    assert (out["received"], out["sent"], out["invalid"], out["indicators"]) == (5, 4, 1, 2)
    a = as_user("analyst_a")
    runs = a.get("/api/v1/insights/feed-runs").json()["items"]
    assert runs and runs[0]["source"] == "demo-isac"
    ind = next(i for i in a.get("/api/v1/insights/indicators").json()["items"] if i["value"] == "203.0.113.45")
    assert ind["provenance"]["source"] == "demo-isac" and ind["confidence"] == 80 and ind["tlp"] == "amber"
    ctx = a.get(f"/api/v1/insights/indicators/{ind['id']}/context").json()["related"]
    assert ctx == [{"stix_id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc", "type": "malware", "name": "SSHBrute (demo family)",
                    "relationship_type": "indicates", "edge": "outgoing"}]
    a.post("/api/v1/insights/match?hours=744")
    alert = next(x for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"] if x["rule_id"] == "5712")
    m = [x for x in a.get(f"/api/v1/insights/matches?alert_id={alert['id']}").json()["items"] if x["indicator"]["value"] == "203.0.113.45"]
    assert m and m[0]["observable"]["source_field"] == "src_ip"
    from app.nhai.evidence import alert_bundle
    from sqlalchemy import text
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        b = alert_bundle(c, world.alpha, world.users["analyst_a"], uuid.UUID(alert["id"]), max_chars=12000)
    ti = [e.excerpt for e in b.evidence if e.ref.type == "ti_match"]
    assert ti and "indicates malware 'SSHBrute (demo family)'" in ti[0]
    # isolation: beta sees none of it; a feeder identity of alpha can never write into beta
    bm = as_user("manager_b")
    assert all(i["value"] != "203.0.113.45" for i in bm.get("/api/v1/insights/indicators").json()["items"])
    assert bm.get(f"/api/v1/insights/indicators/{ind['id']}/context").status_code == 404


def test_only_ti_feeder_identities_may_ingest(fixture_app, owner, world):
    with owner.begin() as c:
        _, fwd = devseed.create_service_identity(c, world.platform, "forwarder", "not-a-feeder", scopes=["alerts:ingest"])
        _, unscoped = devseed.create_service_identity(c, world.alpha, "ti_feeder", "no-scope")
    body = {"source": "x-feed", "bundle": {"type": "bundle", "objects": []}}
    c = TestClient(fixture_app)
    for tok in (fwd, unscoped):
        assert c.post("/api/v1/insights/ingest/stix", json=body, headers={"Authorization": f"Bearer {tok}"}).status_code == 403
    assert c.post("/api/v1/insights/ingest/stix", json=body).status_code == 401
