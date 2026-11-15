"""Unified asset inventory: canonical identity and reconciliation rules, Wazuh sync, alert links, merge, collectors,
permissions and tenant isolation."""
import uuid

from sqlalchemy import text

from app import devseed
from app.assets import reconcile
from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation


def _obs(owner, org, obs: reconcile.Observation) -> reconcile.Outcome:
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
        return reconcile.upsert(c, obs, "test")


def test_wazuh_sync_is_idempotent_and_alerts_link_to_canonical_assets(as_user, fixture_alerts, world):
    m = as_user("manager")
    first = m.post("/api/v1/assets/sync/wazuh", {}, org=world.alpha).json()
    assert first["outcome"] == "completed" and first["source_state"] == "local_fixture" and first["observed"] >= 1
    again = m.post("/api/v1/assets/sync/wazuh", {}, org=world.alpha).json()
    assert again["created"] == 0 and again["updated"] == first["observed"]               # no duplicates on a second sync
    a = as_user("analyst_a")
    alerts = a.get("/api/v1/soc/alerts?limit=200").json()["items"]
    assert alerts and all(x["asset_id"] for x in alerts if x["agent_id"])                # every agent alert has its asset
    agent = alerts[0]["agent_id"]
    assets = [x for x in a.get("/api/v1/assets?limit=500").json()["items"] if x["monitoring"]["wazuh_agent_id"] == agent]
    assert len(assets) == 1 and assets[0]["id"] == alerts[0]["asset_id"] and "wazuh" in assets[0]["sources"]
    d = a.get(f"/api/v1/assets/{assets[0]['id']}").json()
    assert d["wazuh"]["source"]["state"] == "local_fixture" and d["wazuh"]["agent_id"] == agent
    assert any(x["id"] == alerts[0]["id"] for x in d["alerts"]) or d["alerts"]


def test_reconciliation_rules(owner, world):
    org = world.gamma
    with owner.begin() as c:
        site_a = devseed.create_site(c, org, f"rs-a-{uuid.uuid4().hex[:4]}", ["10.77.0.0/16"])
        site_b = devseed.create_site(c, org, f"rs-b-{uuid.uuid4().hex[:4]}", [])
    # 1. same agent id twice -> the same asset
    o1 = _obs(owner, org, reconcile.Observation("wazuh", "host", "gw-01", [("wazuh_agent", "9001"), ("hostname", "gw-01"), ("ip", "10.77.0.5")]))
    o2 = _obs(owner, org, reconcile.Observation("wazuh", "host", "gw-01", [("wazuh_agent", "9001")]))
    assert o1.created and not o2.created and o1.asset_id == o2.asset_id
    # 2. a reused DHCP address with a DIFFERENT agent id is a different asset, and the IP is recorded as a conflict
    o3 = _obs(owner, org, reconcile.Observation("wazuh", "host", "laptop-7", [("wazuh_agent", "9002"), ("ip", "10.77.0.5")]))
    assert o3.created and o3.asset_id != o1.asset_id and o3.conflicts == 1
    # 3. a weak match (IP only) joins the existing asset
    o4 = _obs(owner, org, reconcile.Observation("vms", "host", "10.77.0.5", [("ip", "10.77.0.5")]))
    assert o4.asset_id == o1.asset_id and not o4.created
    # 4. addresses are site-scoped: the same private IP at another site is another asset
    o5 = _obs(owner, org, reconcile.Observation("manual", "host", "branch-gw", [("ip", "10.77.0.5")], site_id=site_b))
    assert o5.created and o5.asset_id != o1.asset_id
    # 5. identifiers are normalized (case, MAC separators)
    o6 = _obs(owner, org, reconcile.Observation("collector", "host", "GW-01", [("hostname", "GW-01.corp.local"), ("mac", "AA-BB-CC-00-11-22")]))
    assert o6.asset_id == o1.asset_id
    o7 = _obs(owner, org, reconcile.Observation("manual", "host", "x", [("mac", "aa:bb:cc:00:11:22")]))
    assert o7.asset_id == o1.asset_id
    with owner.connect() as c:
        kinds = {r[0] for r in c.execute(text("SELECT kind FROM novrsoc.asset_events WHERE asset_id = :a"), {"a": o3.asset_id})}
        assert {"discovered", "identifier_conflict"} <= kinds
        assert site_a  # the site that contains 10.77.0.5 scoped the first address
        sk = c.execute(text("SELECT site_key FROM novrsoc.asset_identifiers WHERE asset_id = :a AND kind = 'ip'"), {"a": o1.asset_id}).scalar()
        assert sk == str(site_a)


def test_manual_create_reconciles_merge_and_retire(as_user, world, owner):
    a = as_user("analyst_a")
    ip = f"192.0.2.{uuid.uuid4().int % 200 + 20}"
    r1 = a.post("/api/v1/assets", {"kind": "host", "display_name": "erp-db", "ip": ip, "criticality": "critical", "owner": "Finance IT"})
    assert r1.status_code == 201
    r2 = a.post("/api/v1/assets", {"kind": "host", "display_name": "erp-db (duplicate entry)", "ip": ip})
    assert r2.status_code == 200 and r2.json()["id"] == r1.json()["id"]                  # one identity, not a duplicate
    assert a.post("/api/v1/assets", {"kind": "host", "display_name": "nothing"}).status_code == 422
    other = a.post("/api/v1/assets", {"kind": "host", "display_name": "erp-db-old", "hostname": f"erp-old-{uuid.uuid4().hex[:4]}"}).json()
    merged = a.post(f"/api/v1/assets/{r1.json()['id']}/merge", {"source_asset_id": other["id"], "reason": "same server, renamed"}).json()
    assert merged["status"] == "active"
    gone = a.get(f"/api/v1/assets/{other['id']}").json()["asset"]
    assert gone["status"] == "retired" and gone["merged_into"] == r1.json()["id"]
    idents = {(i["kind"], i["value"]) for i in a.get(f"/api/v1/assets/{r1.json()['id']}").json()["identifiers"]}
    assert ("hostname", other["hostname"]) in idents
    upd = a.patch(f"/api/v1/assets/{r1.json()['id']}", {"classification": "server", "exposure": "internal", "tags": ["erp"]}).json()
    assert upd["classification"] == "server" and upd["tags"] == ["erp"]
    assert any(e["kind"] == "reclassified" for e in a.get(f"/api/v1/assets/{r1.json()['id']}").json()["events"])
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"ASSET_CREATED", "ASSET_RECONCILED", "ASSET_MERGED", "ASSET_UPDATED"} <= acts


def test_permissions_isolation_and_collectors(as_user, world, owner, app_engine):
    a = as_user("analyst_a")
    created = a.post("/api/v1/assets", {"kind": "domain", "display_name": f"alpha-{uuid.uuid4().hex[:4]}.example"}).json()
    b = as_user("manager_b")
    assert b.get(f"/api/v1/assets/{created['id']}").status_code == 404
    assert all(x["id"] != created["id"] for x in b.get("/api/v1/assets?status=all&limit=500").json()["items"])
    assert as_user("portal_a").get("/api/v1/assets").status_code == 403
    e = as_user("exec_a")
    assert e.get("/api/v1/assets").status_code == 200 and e.post("/api/v1/assets", {"kind": "host", "display_name": "x", "ip": "192.0.2.9"}).status_code == 403
    assert_tenant_isolation(owner, app_engine, table="novrsoc.assets", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "kind": "host", "display_name": f"iso-{uuid.uuid4().hex[:6]}"},
                            update_set="owner = 'tampered'")
    m = as_user("manager")
    c = m.post("/api/v1/assets/collectors", {"name": f"scan-{uuid.uuid4().hex[:4]}", "kind": "network_discovery",
                                             "settings": {"ranges": ["10.0.0.0/24"]}}, org=world.alpha).json()
    assert c["enabled"] is False and "not authorized" in c["execution"]
    refused = m.patch(f"/api/v1/assets/collectors/{c['id']}", {"enabled": True}, org=world.alpha)
    assert refused.status_code == 422 and refused.json()["error"]["code"] == "authorization_required"
    run = m.post(f"/api/v1/assets/collectors/{c['id']}/run", {}, org=world.alpha).json()
    assert run["outcome"] == "source_unconfigured" and "nothing was scanned" in run["detail"]
    w = m.post("/api/v1/assets/collectors", {"name": f"wazuh-{uuid.uuid4().hex[:4]}", "kind": "wazuh_sync"}, org=world.alpha).json()
    assert m.post(f"/api/v1/assets/collectors/{w['id']}/run", {}, org=world.alpha).json()["outcome"] in ("completed", "source_unconfigured")
    assert b.post(f"/api/v1/assets/collectors/{c['id']}/run", {}).status_code == 404
    assert m.delete(f"/api/v1/assets/collectors/{c['id']}", org=world.alpha).status_code == 204
