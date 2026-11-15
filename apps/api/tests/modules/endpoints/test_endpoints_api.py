"""Endpoint management: inventory, details, connector states, group mappings, isolation."""
import uuid

from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation


def test_unconfigured_connector_returns_no_endpoints_and_says_so(app, world, mapped, as_user):
    c = as_user("analyst_a", app)  # the default app: NOVRSOC_WAZUH_MODE unconfigured
    r = c.get("/api/v1/endpoints")
    assert r.status_code == 200
    body = r.json()
    assert body["source"]["state"] == "unconfigured" and body["items"] == [] and body["mapped_groups"] == 2
    d = c.get("/api/v1/endpoints/001")
    assert d.status_code == 503 and d.json()["error"]["code"] == "integration_unconfigured"


def test_fixture_inventory_is_labelled_and_scoped_to_the_organization(world, mapped, as_user):
    alpha = as_user("analyst_a").get("/api/v1/endpoints").json()
    assert alpha["source"]["state"] == "local_fixture" and "Not live telemetry" in alpha["source"]["detail"]
    assert sorted(i["agent_id"] for i in alpha["items"]) == ["001", "002", "003"]
    assert alpha["by_status"] == {"active": 2, "disconnected": 1}
    beta = as_user("manager_b").get("/api/v1/endpoints").json()
    assert [i["agent_id"] for i in beta["items"]] == ["004"], "beta sees only its own mapped groups"


def test_endpoint_detail_has_os_support_vulnerabilities_and_sca(world, mapped, as_user):
    d = as_user("analyst_a").get("/api/v1/endpoints/001").json()
    assert d["endpoint"]["os"] == {"platform": "ubuntu", "name": "Ubuntu", "version": "22.04.4 LTS", "support": "supported"}
    assert d["vulnerabilities"]["total"] == 17 and d["vulnerabilities"]["critical"] == 1
    assert d["vulnerabilities"]["source"]["state"] == "local_fixture"
    pol = d["sca"]["policies"][0]
    assert pol["policy_id"] == "cis_ubuntu22-04" and pol["score_percent"] == round(100 * 132 / 190)


def test_another_organizations_or_unmapped_endpoint_is_not_found(world, mapped, as_user):
    assert as_user("analyst_a").get("/api/v1/endpoints/004").status_code == 404   # beta's endpoint
    assert as_user("manager_b").get("/api/v1/endpoints/001").status_code == 404   # alpha's endpoint
    assert as_user("analyst_a").get("/api/v1/endpoints/005").status_code == 404   # unmapped lab group
    assert as_user("analyst_a").get("/api/v1/endpoints/not-an-id").status_code == 422


def test_permissions(world, mapped, as_user):
    assert as_user("portal_a").get("/api/v1/endpoints").status_code == 403          # no endpoints:read
    assert as_user("exec_a").get("/api/v1/endpoints").status_code == 200            # executives may read
    r = as_user("analyst_a").post("/api/v1/endpoints/group-mappings", {"group_name": "x-analyst"})
    assert r.status_code == 403                                                      # mapping needs endpoints:manage


def test_group_mapping_lifecycle_conflicts_and_audit(owner, world, mapped, as_user):
    m = as_user("manager_b")
    name = f"beta-extra-{uuid.uuid4().hex[:6]}"
    r = m.post("/api/v1/endpoints/group-mappings", {"group_name": name})
    assert r.status_code == 201
    assert m.post("/api/v1/endpoints/group-mappings", {"group_name": "nv-alpha-servers"}).status_code == 409  # owned by alpha
    assert m.post("/api/v1/endpoints/group-mappings", {"group_name": "bad name!"}).status_code == 422
    assert name in [i["group_name"] for i in m.get("/api/v1/endpoints/group-mappings").json()["items"]]
    assert as_user("analyst_a").get("/api/v1/endpoints/group-mappings").json()["items"].__len__() == 2  # alpha sees its own only
    mid = r.json()["id"]
    assert as_user("manager").delete(f"/api/v1/endpoints/group-mappings/{mid}").status_code == 404  # manager acts in platform org
    assert m.delete(f"/api/v1/endpoints/group-mappings/{mid}").status_code == 204
    assert {"WAZUH_GROUP_MAPPED", "WAZUH_GROUP_UNMAPPED"} <= {e["action"] for e in audit_actions(owner, org=world.beta)}


def test_group_mappings_are_tenant_isolated(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.wazuh_group_mappings", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "group_name": f"iso-{uuid.uuid4().hex[:8]}"},
                            update_set=None, deletable=True)  # mappings are create/delete only for the API role
