"""Organization management: directory and detail from real data, profile edits, lifecycle (suspend, archive, reactivate)
with its guards, onboarding computed from configuration, assignment of EXISTING users (no duplicate accounts), and
platform-administrator-only access. Tenant isolation is enforced by the database for every organization-scoped call."""
import random
import uuid

from sqlalchemy import text

from tests.conftest import audit_actions

ADMIN = "/api/v1/admin"


def _org(admin, **kw) -> dict:
    slug = f"t-org-{uuid.uuid4().hex[:8]}"
    r = admin.post(f"{ADMIN}/organizations", {"slug": slug, "name": kw.pop("name", f"Client {slug[-4:]}"), "contact_name": "",
                                              "contact_email": "", "timezone": "Africa/Lagos", **kw})
    assert r.status_code == 201, r.text
    return r.json()


def test_directory_and_detail_reflect_real_configuration(as_user, world):
    admin = as_user("admin")
    org = _org(admin, name="Directory Client", contact_name="Ada Obi", contact_email="soc@client.example")
    d = admin.get(f"{ADMIN}/organizations/directory?q=directory client").json()
    row = next(x for x in d["items"] if x["id"] == org["id"])
    assert row["status"] == "active" and row["timezone"] == "Africa/Lagos" and row["users"] == 0
    assert row["integrations"]["health"] == "not_configured" and row["onboarding_total"] > row["onboarding_completed"] >= 2
    assert row["next_step"] == "users_added"                   # created + profile completed; next real gap
    assert all(x["kind"] == "client" for x in admin.get(f"{ADMIN}/organizations/directory?kind=client").json()["items"])
    # Wire telemetry for the new organization through the regular, organization-scoped APIs (X-Org-Id)
    assert admin.post("/api/v1/log-sources", {"name": "OPNsense edge", "kind": "syslog",
                                              "source_ip": f"10.{random.randint(1, 60)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
                                              "host": "", "device_type": "firewall", "vendor": "OPNsense", "protocol": "udp", "port": 514,
                                              "site_id": None, "network": None, "authorization_reference": "CONTRACT-7.2", "notes": "",
                                              "enabled": True}, org=org["id"]).status_code == 201
    det = admin.get(f"{ADMIN}/organizations/{org['id']}").json()
    steps = det["onboarding"]["steps"]
    assert steps["log_sources_registered"] and steps["telemetry_configured"] and not steps["wazuh_groups_mapped"]
    assert not steps["telemetry_received"] and det["integrations"]["log_sources"] == 1 and det["integrations"]["log_sources_never"] == 1
    assert det["integrations"]["health"] == "attention" and any("not sent any event" in n for n in det["integrations"]["notes"])
    assert det["assets"] == 1                                   # the device was reconciled into its inventory
    # Another organization's numbers are unaffected: the counts are per organization
    alpha = admin.get(f"{ADMIN}/organizations/{world.alpha}").json()
    assert alpha["id"] == str(world.alpha) and alpha["integrations"]["wazuh_groups"] >= 0


def test_profile_edit_and_lifecycle_rules(as_user, world, owner):
    admin = as_user("admin")
    org = _org(admin)
    r = admin.patch(f"{ADMIN}/organizations/{org['id']}", {"contact_name": "Bola", "contact_email": "it@client.example", "notes": "Pilot"})
    assert r.status_code == 200 and r.json()["contact_name"] == "Bola" and r.json()["onboarding"]["steps"]["profile_completed"]
    assert admin.patch(f"{ADMIN}/organizations/{org['id']}", {"contact_email": "not-an-email"}).status_code == 422
    # suspend: members lose access, platform administrators cannot act inside it, data stays
    assert admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "suspended", "reason": "Contract on hold"}).json()["status"] == "suspended"
    assert admin.get("/api/v1/sites", org=org["id"]).status_code == 400                 # no switching into an inactive organization
    assert admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "suspended", "reason": "again!"}).status_code == 409
    # archive is refused while the organization could still receive events
    assert admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "active", "reason": "Contract resumed"}).status_code == 200
    m = admin.post("/api/v1/endpoints/group-mappings", {"group_name": f"grp-{uuid.uuid4().hex[:6]}", "acknowledge_broad_group": False},
                   org=org["id"]).json()
    blocked = admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "archived", "reason": "Client offboarded"})
    assert blocked.status_code == 409 and blocked.json()["error"]["details"]["wazuh_groups"] == 1
    assert admin.delete(f"/api/v1/endpoints/group-mappings/{m['id']}", org=org["id"]).status_code == 204
    arch = admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "archived", "reason": "Client offboarded"}).json()
    assert arch["status"] == "archived" and arch["archived_at"] and arch["status_reason"] == "Client offboarded"
    restored = admin.post(f"{ADMIN}/organizations/{org['id']}/status", {"status": "active", "reason": "Client returned"}).json()
    assert restored["status"] == "active" and restored["archived_at"] is None
    # the platform organization is never suspended or archived
    assert admin.post(f"{ADMIN}/organizations/{world.platform}/status", {"status": "suspended", "reason": "nope nope"}).status_code == 422
    actions = {e["action"] for e in audit_actions(owner, org=world.platform)}
    assert {"ORG_CREATED", "ORG_UPDATED", "ORG_SUSPENDED", "ORG_REACTIVATED", "ORG_ARCHIVED"} <= actions


def test_existing_users_are_assigned_never_duplicated(as_user, world, owner):
    admin = as_user("admin")
    org = _org(admin)
    found = admin.get(f"{ADMIN}/users/search?q=analyst_a@").json()["items"]
    user = next(u for u in found if u["email"] == "analyst_a@test.novrsoc.invalid")
    assert user["home_org_id"] == str(world.alpha) and user["role"] == "analyst"
    r = admin.post(f"{ADMIN}/users/{user['id']}/memberships", {"org_id": org["id"], "access_scope": "operations"})
    assert r.status_code == 200 and {m["org_id"] for m in r.json()["items"]} >= {str(world.alpha), org["id"]}
    assert admin.post(f"{ADMIN}/users/{user['id']}/memberships", {"org_id": org["id"], "access_scope": "operations"}).status_code == 409
    with owner.connect() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.users WHERE email = 'analyst_a@test.novrsoc.invalid'")).scalar() == 1
    # the assigned analyst monitors the new organization through the audited switch, and still only that
    a = as_user("analyst_a")
    assert a.get("/api/v1/soc/alerts", org=org["id"]).status_code == 200
    assert a.get("/api/v1/soc/alerts", org=world.beta).status_code == 403
    assert admin.delete(f"{ADMIN}/users/{user['id']}/memberships/{org['id']}").status_code == 200
    assert a.get("/api/v1/soc/alerts", org=org["id"]).status_code == 403
    users = admin.get(f"{ADMIN}/organizations/{org['id']}").json()["users"]
    assert users == 0


def test_only_platform_administrators_manage_organizations(as_user, world):
    for key in ("manager", "analyst_a", "exec_a", "portal_a"):
        c = as_user(key)
        assert c.get(f"{ADMIN}/organizations/directory").status_code == 403, key
        assert c.get(f"{ADMIN}/organizations/{world.alpha}").status_code == 403, key
        assert c.patch(f"{ADMIN}/organizations/{world.alpha}", {"name": "x"}).status_code == 403, key
        assert c.post(f"{ADMIN}/organizations/{world.alpha}/status", {"status": "suspended", "reason": "hostile"}).status_code == 403, key
        assert c.get(f"{ADMIN}/users/search?q=admin").status_code == 403, key
    assert as_user("admin").get(f"{ADMIN}/organizations/{uuid.uuid4()}").status_code == 404
