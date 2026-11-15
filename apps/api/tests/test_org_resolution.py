"""Port of the legacy approved access policy (lib/resolveOrg.ts) — role alone never reaches another org."""
import uuid

from tests.conftest import audit_actions


def test_analyst_cannot_switch_to_unassigned_org_and_it_is_audited(login, owner, world):
    s = login("analyst_a")
    r = s.get("/api/v1/sites", org=world.beta)
    assert r.status_code == 403 and r.json()["error"]["code"] == "forbidden"
    denied = audit_actions(owner, org=world.alpha, action="CROSS_ORG_DENIED")
    assert any(e["resource_id"] == str(world.beta) and e["actor_id"] == world.users["analyst_a"] for e in denied)


def test_analyst_with_operations_assignment_can_switch_and_it_is_audited(login, owner, world):
    s = login("analyst_assigned")
    r = s.get("/api/v1/auth/me", org=world.beta)
    assert r.status_code == 200 and r.json()["active_org"]["id"] == str(world.beta) and r.json()["cross_org"] is True
    assert any(e["actor_id"] == world.users["analyst_assigned"] for e in audit_actions(owner, org=world.beta, action="CROSS_ORG_ACCESS"))
    assert s.get("/api/v1/sites", org=world.alpha).status_code == 403  # not assigned there


def test_super_admin_reaches_any_existing_org_but_not_unknown(login, world):
    s = login("admin")
    assert s.get("/api/v1/auth/me", org=world.gamma).json()["active_org"]["id"] == str(world.gamma)
    r = s.get("/api/v1/auth/me", org=uuid.uuid4())
    assert r.status_code == 400 and r.json()["error"]["code"] == "unknown_org"
    orgs = s.get("/api/v1/orgs").json()
    assert orgs["all_organizations"] is True and {str(world.alpha), str(world.beta)} <= {o["id"] for o in orgs["items"]}


def test_malformed_org_header_is_rejected_for_staff(login):
    r = login("manager").get("/api/v1/auth/me", headers={"X-Org-Id": "t-alpha"})
    assert r.status_code == 400 and r.json()["error"]["code"] == "invalid_org"


def test_portal_user_header_is_ignored(login, world):
    s = login("portal_a")
    me = s.get("/api/v1/auth/me", org=world.beta).json()
    assert me["active_org"]["id"] == str(world.alpha) and me["cross_org"] is False
    assert s.get("/api/v1/sites").status_code == 403  # portal users hold no sites:read


def test_executive_without_assignment_keeps_own_org(login, world):
    me = login("exec_a").get("/api/v1/auth/me", org=world.gamma).json()
    assert me["active_org"]["id"] == str(world.alpha)


def test_executive_reporting_assignment_is_read_only(login, owner, world):
    s = login("exec_reporting")
    assert s.get("/api/v1/sites", org=world.gamma).status_code == 200
    r = s.post("/api/v1/sites", json={"name": "exec-write"}, org=world.gamma)
    assert r.status_code == 403
    assert any(e["resource_id"] == str(world.gamma) for e in audit_actions(owner, org=world.alpha, action="CROSS_ORG_DENIED"))


def test_org_list_shows_only_what_the_caller_may_act_on(login, world):
    ids = {o["id"] for o in login("manager").get("/api/v1/orgs").json()["items"]}
    assert ids == {str(world.platform), str(world.alpha)}
