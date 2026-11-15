"""Tenant administration and CNII Watch (pilot)."""
import uuid
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from tests.conftest import Session, audit_actions


def test_orgs_users_and_status(app, world, login, owner):
    admin = login("admin")
    slug = f"pilot-{uuid.uuid4().hex[:6]}"
    org = admin.post("/api/v1/admin/organizations", {"slug": slug, "name": "Pilot Client"}).json()
    assert org["kind"] == "client"
    assert admin.post("/api/v1/admin/organizations", {"slug": slug, "name": "dup"}).status_code == 409
    assert slug in {o["slug"] for o in admin.get("/api/v1/admin/organizations").json()["items"]}
    email = f"new-{uuid.uuid4().hex[:6]}@test.novrsoc.invalid"
    created = admin.post("/api/v1/admin/users", {"email": email, "role": "analyst"}, org=org["id"])
    assert created.status_code == 201
    pw = created.json()["temporary_password"]
    uid = created.json()["user"]["id"]
    assert admin.post("/api/v1/admin/users", {"email": email, "role": "analyst"}, org=org["id"]).status_code == 409
    assert admin.post("/api/v1/admin/users", {"email": f"x{email}", "role": "super_admin"}, org=org["id"]).status_code == 422
    newbie = Session(app, email, pw)
    assert newbie.get("/api/v1/auth/me").json()["role"] == "analyst"
    assert admin.post(f"/api/v1/admin/users/{uid}/status", {"status": "disabled"}, org=org["id"]).json()["status"] == "disabled"
    assert newbie.get("/api/v1/auth/me").status_code == 401                     # sessions revoked on disable
    assert admin.post(f"/api/v1/admin/users/{world.users['admin']}/status", {"status": "disabled"}).status_code == 409  # not yourself
    assert admin.post(f"/api/v1/admin/users/{uid}/status", {"status": "active"}).status_code == 404  # not in the platform org
    assert {"ORG_CREATED", "USER_CREATED", "USER_STATUS_CHANGED"} <= {e["action"] for e in audit_actions(owner, org=uuid.UUID(org["id"]))} | \
        {e["action"] for e in audit_actions(owner, org=world.platform)}
    for key in ("manager", "analyst_a", "manager_b"):
        assert login(key).get("/api/v1/admin/organizations").status_code == 403    # platform administrators only


def test_service_identities_issue_once_scope_rules_and_revoke(app, world, login):
    m = login("manager_b")
    issued = m.post("/api/v1/admin/service-identities", {"kind": "vms_worker", "name": "beta-local-worker", "scopes": ["vms:worker"]}).json()
    token, ident = issued["credential"], issued["identity"]
    assert token.startswith("nsk_") and ident["status"] == "active"
    assert all("credential" not in i for i in m.get("/api/v1/admin/service-identities").json()["items"])
    assert m.post("/api/v1/admin/service-identities", {"kind": "vms_worker", "name": "x", "scopes": ["alerts:ingest"]}).status_code == 422
    assert m.post("/api/v1/admin/service-identities", {"kind": "forwarder", "name": "x", "scopes": ["alerts:ingest"]}).status_code == 422
    c = TestClient(app)
    assert c.post("/api/v1/vms/worker/claim", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert login("analyst_a").post(f"/api/v1/admin/service-identities/{ident['id']}/revoke").status_code == 403
    assert login("manager").post(f"/api/v1/admin/service-identities/{ident['id']}/revoke", org=world.alpha).status_code == 404  # not alpha's
    assert m.post(f"/api/v1/admin/service-identities/{ident['id']}/revoke").json()["status"] == "revoked"
    assert c.post("/api/v1/vms/worker/claim", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_cnii_requires_permission_and_designation(app, world, login, owner):
    admin = login("admin")
    r = admin.client.put("/api/v1/cnii/profiles", json={"org_id": str(world.alpha), "sectors": ["power"], "criticality": "vital"},
                         headers={"X-CSRF-Token": admin.csrf})
    assert r.status_code == 200 and r.json()["org_name"] == "Test Alpha"
    analyst = login("analyst_a")                                                  # holds cnii:sector, no designation yet
    denied = analyst.get("/api/v1/cnii/sector-overview?sector=power")
    assert denied.status_code == 403 and denied.json()["error"]["details"]["designation"] == "required"
    expires = (datetime.now(timezone.utc) + timedelta(days=7)).isoformat()
    d = admin.post("/api/v1/cnii/designations", {"user_id": str(world.users["analyst_a"]), "sectors": ["power"], "reason": "Pilot CNII analyst",
                                                 "expires_at": expires}).json()
    ov = analyst.get("/api/v1/cnii/sector-overview?sector=power").json()
    assert ov["sector"] == "power" and [x["org_name"] for x in ov["items"]] == ["Test Alpha"]
    assert analyst.get("/api/v1/cnii/sector-overview?sector=water").status_code == 403    # another sector
    assert login("exec_a").get("/api/v1/cnii/sector-overview?sector=power").status_code == 403  # permission without designation
    assert [x["id"] for x in analyst.get("/api/v1/cnii/designations/mine").json()["items"]] == [d["id"]]
    assert admin.post("/api/v1/cnii/designations", {"user_id": str(world.users["admin"]), "sectors": ["power"], "reason": "self",
                                                    "expires_at": expires}).status_code == 403
    assert admin.post(f"/api/v1/cnii/designations/{d['id']}/revoke", {"designation_id": d["id"], "reason": "pilot over"}).status_code == 200
    assert analyst.get("/api/v1/cnii/sector-overview?sector=power").status_code == 403
    assert {"CNII_DESIGNATION_GRANTED", "CNII_DESIGNATION_REVOKED"} <= {e["action"] for e in audit_actions(owner, org=world.platform)}
    assert "CNII_ACCESS_DENIED" in {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_backups_are_platform_only(login):
    assert login("admin").get("/api/v1/admin/backups").status_code == 200
    assert login("manager").get("/api/v1/admin/backups").status_code == 403
