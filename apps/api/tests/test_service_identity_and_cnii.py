import uuid

import pytest
from fastapi.testclient import TestClient

from app import devseed
from app.core.security import parse_machine_credential
from tests.conftest import audit_actions


@pytest.fixture(scope="module")
def collector(owner, world):
    with owner.begin() as c:
        site = devseed.create_site(c, world.alpha, f"collector-site-{uuid.uuid4().hex[:6]}", ["192.168.1.0/24"])
        ident, token = devseed.create_service_identity(c, world.alpha, "collector", "edge-1", site=site,
                                                       scopes=["telemetry:write", "heartbeat:write"])
    return ident, token, site


def test_org_and_site_come_from_the_identity_not_the_request(app, collector, world):
    ident, token, site = collector
    r = TestClient(app).get("/api/v1/service/whoami",
                            headers={"Authorization": f"Bearer {token}", "X-Org-Id": str(world.beta)})
    assert r.status_code == 200
    assert r.json() == {"identity_id": str(ident), "org_id": str(world.alpha), "site_id": str(site),
                        "kind": "collector", "scopes": ["heartbeat:write", "telemetry:write"]}


def test_bad_or_revoked_credentials_are_refused_and_audited(app, owner, world):
    with owner.begin() as c:
        ident, token = devseed.create_service_identity(c, world.alpha, "vms_worker", "w-1")
    client = TestClient(app)
    assert client.get("/api/v1/service/whoami", headers={"Authorization": f"Bearer {token}x"}).status_code == 401
    assert client.get("/api/v1/service/whoami", headers={"Authorization": "Bearer changeme"}).status_code == 401
    assert client.get("/api/v1/service/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    with owner.begin() as c:
        devseed.revoke_service_identity(c, ident)
    assert client.get("/api/v1/service/whoami", headers={"Authorization": f"Bearer {token}"}).status_code == 401
    reasons = {e["details"]["reason"] for e in audit_actions(owner, org=world.alpha, action="SERVICE_AUTH_FAILED")}
    assert {"bad_secret", "revoked_or_expired"} <= reasons


def test_short_or_malformed_machine_secrets_never_parse():
    assert parse_machine_credential("nsk_" + "0" * 32 + ".short") is None
    assert parse_machine_credential("Bearer something") is None


def test_cnii_needs_permission_and_designation(login, owner, world):
    s = login("analyst_a")  # holds cnii:read, no designation yet
    r = s.get("/api/v1/cnii/access", params={"sector": "power"})
    assert r.status_code == 403 and r.json()["error"]["details"]["designation"] == "required"
    with owner.begin() as c:
        devseed.grant_cnii(c, world.users["analyst_a"], ["power"], world.users["admin"])
    ok = s.get("/api/v1/cnii/access", params={"sector": "power"})
    assert ok.status_code == 200 and ok.json()["sector"] == "power"
    assert s.get("/api/v1/cnii/access", params={"sector": "water"}).status_code == 403
    assert login("portal_a").get("/api/v1/cnii/access", params={"sector": "power"}).status_code == 403
    actions = {e["action"] for e in audit_actions(owner, org=world.alpha) if e["resource_type"] == "cnii_sector"}
    assert {"CNII_ACCESS", "CNII_ACCESS_DENIED"} <= actions


def test_cnii_designation_scope_limits_organizations(login, owner, world):
    with owner.begin() as c:
        devseed.grant_cnii(c, world.users["manager"], ["finance"], world.users["admin"], scope_org_ids=[world.gamma])
    s = login("manager")  # home platform; alpha via operations assignment
    assert s.get("/api/v1/cnii/access", params={"sector": "finance"}, org=world.alpha).status_code == 403


def test_expired_designation_grants_nothing(login, owner, world):
    with owner.begin() as c:
        c.exec_driver_sql("""INSERT INTO novrsoc.cnii_designations (user_id, sectors, reason, granted_at, expires_at)
                             VALUES (%(u)s, ARRAY['health'], 'expired test', now() - interval '2 days', now() - interval '1 day')""",
                          {"u": world.users["exec_a"]})
    assert login("exec_a").get("/api/v1/cnii/access", params={"sector": "health"}).status_code == 403
