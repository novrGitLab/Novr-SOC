"""The Phase 2 integration example (API level): create -> list -> get, and cross-tenant refusal."""
import uuid

from tests.conftest import audit_actions


def test_create_list_get_and_cross_tenant_refusal(login, owner, world):
    mgr_b = login("manager_b")
    name = f"HQ-{uuid.uuid4().hex[:6]}"
    r = mgr_b.post("/api/v1/sites", json={"name": name, "description": "disposable", "network_cidrs": ["10.20.0.5/16"]})
    assert r.status_code == 201, r.text
    site = r.json()
    assert site["org_id"] == str(world.beta) and site["network_cidrs"] == ["10.20.0.0/16"]

    assert any(s["id"] == site["id"] for s in mgr_b.get("/api/v1/sites").json()["items"])
    assert mgr_b.get(f"/api/v1/sites/{site['id']}").status_code == 200

    other = login("analyst_a")  # organization alpha
    assert all(s["id"] != site["id"] for s in other.get("/api/v1/sites").json()["items"])
    r = other.get(f"/api/v1/sites/{site['id']}")
    assert r.status_code == 404 and r.json()["error"]["code"] == "not_found"

    assert any(e["resource_id"] == site["id"] for e in audit_actions(owner, org=world.beta, action="SITE_CREATED"))


def test_permission_is_enforced_and_denial_audited(login, owner, world):
    r = login("analyst_a").post("/api/v1/sites", json={"name": "not-allowed"})
    assert r.status_code == 403 and r.json()["error"]["details"] == {"required": "sites:manage"}
    assert any(e["resource_id"] == "sites:manage" for e in audit_actions(owner, org=world.alpha, action="PERMISSION_DENIED"))


def test_duplicate_name_conflicts(login):
    s = login("manager_b")
    name = f"dup-{uuid.uuid4().hex[:6]}"
    assert s.post("/api/v1/sites", json={"name": name}).status_code == 201
    r = s.post("/api/v1/sites", json={"name": name})
    assert r.status_code == 409 and r.json()["error"]["code"] == "conflict"


def test_validation_errors_are_structured(login):
    s = login("manager_b")
    r = s.post("/api/v1/sites", json={"name": "x", "network_cidrs": ["not-a-cidr"]})
    assert r.status_code == 422 and r.json()["error"]["code"] == "validation_error"
    r = s.post("/api/v1/sites", json={"name": "x", "org_id": str(uuid.uuid4())})
    assert r.status_code == 422, "an org_id in the body is rejected, never trusted"


def test_audit_events_are_tenant_scoped(login, world):
    events = login("manager_b").get("/api/v1/audit/events").json()["items"]
    assert events and all(e["org_id"] == str(world.beta) for e in events)
