"""VMS integration foundation (Phase 5, workstream B): scanning disabled, worker identity, heartbeats, isolation."""
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient

from app import devseed
from tests.helpers.rls import assert_tenant_isolation


def _hb(version="1.8.2"):
    return {"sent_at": datetime.now(timezone.utc).isoformat(), "component_version": version, "state": "ok",
            "queue_depth": 0, "in_flight": 0, "dependencies": [{"name": "greenbone", "state": "unconfigured", "detail": "not checked"}]}


def test_worker_reports_health_but_never_receives_work(app, owner, world, as_user):
    with owner.begin() as c:
        _, token = devseed.create_service_identity(c, world.alpha, "vms_worker", f"local-worker-{uuid.uuid4().hex[:4]}", scopes=["vms:worker"])
    c = TestClient(app)
    h = {"Authorization": f"Bearer {token}"}
    assert c.post("/api/v1/vms/worker/heartbeat", json=_hb(), headers=h).status_code == 204
    assert c.post("/api/v1/vms/worker/heartbeat", json=_hb("1.8.3"), headers=h).status_code == 204   # upsert, one row
    claim = c.post("/api/v1/vms/worker/claim", headers=h).json()
    assert claim == {"job": None, "reason": "scanning_disabled"}
    st = as_user("analyst_a", app).get("/api/v1/vms/status").json()
    assert st["scanning"] == "disabled" and [w["component_version"] for w in st["workers"]].count("1.8.3") == 1
    assert all(w["component_version"] != "1.8.2" for w in st["workers"])
    beta = as_user("manager_b", app).get("/api/v1/vms/status").json()
    assert all(w["component_version"] != "1.8.3" for w in beta["workers"])        # alpha's worker is not beta's


def test_only_a_scoped_vms_worker_identity_may_use_the_protocol(app, owner, world):
    with owner.begin() as c:
        _, fwd = devseed.create_service_identity(c, world.platform, "forwarder", "not-a-worker", scopes=["alerts:ingest"])
        _, unscoped = devseed.create_service_identity(c, world.alpha, "vms_worker", "unscoped")
        ident, revoked = devseed.create_service_identity(c, world.alpha, "vms_worker", "revoked", scopes=["vms:worker"])
        devseed.revoke_service_identity(c, ident)
    c = TestClient(app)
    for token, code in ((fwd, 403), (unscoped, 403), (revoked, 401), ("nsk_" + "0" * 32 + ".nope-nope-nope-nope-nope", 401)):
        assert c.post("/api/v1/vms/worker/claim", headers={"Authorization": f"Bearer {token}"}).status_code == code
    assert c.post("/api/v1/vms/worker/claim").status_code == 401


def test_status_needs_vms_read(as_user, app):
    assert as_user("portal_a", app).get("/api/v1/vms/status").status_code == 403


def test_heartbeats_are_tenant_isolated(owner, app_engine, world):
    def row(org):
        with owner.begin() as c:
            ident, _ = devseed.create_service_identity(c, org, "vms_worker", f"iso-{uuid.uuid4().hex[:6]}", scopes=["vms:worker"])
        return {"org_id": org, "identity_id": ident, "sent_at": datetime.now(timezone.utc), "component_version": "1.0.0", "state": "ok"}
    assert_tenant_isolation(owner, app_engine, table="novrsoc.vms_worker_heartbeats", org_a=world.alpha, org_b=world.beta,
                            make_row=row, update_set="state = 'failing'")
