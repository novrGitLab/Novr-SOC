"""CNII monitoring scope: permission AND designation on every endpoint, sector-limited views, authorization records that
gate designation and schedules (server side), honest `not_run` checks (no probe), revocation stops schedules."""
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from app import devseed
from app.modules.cnii import run_due_checks
from tests.conftest import audit_actions


def _iso(d: timedelta) -> str:
    return (datetime.now(timezone.utc) + d).isoformat()


def _auth(sectors, ref=None, frm=timedelta(days=-1), until=timedelta(days=180)):
    return {"reference": ref or f"NCC/CNII/{uuid.uuid4().hex[:6]}", "issuing_authority": "Sector regulator",
            "scope_description": "Availability and vulnerability monitoring of designated grid control assets.",
            "sectors": sectors, "valid_from": _iso(frm), "valid_until": _iso(until)}


def test_designation_is_required_and_sectors_are_enforced(as_user, world, owner):
    m = as_user("manager")
    denied = m.get("/api/v1/cnii/overview", org=world.alpha)
    assert denied.status_code == 403 and denied.json()["error"]["details"]["designation"] == "required"
    assert "CNII_ACCESS_DENIED" in {e["action"] for e in audit_actions(owner, org=world.alpha)}
    with owner.begin() as c:
        admin = c.execute(text("SELECT id FROM novrsoc.users WHERE email = 'admin@test.novrsoc.invalid'")).scalar()
        mgr = c.execute(text("SELECT id FROM novrsoc.users WHERE email = 'manager@test.novrsoc.invalid'")).scalar()
        devseed.grant_cnii(c, mgr, ["power"], admin, days=30, scope_org_ids=[world.alpha])
    ov = m.get("/api/v1/cnii/overview", org=world.alpha).json()
    assert "power" in ov["designation_sectors"] and "not_run" in ov["probe"]
    refused = m.post("/api/v1/cnii/authorizations", _auth(["mines"]), org=world.alpha)
    assert refused.status_code == 403                                                     # not designated for mines
    assert as_user("analyst_a").get("/api/v1/cnii/authorizations").status_code == 403    # analyst has no designation here
    assert m.get("/api/v1/cnii/overview", org=world.beta).status_code == 403             # designation scoped to alpha only


def test_authorization_gates_designation_schedules_and_checks(as_user, world, owner):
    m = as_user("manager")
    with owner.begin() as c:
        admin = c.execute(text("SELECT id FROM novrsoc.users WHERE email = 'admin@test.novrsoc.invalid'")).scalar()
        mgr = c.execute(text("SELECT id FROM novrsoc.users WHERE email = 'manager@test.novrsoc.invalid'")).scalar()
        devseed.grant_cnii(c, mgr, ["power", "water"], admin, days=30, scope_org_ids=[world.alpha])
    asset = as_user("analyst_a").post("/api/v1/assets", {"kind": "host", "display_name": "grid-scada-01",
                                                         "hostname": f"scada-{uuid.uuid4().hex[:4]}"}).json()
    expired = m.post("/api/v1/cnii/authorizations", _auth(["power"], frm=timedelta(days=-30), until=timedelta(days=-1)), org=world.alpha).json()
    assert expired["state"] == "expired"
    r = m.post("/api/v1/cnii/monitored-assets", {"asset_id": asset["id"], "authorization_id": expired["id"], "sector": "power",
                                                 "owning_unit": "Grid Operations"}, org=world.alpha)
    assert r.status_code == 409 and r.json()["error"]["code"] == "authorization_not_active"
    auth = m.post("/api/v1/cnii/authorizations", _auth(["power"]), org=world.alpha).json()
    assert auth["state"] == "active"
    wrong_sector = m.post("/api/v1/cnii/monitored-assets", {"asset_id": asset["id"], "authorization_id": auth["id"], "sector": "water",
                                                            "owning_unit": "Grid Operations"}, org=world.alpha)
    assert wrong_sector.status_code == 422                                                # the authorization does not cover water
    ma = m.post("/api/v1/cnii/monitored-assets", {"asset_id": asset["id"], "authorization_id": auth["id"], "sector": "power",
                                                  "owning_unit": "Grid Operations"}, org=world.alpha).json()
    assert ma["authorization_state"] == "active" and ma["availability_30d"] is None       # no check recorded: unknown, not 100%
    ma = m.put(f"/api/v1/cnii/monitored-assets/{ma['id']}/schedule", {"check_kind": "availability", "interval_minutes": 5, "enabled": True},
               org=world.alpha).json()
    assert ma["schedules"][0]["enabled"] is True and "not_run" in ma["schedules"][0]["execution"]
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.cnii_schedules SET next_due_at = now() - interval '1 minute' WHERE monitored_asset_id = :m"), {"m": ma["id"]})
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        assert run_due_checks(c) >= 1
    checks = m.get(f"/api/v1/cnii/monitored-assets/{ma['id']}/checks", org=world.alpha).json()
    assert checks and checks[0]["outcome"] == "not_run" and "probe" in checks[0]["detail"]
    assert m.get(f"/api/v1/assets/{asset['id']}", org=world.alpha).json()["asset"]["monitoring"]["cnii_designated"] is True
    m.post(f"/api/v1/cnii/authorizations/{auth['id']}/revoke", {"reason": "Mandate withdrawn"}, org=world.alpha)
    after = next(x for x in m.get("/api/v1/cnii/monitored-assets", org=world.alpha).json()["items"] if x["id"] == ma["id"])
    assert after["authorization_state"] == "revoked" and after["schedules"][0]["enabled"] is False
    again = m.put(f"/api/v1/cnii/monitored-assets/{ma['id']}/schedule", {"check_kind": "availability", "interval_minutes": 5, "enabled": True},
                  org=world.alpha)
    assert again.status_code == 409
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"CNII_AUTHORIZATION_RECORDED", "CNII_ASSET_DESIGNATED", "CNII_AUTHORIZATION_REVOKED"} <= acts
