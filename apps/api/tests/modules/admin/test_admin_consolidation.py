"""Administration consolidation: billing (platform only, no payment claims), authorized exports (justified, checksummed,
audited, expiring, revocable, tenant-scoped), teams, memberships (analyst onboarding), analytics and health."""
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from tests.conftest import audit_actions


def _iso(d: timedelta) -> str:
    return (datetime.now(timezone.utc) + d).isoformat()


def test_billing_is_administrative_and_platform_only(as_user, world):
    admin, m = as_user("admin"), as_user("manager")
    assert m.get("/api/v1/admin/billing").status_code == 403
    code = f"std-{uuid.uuid4().hex[:6]}"
    plan = admin.post("/api/v1/admin/billing/plans", {"code": code, "name": "Standard SOC", "price_minor": 45_000_000, "currency": "NGN",
                                                      "max_assets": 1, "max_users": 50}).json()
    assert admin.post("/api/v1/admin/billing/plans", {"code": code, "name": "dup", "price_minor": 1}).status_code == 409
    ov = admin.put("/api/v1/admin/billing/subscriptions", {"org_id": str(world.alpha), "plan_id": plan["id"], "status": "active"}).json()
    assert ov["payment_provider"] == "not_configured" and "takes no payments" in ov["note"]
    row = next(r for r in ov["organizations"] if r["org_id"] == str(world.alpha))
    assert row["plan_code"] == code and (row["over_limit"] or row["assets"] <= 1)
    assert admin.put("/api/v1/admin/billing/subscriptions", {"org_id": str(world.platform), "plan_id": plan["id"],
                                                             "status": "active"}).status_code == 404       # only client organizations


def test_exports_are_justified_checksummed_audited_and_scoped(as_user, world, owner, fixture_alerts):
    m = as_user("manager")
    body = {"dataset": "alerts", "format": "csv", "period_start": _iso(timedelta(days=-365)), "period_end": _iso(timedelta(hours=1)),
            "justification": "Quarterly evidence pack for the client CISO", "recipient": "Alpha CISO office"}
    assert as_user("analyst_a").post("/api/v1/admin/exports", body).status_code == 403
    assert m.post("/api/v1/admin/exports", {**body, "justification": "short"}, org=world.alpha).status_code == 422
    ex = m.post("/api/v1/admin/exports", body, org=world.alpha).json()
    assert ex["row_count"] >= 1 and ex["state"] == "available"
    d = m.get(f"/api/v1/admin/exports/{ex['id']}/download", org=world.alpha)
    assert d.status_code == 200 and hashlib.sha256(d.content).hexdigest() == ex["sha256"] == d.headers["x-content-sha256"]
    assert d.text.splitlines()[0].startswith("id,observed_at,severity")
    assert as_user("manager_b").get(f"/api/v1/admin/exports/{ex['id']}/download").status_code == 404      # another tenant
    assert m.post(f"/api/v1/admin/exports/{ex['id']}/revoke", {}, org=world.alpha).json()["state"] == "revoked"
    assert m.get(f"/api/v1/admin/exports/{ex['id']}/download", org=world.alpha).status_code == 410
    ex2 = m.post("/api/v1/admin/exports", {**body, "format": "json", "dataset": "assets"}, org=world.alpha).json()
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.data_exports SET created_at = now() - interval '9 days', expires_at = now() - interval '1 day' WHERE id = :i"),
                  {"i": ex2["id"]})
    assert m.get(f"/api/v1/admin/exports/{ex2['id']}/download", org=world.alpha).status_code == 410
    acts = [e["action"] for e in audit_actions(owner, org=world.alpha)]
    assert {"DATA_EXPORT_CREATED", "DATA_EXPORT_DOWNLOADED", "DATA_EXPORT_REVOKED", "DATA_EXPORT_DOWNLOAD_REFUSED"} <= set(acts)


def test_teams_memberships_analytics_and_health(as_user, world):
    admin = as_user("admin")
    team = admin.post("/api/v1/admin/teams", {"name": f"Night shift {uuid.uuid4().hex[:4]}"}, org=world.alpha).json()
    analyst = str(world.users["analyst_a"])
    t = admin.post(f"/api/v1/admin/teams/{team['id']}/members", {"user_id": analyst, "team_role": "lead"}, org=world.alpha).json()
    assert t["members"][0]["email"] == "analyst_a@test.novrsoc.invalid" and t["members"][0]["team_role"] == "lead"
    outsider = str(world.users["analyst_b"])
    assert admin.post(f"/api/v1/admin/teams/{team['id']}/members", {"user_id": outsider}, org=world.alpha).status_code == 422
    assert as_user("manager").get("/api/v1/admin/teams", org=world.alpha).status_code == 403
    ms = admin.post(f"/api/v1/admin/users/{analyst}/memberships", {"org_id": str(world.gamma), "access_scope": "operations"}).json()
    assert {(x["org_id"], x["access_scope"]) for x in ms["items"]} >= {(str(world.gamma), "operations")}
    assert admin.post(f"/api/v1/admin/users/{analyst}/memberships", {"org_id": str(world.gamma), "access_scope": "operations"}).status_code == 409
    assert admin.post(f"/api/v1/admin/users/{world.users['exec_a']}/memberships", {"org_id": str(world.gamma),
                                                                                    "access_scope": "operations"}).status_code == 422
    left = admin.delete(f"/api/v1/admin/users/{analyst}/memberships/{world.gamma}").json()
    assert all(x["org_id"] != str(world.gamma) for x in left["items"])
    assert admin.delete(f"/api/v1/admin/users/{analyst}/memberships/{world.alpha}").status_code == 404     # never the home membership
    an = admin.get("/api/v1/admin/analytics").json()
    assert an["totals"]["organizations"] >= 4 and any(r["org_id"] == str(world.alpha) for r in an["organizations"])
    assert as_user("manager").get("/api/v1/admin/analytics").status_code == 403
    h = admin.get("/api/v1/admin/health").json()
    comp = {c["key"]: c for c in h["components"]}
    assert comp["database"]["state"] == "ok" and comp["migrations"]["state"] == "ok"
    assert comp["soar_bridge"]["state"] == "unconfigured" and comp["jobs_worker"]["state"] in ("unknown", "ok", "failing", "degraded")
    assert "nhai" in h["queues"] and isinstance(h["failures_24h"], list)
    ob = admin.get("/api/v1/admin/onboarding", org=world.alpha).json()
    assert ob["steps"]["organization_created"] and ob["steps"]["wazuh_groups_mapped"]
