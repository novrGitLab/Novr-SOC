"""Data continuity: plans state what is connected, requests are decided and verified by someone other than the requester,
deleted data is never claimed recoverable without a plan, RPO/RTO are computed from recorded times, isolation."""
from datetime import datetime, timedelta, timezone

from sqlalchemy import text

from tests.conftest import audit_actions
from tests.helpers.rls import assert_tenant_isolation


def _iso(d: timedelta) -> str:
    return (datetime.now(timezone.utc) + d).isoformat()


def test_plans_requests_decisions_verification_and_targets(as_user, world, owner):
    m, a = as_user("manager"), as_user("analyst_a")
    bad = m.post("/api/v1/continuity/plans", {"name": "Platform DB", "scope": "NovrSOC database", "backup_source": "novrsoc_platform_backup"},
                 org=world.alpha)
    assert bad.status_code == 422                                                        # client data is not covered by platform backups
    assert m.post("/api/v1/continuity/plans", {"name": "File server", "scope": "Shared drives", "backup_source": "external_provider"},
                  org=world.alpha).status_code == 422                                     # an external provider plan names its provider
    plan = m.post("/api/v1/continuity/plans", {"name": "Finance file server", "scope": "Finance shared drives", "backup_source": "external_provider",
                                               "provider_name": "Offsite backup vendor", "rpo_minutes": 1440, "rto_minutes": 480},
                  org=world.alpha).json()
    assert "Administrative workflow" in plan["execution"]
    req = a.post("/api/v1/continuity/requests", {"title": "Deleted finance folder", "description": "Folder Q3 deleted by mistake on Monday.",
                                                 "affected_data": "\\\\fs01\\finance\\Q3", "loss_detected_at": _iso(timedelta(hours=-2))}).json()
    assert req["status"] == "submitted" and req["events"][0]["kind"] == "submitted"
    assert a.post(f"/api/v1/continuity/requests/{req['id']}/decision", {"decision": "approve", "reason": "self"}).status_code == 403
    noplan = m.post(f"/api/v1/continuity/requests/{req['id']}/decision", {"decision": "approve", "reason": "Backup exists"}, org=world.alpha)
    assert noplan.status_code == 422 and noplan.json()["error"]["code"] == "plan_required"
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.recovery_requests SET plan_id = :p WHERE id = :r"), {"p": plan["id"], "r": req["id"]})
    m.post(f"/api/v1/continuity/requests/{req['id']}/decision", {"decision": "approve", "reason": "Nightly copy at 01:00 covers it",
                                                                 "backup_reference": "vendor job 7781"}, org=world.alpha)
    m.post(f"/api/v1/continuity/requests/{req['id']}/progress", {"status": "in_progress", "note": "Restore started at the vendor"}, org=world.alpha)
    no_point = m.post(f"/api/v1/continuity/requests/{req['id']}/progress", {"status": "completed", "note": "done"}, org=world.alpha)
    assert no_point.status_code == 422
    done = m.post(f"/api/v1/continuity/requests/{req['id']}/progress", {"status": "completed", "note": "Restored to the original path",
                                                                        "recovered_point": _iso(timedelta(hours=-14)),
                                                                        "evidence": ["vendor ticket 7781 closed"]}, org=world.alpha).json()
    assert done["status"] == "completed" and done["achieved_rpo_minutes"] >= 700 and done["achieved_rto_minutes"] is not None
    assert a.post(f"/api/v1/continuity/requests/{req['id']}/verify", {"result": "verified", "note": "self check"}).status_code == 403
    v = m.post(f"/api/v1/continuity/requests/{req['id']}/verify", {"result": "verified", "note": "Owner confirmed files"}, org=world.alpha).json()
    assert v["verification"] == "verified" and any(e["kind"] == "evidence" for e in v["events"])
    ov = a.get("/api/v1/continuity/overview").json()
    assert ov["platform_backups"]["visible"] is False and ov["rpo_met"] >= 1 and ov["completed_requests"] >= 1
    assert as_user("exec_a").post("/api/v1/continuity/requests", {"title": "Executive request", "description": "exec cannot submit this",
                                                                  "affected_data": "Board files", "loss_detected_at": _iso(timedelta(hours=-1))}).status_code == 403
    assert as_user("manager_b").get(f"/api/v1/continuity/requests/{req['id']}").status_code == 404
    acts = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"RECOVERY_PLAN_CREATED", "RECOVERY_REQUESTED", "RECOVERY_DECIDED", "RECOVERY_PROGRESS", "RECOVERY_VERIFIED"} <= acts


def test_not_recoverable_and_isolation(as_user, world, owner, app_engine):
    m, a = as_user("manager"), as_user("analyst_a")
    req = a.post("/api/v1/continuity/requests", {"title": "Laptop data", "description": "Unbacked-up laptop wiped by ransomware.",
                                                 "affected_data": "Local files", "loss_detected_at": _iso(timedelta(hours=-1))}).json()
    out = m.post(f"/api/v1/continuity/requests/{req['id']}/decision", {"decision": "not_recoverable", "reason": "No backup covers this device"},
                 org=world.alpha).json()
    assert out["status"] == "not_recoverable" and out["verification"] == "not_applicable"
    assert_tenant_isolation(owner, app_engine, table="novrsoc.recovery_plans", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "name": f"iso-{org.hex[:6]}-{datetime.now().timestamp()}", "scope": "test scope",
                                                  "backup_source": "manual_procedure"},
                            update_set="procedure = 'tampered'")
