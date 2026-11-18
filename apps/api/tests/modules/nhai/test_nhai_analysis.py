"""NHAI combined analysis and readiness.

Organization scope: one cited aggregate per domain (SIEM, VMS, assets, cases, Threat Insights, SOAR, remediation,
posture), validated like every NHAI draft. Platform scope: platform staff only, platform organization active, one
aggregate per organization read under that organization's RLS. Readiness comes from records only (backend setting,
the worker's own heartbeat, the queue, outcomes); a small model is labelled a limited pilot. Failed jobs can be retried
with freshly assembled evidence. Migration 0021 rolls back cleanly."""
import secrets

import pytest
from sqlalchemy import text

from app.connectors.inference import TestInferenceAdapter
from app.main import create_app
from tests.modules.conftest import Client
from tests.modules.nhai.test_nhai import drain

DOMAINS = {"siem_alerts", "vms_findings", "assets", "cases", "threat_insights", "soar", "remediation", "posture"}


@pytest.fixture(scope="module")
def nhai_app(fixture_settings):
    return create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter", "nhai_model": "qwen2.5:1.5b"}))


def _bundle(owner, job_id):
    with owner.connect() as c:
        return c.execute(text("SELECT bundle FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": job_id}).scalar()


def test_readiness_is_unavailable_without_a_backend(fixture_app, world):
    r = Client(fixture_app, "analyst_a").get("/api/v1/nhai/readiness").json()
    assert r["state"] == "unavailable" and r["backend_configured"] is False and "not configured" in r["reasons"][0]


def test_readiness_reads_the_worker_heartbeat_and_labels_a_small_model_as_a_pilot(nhai_app, owner, world):
    a = Client(nhai_app, "analyst_a")
    with owner.begin() as c:
        c.execute(text("DELETE FROM novrsoc.platform_heartbeats WHERE component = 'nhai_worker'"))
    silent = a.get("/api/v1/nhai/readiness").json()
    assert silent["worker_state"] == "unknown" and any("never reported" in x for x in silent["reasons"]) and silent["state"] == "degraded"
    with owner.begin() as c:
        c.execute(text("SELECT novrsoc.nhai_heartbeat('server1:1:abc', 'ok', 'model=qwen2.5:1.5b; jobs since start=0')"))
        assert c.execute(text("SELECT count(*) FROM novrsoc.platform_heartbeats WHERE component = 'nhai_worker'")).scalar() == 1
    r = a.get("/api/v1/nhai/readiness").json()
    assert r["worker_state"] == "ok" and r["worker_last_seen_at"] and r["model"] == "qwen2.5:1.5b"
    assert r["pilot"] is True and "limited pilot" in r["pilot_note"]
    with owner.begin() as c:                                                         # a stale heartbeat is "not reporting"
        c.execute(text("UPDATE novrsoc.platform_heartbeats SET last_seen_at = now() - interval '1 hour' WHERE component = 'nhai_worker'"))
    stale = a.get("/api/v1/nhai/readiness").json()
    assert stale["worker_state"] == "failing" and stale["state"] == "degraded"


def test_organization_analysis_cites_every_domain_and_is_a_validated_draft(nhai_app, owner, world, app_engine, fixture_settings,
                                                                          fixture_alerts):
    a = Client(nhai_app, "analyst_a")
    j = a.post("/api/v1/nhai/posture-analyses", {"scope": "organization", "window_days": 30})
    assert j.status_code == 202 and j.json()["task"] == "posture_analysis" and j.json()["subject"]["type"] == "organization", j.text
    b = _bundle(owner, j.json()["id"])
    kinds = {e["ref"]["type"] for e in b["evidence"]}
    assert DOMAINS <= kinds and b["org_id"] == str(world.alpha) and b["subject"]["id"] == str(world.alpha)
    assert drain(app_engine, fixture_settings, TestInferenceAdapter()).count("succeeded") >= 1
    done = a.get(f"/api/v1/nhai/jobs/{j.json()['id']}").json()
    assert done["status"] == "succeeded" and done["result"]["status"] == "draft"
    assert done["result"]["severity_assessment"] is None                             # no authoritative severity for a posture
    assert any("aggregates" in g for g in done["result"]["missing_evidence"])
    assert all(rec["requires_human_approval"] for rec in done["result"]["recommendations"])
    assert Client(nhai_app, "analyst_b").get(f"/api/v1/nhai/jobs/{j.json()['id']}").status_code == 404   # another tenant


def test_platform_analysis_is_platform_staff_only_and_stored_in_the_platform_organization(nhai_app, owner, world):
    admin = Client(nhai_app, "admin")
    j = admin.post("/api/v1/nhai/posture-analyses", {"scope": "platform", "window_days": 7}, org=world.platform)
    assert j.status_code == 202 and j.json()["subject"]["type"] == "platform", j.text
    b = _bundle(owner, j.json()["id"])
    assert b["org_id"] == str(world.platform)
    orgs = {e["ref"]["id"] for e in b["evidence"] if e["ref"]["type"] == "organization_summary"}
    assert {str(world.alpha), str(world.beta)} <= orgs                                # one aggregate per organization
    assert all("raw" not in e["excerpt"] for e in b["evidence"])
    assert Client(nhai_app, "analyst_a").post("/api/v1/nhai/posture-analyses", {"scope": "platform"}).status_code == 403
    m = Client(nhai_app, "manager")                                                   # platform staff, but a client org active
    r = m.post("/api/v1/nhai/posture-analyses", {"scope": "platform"}, org=world.alpha)
    assert r.status_code == 409 and r.json()["error"]["code"] == "platform_organization_required"
    ov = admin.get("/api/v1/nhai/overview", org=world.platform).json()
    assert {str(world.alpha), str(world.beta)} <= {o["org_id"] for o in ov["organizations"]} and ov["readiness"]["backend_configured"]
    assert Client(nhai_app, "analyst_a").get("/api/v1/nhai/overview").status_code == 403


def test_a_failed_job_can_be_retried_with_fresh_evidence(nhai_app, owner, world):
    a = Client(nhai_app, "analyst_a")
    j = a.post("/api/v1/nhai/posture-analyses", {"window_days": 3}).json()
    assert a.post(f"/api/v1/nhai/jobs/{j['id']}/retry").status_code == 409             # still queued: nothing to retry
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.nhai_jobs SET status = 'failed', error_code = 'backend_unavailable', finished_at = now() WHERE id = :i"),
                  {"i": j["id"]})
    again = a.post(f"/api/v1/nhai/jobs/{j['id']}/retry")
    assert again.status_code == 202 and again.json()["id"] != j["id"] and again.json()["status"] == "queued", again.text
    window = [e for e in _bundle(owner, again.json()["id"])["evidence"] if e["ref"]["type"] == "analysis_scope"][0]["excerpt"]
    assert '"window_days": 3' in window                                               # the same request, assembled afresh


def test_0021_rolls_back_cleanly(db):
    from alembic import command
    from sqlalchemy import create_engine

    from tests.conftest import _with_db, alembic_config, drop_database, make_database
    name = f"novrsoc_mig21_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    url = _with_db(db.owner_url, name)
    cfg, eng = alembic_config(url), create_engine(url)
    try:
        command.upgrade(cfg, "0021_nhai_analysis")
        with eng.begin() as c:
            c.execute(text("SELECT novrsoc.nhai_heartbeat('w', 'ok', 'model=qwen2.5:1.5b')"))
            assert c.execute(text("SELECT state FROM novrsoc.nhai_worker_status()")).scalar() == "ok"
        command.downgrade(cfg, "0020_soar_automation")
        with eng.begin() as c:
            fns = {r[0] for r in c.execute(text("SELECT proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'novrsoc'"))}
            assert not fns & {"nhai_heartbeat", "nhai_worker_status"}
            assert c.execute(text("SELECT count(*) FROM novrsoc.platform_heartbeats WHERE component = 'nhai_worker'")).scalar() == 0
        command.upgrade(cfg, "head")
    finally:
        eng.dispose()
        drop_database(db.admin_url, name)
