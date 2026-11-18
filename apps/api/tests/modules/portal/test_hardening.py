"""Hardening of the organization portals: public-endpoint rate limits, agent/manager version compatibility, the approved
portal theme, scheduled asset sync with per-organization isolation, and the 0018 -> 0019 -> 0018 migration with data."""
import secrets
import uuid

import pytest
from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app import devseed, jobs
from app import portal as portals
from app.connectors import registry
from app.main import create_app
from tests.conftest import PASSWORD, _with_db, alembic_config, audit_actions, drop_database, make_database
from tests.helpers.fake_manager import FakeManager

BASE = "novrsoc.test"


# ---------------------------------------------------------------- version compatibility and theme (pure)
def test_agent_versions_follow_the_manager_and_are_never_newer():
    assert portals.agent_compatibility("4.9.2", "") == ("4.9.2", "")                 # default: match the manager
    assert portals.agent_compatibility("v4.12.0", "4.9.2") == ("4.9.2", "")          # older agent of the same major: fine
    assert portals.agent_compatibility("4.9.2", "4.12.0")[0] is None                 # newer than the manager: refused
    assert "newer than the manager" in portals.agent_compatibility("4.9.2", "4.12.0")[1]
    assert portals.agent_compatibility("4.9.2", "5.0.0")[0] is None                  # another major version
    assert portals.agent_compatibility(None, "")[0] is None                          # unknown manager: never guessed
    assert portals.agent_compatibility("banana", "")[0] is None


def test_only_accessible_brand_colors_become_the_portal_theme():
    t = portals.theme_for("#0b3d91")
    assert t and t["on_primary"] == "#ffffff" and portals.contrast(t["primary_hover"], "#ffffff") >= 4.5
    assert portals.theme_for("#f5a623") is None                                      # orange on white text: 2.1:1
    assert portals.theme_for("#ffffff") is None and portals.theme_for(None) is None and portals.theme_for("red") is None


# ---------------------------------------------------------------- rate limits
@pytest.fixture(scope="module")
def limited_app(fixture_settings):
    return create_app(fixture_settings.model_copy(update={"portal_base_domain": BASE, "platform_hosts": "testserver",
                                                          "rate_limits_enabled": True}))


def test_public_endpoints_are_rate_limited_per_client_address(limited_app, owner):
    ip = f"203.0.113.{secrets.randbelow(200) + 20}"
    c = TestClient(limited_app, client=(ip, 50000))
    codes = [c.post("/api/v1/invitations/preview", json={"token": "x" * 43}).status_code for _ in range(21)]
    assert codes[:20] == [404] * 20 and codes[20] == 429                             # guesses still count: 20 per 10 minutes
    r = c.post("/api/v1/invitations/accept", json={"token": "x" * 43, "display_name": "x", "password": "p" * 12})
    assert r.status_code == 429 and r.headers["retry-after"] == "600" and r.json()["error"]["code"] == "rate_limited"
    other = TestClient(limited_app, client=(f"198.51.100.{secrets.randbelow(200) + 20}", 50000))
    assert other.post("/api/v1/invitations/preview", json={"token": "x" * 43}).status_code == 404   # another address: unaffected
    for _ in range(30):
        c.get("/api/v1/install/novragent.sh", params={"t": "y" * 43})
    assert c.get("/api/v1/install/novragent.sh", params={"t": "y" * 43}).status_code == 429
    assert c.get("/api/v1/portal").status_code == 200                               # its own, generous limit
    limited = audit_actions(owner, action="RATE_LIMITED")
    assert {e["resource_id"] for e in limited} >= {"invitation", "installer"}
    assert all(ip not in str(e["details"]) for e in limited)                        # the address is audited as ip, never stored in buckets
    with owner.connect() as cn:
        assert cn.execute(text("SELECT count(*) FROM novrsoc.rate_limit_windows WHERE bucket LIKE :b"), {"b": f"%{ip}%"}).scalar() == 0


# ---------------------------------------------------------------- the manager version decides the installer
@pytest.fixture
def enrollment_app(fixture_settings):
    fake = FakeManager()
    previous = registry.enrollment_factory
    registry.enrollment_factory = lambda env, app_env: fake.client()
    registry.reset_enrollment()
    app = create_app(fixture_settings.model_copy(update={"portal_base_domain": BASE, "platform_hosts": "testserver",
                                                         "enrollment_mode": "manager_api", "agent_manager_address": "siem.novrsoc.test",
                                                         "rate_limits_enabled": False}))
    yield app, fake
    registry.enrollment_factory = previous
    registry.reset_enrollment()


def _tenant(owner):
    tag = f"hz{uuid.uuid4().hex[:6]}"
    with owner.begin() as c:
        org = devseed.create_org(c, tag, f"Hardening {tag}")
        devseed.create_user(c, f"m-{tag}@test.novrsoc.invalid", PASSWORD, "soc_manager", org)
    return org, tag, f"m-{tag}@test.novrsoc.invalid"


def _login(app, email):
    c = TestClient(app)
    r = c.post("/api/v1/auth/login", json={"email": email, "password": PASSWORD})
    assert r.status_code == 200, r.text
    c.headers["X-CSRF-Token"] = r.json()["csrf_token"]
    return c


def test_installers_follow_the_real_manager_version_and_refuse_incompatible_or_unknown(enrollment_app, owner, world):
    app, fake = enrollment_app
    org, tag, mgr = _tenant(owner)
    _login(app, "admin@test.novrsoc.invalid").post(f"/api/v1/admin/organizations/{org}/agent-group")
    m = _login(app, mgr)
    st = m.get("/api/v1/onboarding/status").json()["enrollment"]
    assert (st["available"], st["manager_version"], st["agent_version"]) == (True, "4.9.2", "4.9.2")
    assert m.post("/api/v1/onboarding/installer", json={"os": "linux"}).json()["agent_version"] == "4.9.2"
    registry.reset_enrollment()                                                     # the manager now reports nonsense
    fake.version = "garbage"
    st = m.get("/api/v1/onboarding/status").json()
    assert st["installer_available"] is False and "version" in st["installer_reason"]
    assert m.post("/api/v1/onboarding/installer", json={"os": "linux"}).json()["error"]["code"] == "installer_unavailable"


def test_a_configured_agent_newer_than_the_manager_is_refused(fixture_settings, owner, world):
    fake = FakeManager(version="v4.9.2")
    previous = registry.enrollment_factory
    registry.enrollment_factory = lambda env, app_env: fake.client()
    registry.reset_enrollment()
    try:
        app = create_app(fixture_settings.model_copy(update={"enrollment_mode": "manager_api", "agent_manager_address": "siem.novrsoc.test",
                                                             "agent_version": "4.12.0", "rate_limits_enabled": False}))
        org, tag, mgr = _tenant(owner)
        _login(app, "admin@test.novrsoc.invalid").post(f"/api/v1/admin/organizations/{org}/agent-group")
        st = _login(app, mgr).get("/api/v1/onboarding/status").json()
        assert st["installer_available"] is False and "newer than the manager" in st["installer_reason"]
    finally:
        registry.enrollment_factory = previous
        registry.reset_enrollment()


# ---------------------------------------------------------------- scheduled asset sync, isolated per organization
def test_scheduled_asset_sync_runs_when_due_and_isolates_each_organizations_failures(fixture_settings, fixture_alerts, app_engine, owner,
                                                                                    world, monkeypatch):
    from app.modules import assets as assets_module
    real = assets_module.sync_wazuh

    def flaky(conn, settings, org_id, label):
        if org_id == world.beta:
            raise RuntimeError("simulated connector crash")
        return real(conn, settings, org_id, label)
    monkeypatch.setattr(assets_module, "sync_wazuh", flaky)
    # An organization's own wazuh_sync collector overrides the installation schedule (other tests may have left a disabled
    # one, which means "on demand only"): set those aside for this test, and put them back afterwards.
    with owner.begin() as c:
        c.execute(text("DELETE FROM novrsoc.asset_sync_runs WHERE org_id IN (:a, :b)"), {"a": world.alpha, "b": world.beta})
        aside = [r[0] for r in c.execute(text("""UPDATE novrsoc.collectors SET kind = 'manual_import' WHERE kind = 'wazuh_sync'
                                                  AND org_id IN (:a, :b) RETURNING id"""), {"a": world.alpha, "b": world.beta})]
    try:
        _scheduled_sync_checks(fixture_settings, app_engine, owner, world)
    finally:
        with owner.begin() as c:
            c.execute(text("UPDATE novrsoc.collectors SET kind = 'wazuh_sync' WHERE id = ANY(:i)"), {"i": aside})


def _scheduled_sync_checks(fixture_settings, app_engine, owner, world):
    totals = jobs.run_cycle(app_engine, fixture_settings)
    assert totals["asset_syncs"] >= 1 and totals["asset_sync_errors"] >= 1
    with owner.connect() as c:
        runs = {r.org_id: r for r in c.execute(text("""SELECT DISTINCT ON (org_id) org_id, outcome, detail, requested_label
                                                       FROM novrsoc.asset_sync_runs WHERE org_id IN (:a, :b)
                                                       ORDER BY org_id, started_at DESC"""), {"a": world.alpha, "b": world.beta})}
    assert runs[world.alpha].outcome == "completed" and runs[world.alpha].requested_label == "scheduled sync"
    assert runs[world.beta].outcome == "failed" and "RuntimeError" in runs[world.beta].detail and "simulated" not in runs[world.beta].detail
    again = jobs.run_cycle(app_engine, fixture_settings)                           # not due again within the interval
    with owner.connect() as c:
        n = c.execute(text("SELECT count(*) FROM novrsoc.asset_sync_runs WHERE org_id = :a"), {"a": world.alpha}).scalar()
    assert n == 1 and again["asset_syncs"] == 0
    a = _login(create_app(fixture_settings), "analyst_a@test.novrsoc.invalid")
    s = a.get("/api/v1/onboarding/status").json()["asset_sync"]
    assert s["interval_minutes"] == 60 and s["last_outcome"] == "completed" and s["next_due_at"] > s["last_run_at"]
    b = _login(create_app(fixture_settings), "analyst_b@test.novrsoc.invalid").get("/api/v1/onboarding/status").json()["asset_sync"]
    assert b["last_outcome"] == "failed"                                            # each organization sees only its own runs
    off = jobs.run_cycle(app_engine, fixture_settings.model_copy(update={"asset_sync_interval_minutes": 0}))
    assert off["asset_syncs"] == 0


# ---------------------------------------------------------------- 0018 -> 0019 -> 0018 with live data
def test_0019_upgrades_a_0018_installation_in_place_and_rolls_back_cleanly(db):
    name = f"novrsoc_mig19_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    url = _with_db(db.owner_url, name)
    cfg = alembic_config(url)
    eng = create_engine(url)
    try:
        command.upgrade(cfg, "0018_vms_policy_attribution")
        with eng.begin() as c:                                                     # the deployed release's data
            org = devseed.create_org(c, "legacy-co", "Legacy Co")
            uid = devseed.create_user(c, "legacy@test.novrsoc.invalid", PASSWORD, "soc_manager", org)
            c.execute(text("SELECT novrsoc.auth_create_session(:u, :t, :c, 60)"), {"u": uid, "t": b"t" * 32, "c": b"c" * 32})
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, 'legacy-servers')"), {"o": org})
            c.execute(text("""INSERT INTO novrsoc.log_sources (org_id, name, kind, source_ip, match_value, device_type, protocol, authorization_reference)
                              VALUES (:o, 'fw', 'syslog', '10.9.9.9', '10.9.9.9', 'firewall', 'udp', 'CHG-1')"""), {"o": org})
        with eng.begin() as c:
            for (t,) in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc'")).all():
                c.execute(text(f'ALTER TABLE novrsoc."{t}" SET (autovacuum_enabled = false)'))
        command.upgrade(cfg, "0019_org_portals_onboarding")
        with eng.begin() as c:
            row = c.execute(text("SELECT user_id, portal_org_id FROM novrsoc.auth_session_portal(:t)"), {"t": b"t" * 32}).one()
            assert row.user_id == uid and row.portal_org_id is None                # existing sessions: the platform address
            assert c.execute(text("SELECT user_id FROM novrsoc.auth_session(:t)"), {"t": b"t" * 32}).scalar() == uid   # 0018 code still works
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            assert c.execute(text("SELECT verified_at IS NOT NULL FROM novrsoc.log_sources WHERE name = 'fw'")).scalar()
            assert c.execute(text("SELECT provisioned FROM novrsoc.wazuh_group_mappings WHERE group_name = 'legacy-servers'")).scalar() is False
            o = c.execute(text("SELECT portal_enabled, portal_subdomain FROM novrsoc.organizations WHERE id = :o"), {"o": org}).one()
            assert (o.portal_enabled, o.portal_subdomain) == (False, None)
        command.downgrade(cfg, "0018_vms_policy_attribution")
        with eng.begin() as c:
            assert c.execute(text("SELECT user_id FROM novrsoc.auth_session(:t)"), {"t": b"t" * 32}).scalar() == uid
            c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
            assert c.execute(text("SELECT count(*) FROM novrsoc.log_sources")).scalar() == 1
            assert c.execute(text("SELECT count(*) FROM novrsoc.wazuh_group_mappings")).scalar() == 1
            tables = {r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc'"))}
            assert not tables & {"user_invitations", "agent_enrollment_tickets", "agent_enrollments", "rate_limit_windows"}
        command.upgrade(cfg, "head")                                              # and forward again
    finally:
        eng.dispose()
        drop_database(db.admin_url, name)
