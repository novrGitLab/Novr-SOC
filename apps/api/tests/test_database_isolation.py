"""Database-level tenant isolation, tested as the API's runtime role (novrsoc_app), below the API."""
import uuid

import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, ProgrammingError

from app import devseed

TENANT_TABLES = ["organizations", "users", "memberships", "sessions", "sites", "service_identities",
                 "audit_events", "cnii_designations"]


@pytest.fixture(scope="module")
def two_sites(owner, world):
    with owner.begin() as c:
        a = devseed.create_site(c, world.alpha, f"iso-a-{uuid.uuid4().hex[:6]}", ["10.0.0.0/24"])
        b = devseed.create_site(c, world.beta, f"iso-b-{uuid.uuid4().hex[:6]}", ["10.0.0.0/24"])  # same private range
    return a, b


def ctx(c, org=None, user=None):
    if org:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
    if user:
        c.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(user)})


def test_runtime_role_cannot_bypass_rls(app_engine):
    with app_engine.connect() as c:
        r = c.execute(text("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user")).one()
        assert r == (False, False)
        owned = c.execute(text("""SELECT count(*) FROM pg_tables WHERE schemaname = 'novrsoc'
                                    AND tableowner = current_user""")).scalar()
        assert owned == 0, "the runtime role must own no table (owners bypass RLS)"


def test_rls_enabled_on_every_tenant_table(app_engine):
    with app_engine.connect() as c:
        rows = dict(c.execute(text("""SELECT c.relname, c.relrowsecurity FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'novrsoc' AND c.relkind = 'r'""")).all())
    for t in TENANT_TABLES:
        assert rows[t] is True, f"RLS must be enabled on {t}"


def test_no_context_sees_nothing(app_engine, two_sites):
    with app_engine.begin() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.sites")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM novrsoc.service_identities")).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM novrsoc.organizations")).scalar() == 0


def test_org_context_sees_only_its_rows(app_engine, two_sites, world):
    a, b = two_sites
    with app_engine.begin() as c:
        ctx(c, org=world.alpha)
        ids = {r[0] for r in c.execute(text("SELECT id FROM novrsoc.sites"))}
        assert a in ids and b not in ids
        # Even an explicit WHERE on the other organization returns nothing.
        assert c.execute(text("SELECT count(*) FROM novrsoc.sites WHERE id = :b"), {"b": b}).scalar() == 0


def test_cannot_write_into_another_org(app_engine, two_sites, world):
    a, b = two_sites
    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_engine.begin() as c:
            ctx(c, org=world.alpha)
            c.execute(text("INSERT INTO novrsoc.sites (org_id, name) VALUES (:o, 'smuggled')"), {"o": world.beta})
    with app_engine.begin() as c:
        ctx(c, org=world.alpha)
        n = c.execute(text("UPDATE novrsoc.sites SET description = 'x' WHERE id = :b"), {"b": b}).rowcount
        assert n == 0
        with pytest.raises(ProgrammingError, match="row-level security"):
            with c.begin_nested():
                c.execute(text("UPDATE novrsoc.sites SET org_id = :o WHERE id = :a"), {"o": world.beta, "a": a})


def test_context_is_transaction_local(app_engine, world, two_sites):
    with app_engine.connect() as c:
        with c.begin():
            ctx(c, org=world.alpha)
            assert c.execute(text("SELECT count(*) FROM novrsoc.sites")).scalar() >= 1
        with c.begin():  # same pooled connection, next transaction: context is gone
            assert c.execute(text("SELECT novrsoc.app_org()")).scalar() is None
            assert c.execute(text("SELECT count(*) FROM novrsoc.sites")).scalar() == 0


def test_sessions_table_is_unreadable(app_engine):
    with pytest.raises(ProgrammingError, match="permission denied"):
        with app_engine.begin() as c:
            c.execute(text("SELECT * FROM novrsoc.sessions"))


def test_users_visible_only_to_self_or_same_org(app_engine, world):
    with app_engine.begin() as c:
        ctx(c, user=world.users["analyst_b"], org=world.beta)
        ids = {r[0] for r in c.execute(text("SELECT id FROM novrsoc.users"))}
        assert world.users["analyst_b"] in ids
        assert world.users["analyst_a"] not in ids, "a user of another organization must be invisible"


def test_audit_is_append_only(app_engine, owner, world):
    with app_engine.begin() as c:
        ctx(c, org=world.alpha)
        c.execute(text("INSERT INTO novrsoc.audit_events (org_id, actor_type, action, outcome) VALUES (:o, 'system', 'TEST_EVENT', 'success')"),
                  {"o": world.alpha})
    with pytest.raises(ProgrammingError, match="permission denied"):
        with app_engine.begin() as c:
            c.execute(text("UPDATE novrsoc.audit_events SET action = 'X'"))
    with pytest.raises(DBAPIError, match="append-only"):  # even the owner cannot rewrite history
        with owner.begin() as c:
            c.execute(text("DELETE FROM novrsoc.audit_events"))


def test_audit_insert_cannot_target_another_org(app_engine, world):
    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_engine.begin() as c:
            ctx(c, org=world.alpha)
            c.execute(text("INSERT INTO novrsoc.audit_events (org_id, actor_type, action, outcome) VALUES (:o, 'system', 'TEST_EVENT', 'success')"),
                      {"o": world.beta})


def test_service_identity_site_must_belong_to_same_org(owner, world, two_sites):
    a, b = two_sites
    with pytest.raises(DBAPIError, match="foreign key"):
        with owner.begin() as c:
            devseed.create_service_identity(c, world.alpha, "collector", "cross-site", site=b)


def test_overlapping_private_ranges_are_distinct_sites(owner, two_sites):
    a, b = two_sites
    with owner.connect() as c:
        rows = c.execute(text("SELECT org_id, network_cidrs::text[] FROM novrsoc.sites WHERE id IN (:a, :b)"), {"a": a, "b": b}).all()
    assert rows[0][1] == rows[1][1] == ["10.0.0.0/24"] and rows[0][0] != rows[1][0]
