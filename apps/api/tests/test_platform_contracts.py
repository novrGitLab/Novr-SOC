"""Platform guards that every workstream inherits automatically (Phase 3, platform-owned).

  * every /api/v1 route requires a user session or a machine identity (reviewed public allowlist only);
  * module discovery rejects malformed modules;
  * migrations form one linear history with conventional revision ids;
  * every table with an org_id column has RLS enabled and a policy keyed on novrsoc.app_org();
  * tables without RLS are limited to the reviewed global catalogues;
  * the reusable isolation helper passes on the existing tenant tables.
"""
import re
import uuid
from pathlib import Path

import pytest
from fastapi import APIRouter
from fastapi.routing import APIRoute
from sqlalchemy import text

from app import devseed
from app.auth.deps import current_principal, current_service
from app.modules import ModuleError, ModuleInfo, discover, validate
from tests.helpers.rls import assert_tenant_isolation

PUBLIC_ROUTES = {("POST", "/api/v1/auth/login")}  # reviewed: the only unauthenticated /api/v1 endpoint
GLOBAL_TABLES_WITHOUT_RLS = {"roles", "permissions", "role_permissions", "alembic_version"}
MIGRATIONS = Path(__file__).resolve().parents[3] / "packages" / "db" / "migrations" / "versions"


def _calls(dependant, seen=None):
    seen = seen if seen is not None else set()
    for d in dependant.dependencies:
        if d.call is not None and id(d.call) not in seen:
            seen.add(id(d.call))
            yield d.call
            yield from _calls(d, seen)


def api_routes(routes):
    """Every APIRoute, including those inside included routers. FastAPI >= 0.16x wraps an included router in an
    _IncludedRouter (its routes live on .original_router), so a flat scan of app.routes would see none of them."""
    for route in routes:
        if isinstance(route, APIRoute):
            yield route
        inner = getattr(route, "original_router", None)
        if inner is not None:
            yield from api_routes(inner.routes)


def test_every_api_route_is_authenticated(app):
    unguarded, checked = [], 0
    for route in api_routes(app.routes):
        if not route.path.startswith("/api/v1"):
            continue
        checked += 1
        for method in route.methods:
            if (method, route.path) in PUBLIC_ROUTES:
                continue
            calls = set(_calls(route.dependant))
            if current_principal not in calls and current_service not in calls:
                unguarded.append(f"{method} {route.path}")
    assert checked >= 25, f"only {checked} /api/v1 routes inspected: the route walk is broken (would pass vacuously)"
    assert unguarded == [], f"routes without authentication: {unguarded}"


def test_module_discovery_is_strict():
    assert all(isinstance(i, ModuleInfo) for i, _ in discover())
    good = APIRouter(prefix="/api/v1/demo")

    @good.get("/items")
    def _items():  # pragma: no cover - never called
        return []
    validate("demo", ModuleInfo("demo", "A", "/api/v1/demo", "test"), good)
    with pytest.raises(ModuleError, match="prefix"):
        validate("demo", ModuleInfo("demo", "A", "/api/v1/other", "test"), good)
    with pytest.raises(ModuleError, match="package name"):
        validate("demo", ModuleInfo("other", "A", "/api/v1/demo", "test"), good)
    with pytest.raises(ModuleError, match="workstream"):
        validate("demo", ModuleInfo("demo", "Z", "/api/v1/demo", "test"), good)
    with pytest.raises(ModuleError, match="must export"):
        validate("demo", None, good)


def test_migrations_are_one_linear_history_with_conventional_ids():
    from alembic.config import Config
    from alembic.script import ScriptDirectory
    script = ScriptDirectory.from_config(Config(str(MIGRATIONS.parents[1] / "alembic.ini")))
    assert len(script.get_heads()) == 1, "exactly one migration head (the platform owner chains workstream migrations)"
    for rev in script.walk_revisions():
        assert re.match(r"^\d{4}_[a-z0-9_]+$", rev.revision), rev.revision
        assert not isinstance(rev.down_revision, (tuple, list)), f"{rev.revision}: merge revisions need the platform owner"
    files = sorted(p.name for p in MIGRATIONS.glob("*.py"))
    assert all(re.match(r"^\d{4}_[a-z0-9_]+\.py$", f) for f in files), files


def test_every_tenant_table_has_rls_keyed_on_app_org(app_engine):
    with app_engine.connect() as c:
        tables = dict(c.execute(text("""SELECT c.relname, c.relrowsecurity FROM pg_class c
            JOIN pg_namespace n ON n.oid = c.relnamespace WHERE n.nspname = 'novrsoc' AND c.relkind = 'r'""")).all())
        with_org = {r[0] for r in c.execute(text("""SELECT table_name FROM information_schema.columns
            WHERE table_schema = 'novrsoc' AND column_name = 'org_id'"""))}
        policies = {}
        for t, qual, check in c.execute(text("SELECT tablename, qual, with_check FROM pg_policies WHERE schemaname = 'novrsoc'")):
            policies.setdefault(t, []).append(f"{qual or ''} {check or ''}")
    for t in sorted(with_org):
        assert tables.get(t) is True, f"{t}: has org_id but RLS is not enabled"
        assert any("app_org()" in p for p in policies.get(t, [])), f"{t}: no policy keyed on novrsoc.app_org()"
    without = {t for t, on in tables.items() if not on}
    assert without <= GLOBAL_TABLES_WITHOUT_RLS, f"tables without RLS outside the reviewed catalogues: {without - GLOBAL_TABLES_WITHOUT_RLS}"


def test_isolation_helper_on_existing_tenant_tables(owner, app_engine, world):
    assert_tenant_isolation(owner, app_engine, table="novrsoc.sites", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "name": f"iso-{uuid.uuid4().hex[:8]}"},
                            update_set="description = 'tampered'")
    with owner.begin() as c:
        site_a = devseed.create_site(c, world.alpha, f"si-a-{uuid.uuid4().hex[:6]}")
        site_b = devseed.create_site(c, world.beta, f"si-b-{uuid.uuid4().hex[:6]}")
    sites = {world.alpha: site_a, world.beta: site_b}
    assert_tenant_isolation(owner, app_engine, table="novrsoc.service_identities", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "site_id": sites[org], "kind": "collector",
                                                  "name": f"c-{uuid.uuid4().hex[:6]}", "secret_hash": b"\x00" * 32},
                            update_set="name = 'tampered'")


def test_new_permissions_are_enforced_by_role(login):
    analyst = set(login("analyst_a").get("/api/v1/auth/me").json()["permissions"])
    assert {"nhai:analyze", "nhai:review"} <= analyst and "ai_gateway:manage" not in analyst
    manager = set(login("manager_b").get("/api/v1/auth/me").json()["permissions"])
    assert {"nhai:analyze", "nhai:review", "ai_gateway:manage"} <= manager
    for role in ("exec_a", "portal_a"):
        perms = set(login(role).get("/api/v1/auth/me").json()["permissions"])
        assert not ({"nhai:analyze", "nhai:review", "ai_gateway:manage"} & perms), role
