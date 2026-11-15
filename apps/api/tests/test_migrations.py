"""Migration round-trip on its own throwaway database: upgrade -> downgrade -> upgrade."""
import secrets

from alembic import command
from sqlalchemy import create_engine, text

from tests.conftest import _with_db, alembic_config, drop_database, make_database


def _tables(url):
    eng = create_engine(url)
    with eng.connect() as c:
        rows = {r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc'"))}
        funcs = {r[0] for r in c.execute(text("""SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                                                 WHERE n.nspname = 'novrsoc'"""))}
    eng.dispose()
    return rows, funcs


def test_upgrade_downgrade_upgrade(db):
    name = f"novrsoc_migtest_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    owner_url = _with_db(db.owner_url, name)
    try:
        cfg = alembic_config(owner_url)
        command.upgrade(cfg, "head")
        tables, funcs = _tables(owner_url)
        assert {"organizations", "users", "memberships", "sessions", "sites", "service_identities",
                "audit_events", "cnii_designations", "roles", "permissions", "role_permissions", "alembic_version"} <= tables
        assert {"auth_session", "auth_user_for_login", "auth_service_identity", "app_org"} <= funcs
        command.downgrade(cfg, "base")
        tables, funcs = _tables(owner_url)
        assert tables == {"alembic_version"} and not funcs
        command.upgrade(cfg, "head")
        assert "sites" in _tables(owner_url)[0]
        eng = create_engine(owner_url)
        with eng.connect() as c:
            from app.main import expected_migration_head
            assert c.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar() == expected_migration_head()
            definer = c.execute(text("""SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'novrsoc' AND p.prosecdef AND NOT ('search_path=novrsoc, pg_temp' = ANY(coalesce(p.proconfig, '{}')))""")).scalar()
            assert definer == 0, "every SECURITY DEFINER function pins its search_path"
        eng.dispose()
    finally:
        drop_database(db.admin_url, name)
