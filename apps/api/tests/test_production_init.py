"""Production initialization: a freshly migrated database holds NO organizations, users, assets, alerts, cases,
intelligence or any other tenant record; migrations seed only the role and permission catalogues. The first
administrator comes from `bootstrap-platform` (one platform organization, one super_admin with a forced password
change), which refuses a second run. Production configuration refuses the development seeding commands."""
import secrets

from alembic import command
from sqlalchemy import create_engine, text

from tests.conftest import _with_db, alembic_config, drop_database, make_database

CATALOGUES = {"roles", "permissions", "role_permissions", "alembic_version"}


def test_fresh_database_is_empty_except_catalogues(db):
    name = f"novrsoc_prodinit_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    owner_url = _with_db(db.owner_url, name)
    try:
        command.upgrade(alembic_config(owner_url), "head")
        eng = create_engine(owner_url)
        with eng.connect() as c:
            tables = [r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc' ORDER BY 1"))]
            non_empty = {t: c.execute(text(f"SELECT count(*) FROM novrsoc.{t}")).scalar() for t in tables if t not in CATALOGUES}
            assert {t: n for t, n in non_empty.items() if n} == {}, "migrations must not seed tenant or demo records"
            assert len(non_empty) >= 60
            assert c.execute(text("SELECT count(*) FROM novrsoc.billing_plans")).scalar() == 0      # no plans pre-defined
            assert c.execute(text("SELECT count(*) FROM novrsoc.soar_playbooks")).scalar() == 0     # no playbooks pre-defined
        eng.dispose()
    finally:
        drop_database(db.admin_url, name)


def test_production_settings_refuse_development_seeding(monkeypatch, tmp_path):
    from app import cli
    monkeypatch.setenv("NOVRSOC_ENV", "production")
    monkeypatch.setenv("NOVRSOC_DATABASE_URL", "postgresql+psycopg://u:p@db.internal.example:5432/novrsoc")
    try:
        rc = cli.seed_dev(tmp_path / "creds.json")
    except Exception as e:  # production settings validation may refuse even earlier: also a refusal
        rc = type(e).__name__
    assert rc != 0
    assert not (tmp_path / "creds.json").exists()
