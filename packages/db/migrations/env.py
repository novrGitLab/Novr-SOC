"""Alembic environment for NovrSOC V2.

The database URL is taken from NOVRSOC_MIGRATION_DATABASE_URL (the schema-owner role), or from
`-x url=...` (used by the test-suite against disposable databases). The production guard below
refuses any host listed in NOVRSOC_PRODUCTION_DATABASE_HOSTS unless NOVRSOC_ENV=production.
"""
import os
from urllib.parse import urlsplit

from alembic import context
from sqlalchemy import create_engine, pool, text

SCHEMA = "novrsoc"


def _url() -> str:
    x = context.get_x_argument(as_dictionary=True)
    url = x.get("url") or os.environ.get("NOVRSOC_MIGRATION_DATABASE_URL", "")
    if not url:
        raise SystemExit("NOVRSOC_MIGRATION_DATABASE_URL is not set (or pass -x url=...)")
    host = (urlsplit(url.replace("+psycopg", "")).hostname or "").lower()
    prod_hosts = {h.strip().lower() for h in os.environ.get("NOVRSOC_PRODUCTION_DATABASE_HOSTS", "").split(",") if h.strip()}
    if host in prod_hosts and os.environ.get("NOVRSOC_ENV") != "production":
        raise SystemExit(f"refusing to migrate a production database host ({host}) outside NOVRSOC_ENV=production")
    return url


def run_migrations_offline() -> None:
    context.configure(url=_url(), target_metadata=None, literal_binds=True,
                      version_table_schema=SCHEMA, include_schemas=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    engine = create_engine(_url(), poolclass=pool.NullPool)
    with engine.connect() as conn:
        conn.execute(text(f"SET search_path = {SCHEMA}, public"))
        context.configure(connection=conn, target_metadata=None, version_table_schema=SCHEMA,
                          transaction_per_migration=True)
        with context.begin_transaction():
            context.run_migrations()
        conn.commit()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
