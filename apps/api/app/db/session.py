"""Database access. One connection + transaction per request; tenant context is transaction-local.

`set_context` uses set_config(..., is_local => true), so app.org_id / app.user_id / app.platform_admin
vanish at COMMIT/ROLLBACK and can never leak to the next request on a pooled connection.
With no app.org_id set, every tenant-table policy evaluates to false: access fails closed.
"""
from __future__ import annotations

import uuid
from collections.abc import Iterator
from contextlib import contextmanager

from sqlalchemy import Engine, create_engine, text
from sqlalchemy.engine import Connection

_engine: Engine | None = None


def init_engine(database_url: str) -> Engine:
    global _engine
    if _engine is not None:
        _engine.dispose()
    _engine = create_engine(database_url, pool_pre_ping=True, pool_size=5, max_overflow=5,
                            connect_args={"application_name": "novrsoc-api", "connect_timeout": 5})
    return _engine


def engine() -> Engine:
    if _engine is None:
        raise RuntimeError("database engine not initialised")
    return _engine


def set_context(conn: Connection, *, org_id: uuid.UUID | None = None, user_id: uuid.UUID | None = None,
                platform_admin: bool | None = None) -> None:
    if org_id is not None:
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org_id)})
    if user_id is not None:
        conn.execute(text("SELECT set_config('app.user_id', :v, true)"), {"v": str(user_id)})
    if platform_admin is not None:
        conn.execute(text("SELECT set_config('app.platform_admin', :v, true)"), {"v": "on" if platform_admin else ""})


@contextmanager
def transaction() -> Iterator[Connection]:
    with engine().begin() as conn:
        yield conn


def request_connection() -> Iterator[Connection]:
    """FastAPI dependency: a connection in a transaction, committed when the request succeeds."""
    with engine().connect() as conn:
        tx = conn.begin()
        try:
            yield conn
        except BaseException:
            tx.rollback()
            raise
        else:
            if tx.is_active:
                tx.commit()
