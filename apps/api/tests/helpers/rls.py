"""Reusable tenant-isolation assertions for EVERY tenant table (platform-owned; workstreams call it).

    from tests.helpers.rls import assert_tenant_isolation
    assert_tenant_isolation(owner, app_engine, table="novrsoc.scan_jobs",
                            org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "name": f"job-{uuid.uuid4().hex[:6]}"},
                            update_set="name = 'tampered'")

Checks, as the API runtime role (novrsoc_app, RLS applies):
  1. with no organization context, neither row is visible;
  2. with org A's context, A's row is visible and B's is not (even when selected by id);
  3. inserting a row for org B under org A's context is refused by row-level security;
  4. updating org B's row under org A's context changes nothing;
  5. moving org A's row to org B (UPDATE org_id) is refused;
  6. (deletable=True) deleting org B's row under org A's context deletes nothing.
Tables the API role may not UPDATE at all pass update_set=None: the helper then asserts UPDATE is refused
by privilege instead of checks 4-5.
Convention: tenant tables have an `id` primary key and an `org_id` column.
"""
from __future__ import annotations

import uuid
from collections.abc import Callable

import pytest
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError


def _insert(conn, table: str, row: dict):
    cols = ", ".join(row)
    vals = ", ".join(f":{k}" for k in row)
    return conn.execute(text(f"INSERT INTO {table} ({cols}) VALUES ({vals}) RETURNING id"), row).scalar_one()


def _ctx(conn, org: uuid.UUID) -> None:
    conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})


def assert_tenant_isolation(owner, app_engine, *, table: str, org_a: uuid.UUID, org_b: uuid.UUID,
                            make_row: Callable[[uuid.UUID], dict], update_set: str | None,
                            deletable: bool = False) -> None:
    with owner.begin() as c:  # the owner bypasses RLS: set up one row per organization
        id_a = _insert(c, table, make_row(org_a))
        id_b = _insert(c, table, make_row(org_b))
    ids = {"a": id_a, "b": id_b}

    with app_engine.begin() as c:
        seen = c.execute(text(f"SELECT count(*) FROM {table} WHERE id IN (:a, :b)"), ids).scalar()
        assert seen == 0, f"{table}: rows visible without an organization context"

    with app_engine.begin() as c:
        _ctx(c, org_a)
        visible = {r[0] for r in c.execute(text(f"SELECT id FROM {table} WHERE id IN (:a, :b)"), ids)}
        assert visible == {id_a}, f"{table}: org A must see exactly its own row"
        if update_set is not None:
            changed = c.execute(text(f"UPDATE {table} SET {update_set} WHERE id = :b"), ids).rowcount
            assert changed == 0, f"{table}: org A updated org B's row"
        if deletable:
            gone = c.execute(text(f"DELETE FROM {table} WHERE id = :b"), ids).rowcount
            assert gone == 0, f"{table}: org A deleted org B's row"

    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_engine.begin() as c:
            _ctx(c, org_a)
            _insert(c, table, make_row(org_b))

    if update_set is None:
        with pytest.raises(ProgrammingError, match="permission denied"):
            with app_engine.begin() as c:
                _ctx(c, org_a)
                c.execute(text(f"UPDATE {table} SET org_id = :b_org WHERE id = :a"), {"a": id_a, "b_org": org_b})
        return
    with pytest.raises(ProgrammingError, match="row-level security"):
        with app_engine.begin() as c:
            _ctx(c, org_a)
            c.execute(text(f"UPDATE {table} SET org_id = :b_org WHERE id = :a"), {"a": id_a, "b_org": org_b})
