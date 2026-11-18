"""Team and presence: member counts by role come from memberships under RLS; "online" comes only from heartbeats sent by
open NovrSOC tabs (migration 0022). Until a heartbeat exists, presence is reported as not tracked (unknown, not zero).
A person writes only their own presence, in the active organization. NovrChat answers "how many analysts are online"
from the same source and cites it."""
import secrets

from sqlalchemy import text

from tests.modules.chat.test_chat import _ask


def test_presence_is_unknown_until_tracked_then_counts_heartbeats(as_user, world, owner):
    with owner.begin() as c:
        c.execute(text("DELETE FROM novrsoc.user_presence WHERE org_id = :o"), {"o": world.beta})
    b = as_user("manager_b")
    t = b.get("/api/v1/presence/team").json()
    assert t["presence_tracked"] is False and t["online"] is None and all(r["online"] is None for r in t["by_role"])
    assert t["members"] >= 1 and any(r["role"] == "soc_manager" for r in t["by_role"])
    _, ans = _ask(as_user("analyst_b"), "How many analysts are online right now?")
    team = next(x for x in ans["tools"] if x["tool"] == "team")
    assert team["state"] == "ok" and "not tracked yet" in ans["content"]
    assert b.post("/api/v1/presence/heartbeat").status_code == 204
    t = b.get("/api/v1/presence/team").json()
    assert t["presence_tracked"] is True and t["online"] == 1
    assert next(r for r in t["by_role"] if r["role"] == "soc_manager")["online"] == 1
    _, ans = _ask(as_user("analyst_b"), "Who is online on the team?")
    assert "Online now" in ans["content"] and any(c["ref"]["type"] == "presence" for c in ans["citations"])
    with owner.begin() as c:                                              # a heartbeat older than two minutes is not "online"
        c.execute(text("UPDATE novrsoc.user_presence SET last_seen_at = now() - interval '5 minutes' WHERE org_id = :o"), {"o": world.beta})
    assert b.get("/api/v1/presence/team").json()["online"] == 0


def test_presence_stays_in_the_organization_and_is_written_only_by_its_owner(as_user, world, app_engine):
    as_user("analyst_a").post("/api/v1/presence/heartbeat")
    with app_engine.begin() as c:                                         # beta's context: alpha's presence is invisible
        c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(world.beta)})
        assert c.execute(text("SELECT count(*) FROM novrsoc.user_presence WHERE org_id = :a"), {"a": str(world.alpha)}).scalar() == 0
    from sqlalchemy.exc import ProgrammingError
    with app_engine.begin() as c:                                         # nobody writes someone else's presence
        c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(world.alpha)})
        c.execute(text("SELECT set_config('app.user_id', :u, true)"), {"u": str(world.users["analyst_a"])})
        try:
            c.execute(text("SAVEPOINT s"))
            c.execute(text("INSERT INTO novrsoc.user_presence (user_id, org_id) VALUES (:u, :o)"),
                      {"u": world.users["exec_a"], "o": world.alpha})
            raise AssertionError("another person's presence was written")
        except ProgrammingError:
            c.execute(text("ROLLBACK TO SAVEPOINT s"))
    alpha = as_user("portal_a").get("/api/v1/presence/team").json()             # portal users hold org:read: their own team only
    assert alpha["members"] == as_user("analyst_a").get("/api/v1/presence/team").json()["members"]


def test_0022_rolls_back_cleanly(db):
    from alembic import command
    from sqlalchemy import create_engine

    from tests.conftest import _with_db, alembic_config, drop_database, make_database
    name = f"novrsoc_mig22_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    url = _with_db(db.owner_url, name)
    cfg, eng = alembic_config(url), create_engine(url)
    try:
        command.upgrade(cfg, "0022_presence")
        command.downgrade(cfg, "0021_nhai_analysis")
        with eng.begin() as c:
            assert "user_presence" not in {r[0] for r in c.execute(text("SELECT tablename FROM pg_tables WHERE schemaname = 'novrsoc'"))}
        command.upgrade(cfg, "head")
    finally:
        eng.dispose()
        drop_database(db.admin_url, name)
