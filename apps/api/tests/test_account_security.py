"""Account security for production: temporary passwords must be changed, self-service change, operator bootstrap."""
import secrets
import uuid

from alembic import command
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app import cli
from tests.conftest import Session, _with_db, alembic_config, audit_actions, drop_database, make_database

NEW = "correct horse battery staple 42"


def _new_user(login, role="analyst"):
    admin = login("admin")
    email = f"acct-{uuid.uuid4().hex[:8]}@test.novrsoc.invalid"
    r = admin.post("/api/v1/admin/users", {"email": email, "role": role})
    assert r.status_code == 201, r.text
    return email, r.json()["temporary_password"], r.json()["user"]["id"]


def test_temporary_password_blocks_everything_until_changed(app, world, login, owner):
    email, temp, uid = _new_user(login)
    s = Session(app, email, temp)
    assert s.login_response.json()["session"]["password_change_required"] is True
    me = s.get("/api/v1/auth/me")
    assert me.status_code == 200 and me.json()["password_change_required"] is True
    for path in ("/api/v1/sites", "/api/v1/orgs", "/api/v1/soc/alerts", "/api/v1/platform/status"):
        r = s.get(path)
        assert r.status_code == 403 and r.json()["error"]["code"] == "password_change_required", (path, r.text)
    assert s.post("/api/v1/sites", {"name": "blocked"}).status_code == 403

    assert s.post("/api/v1/auth/password", {"current_password": "wrong-password-123", "new_password": NEW}).status_code == 400
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": temp}).status_code == 422
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": "é" * 40}).status_code == 422  # > 72 bytes
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": "short"}).status_code == 422
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": NEW}, csrf=False).status_code == 403

    other = Session(app, email, temp)                                       # a second session of the same user
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": NEW}).status_code == 204
    assert other.get("/api/v1/auth/me").status_code == 401                  # other sessions are revoked
    me = s.get("/api/v1/auth/me").json()                                     # the changing session continues
    assert me["password_change_required"] is False
    assert s.get("/api/v1/sites").status_code == 200

    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"email": email, "password": temp}).status_code == 401
    assert Session(app, email, NEW).login_response.json()["session"]["password_change_required"] is False
    acts = [e for e in audit_actions(owner, action="PASSWORD_CHANGED") if e["actor_id"] == uuid.UUID(uid)]
    assert len(acts) == 1 and acts[0]["details"]["was_temporary"] is True
    assert any(e["actor_id"] == uuid.UUID(uid) for e in audit_actions(owner, action="PASSWORD_CHANGE_FAILED"))


def test_wrong_current_password_counts_towards_the_lockout(app, world, login, owner):
    email, temp, uid = _new_user(login)
    s = Session(app, email, temp)
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": NEW}).status_code == 204
    for _ in range(5):
        assert s.post("/api/v1/auth/password", {"current_password": "not-the-password-1", "new_password": NEW + "x"}).status_code == 400
    with owner.connect() as conn:
        assert conn.execute(text("SELECT locked_until IS NOT NULL FROM novrsoc.users WHERE id = :u"), {"u": uid}).scalar()
    assert TestClient(app).post("/api/v1/auth/login", json={"email": email, "password": NEW}).status_code == 401


def test_the_app_role_cannot_change_another_users_password(db, world):
    eng = create_engine(db.app_url)
    with eng.begin() as conn:                                               # no signed-in user context
        try:
            with conn.begin_nested():
                conn.execute(text("SELECT novrsoc.auth_change_password(:h, :k)"), {"h": "x" * 60, "k": b"k"})
            raise AssertionError("auth_change_password ran without a user context")
        except Exception as exc:
            assert "signed-in user context required" in str(exc)
        try:
            with conn.begin_nested():
                conn.execute(text("UPDATE novrsoc.users SET password_hash = 'x' WHERE id = :u"), {"u": world.users["admin"]})
            raise AssertionError("the API role updated users directly")
        except Exception as exc:
            assert "permission denied" in str(exc)
    eng.dispose()


def test_bootstrap_platform_runs_once_on_an_empty_database(db, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    assert cli.bootstrap_platform("first@ops.invalid", "Platform", tmp_path / "pw0") == 2        # populated: refused
    assert not (tmp_path / "pw0").exists()

    name = f"novrsoc_boot_{secrets.token_hex(4)}"
    make_database(db.admin_url, name)
    owner_url = _with_db(db.owner_url, name)
    try:
        command.upgrade(alembic_config(owner_url), "head")
        monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", owner_url)
        out = tmp_path / "first-admin.txt"
        assert cli.bootstrap_platform("First@Ops.invalid", "NovrSOC Platform", out) == 0
        pw = out.read_text().strip()
        assert len(pw) >= 20 and pw not in capsys.readouterr().out
        eng = create_engine(owner_url)
        with eng.connect() as c:
            u = c.execute(text("""SELECT u.email, u.password_change_required, m.role_key, o.kind FROM novrsoc.users u
                                  JOIN novrsoc.memberships m ON m.user_id = u.id JOIN novrsoc.organizations o ON o.id = m.org_id""")).one()
            assert (str(u.email), u.password_change_required, u.role_key, u.kind) == ("first@ops.invalid", True, "super_admin", "platform")
            assert c.execute(text("SELECT count(*) FROM novrsoc.audit_events WHERE action = 'PLATFORM_BOOTSTRAPPED'")).scalar() == 1
        eng.dispose()
        assert cli.bootstrap_platform("second@ops.invalid", "Again", tmp_path / "pw2") == 2      # once only
        assert cli.bootstrap_platform("x@ops.invalid", "Again", out) == 2                         # never overwrites
    finally:
        drop_database(db.admin_url, name)


def test_admin_reset_issues_a_temporary_password_and_revokes_sessions(app, world, login, owner):
    email, temp, uid = _new_user(login)
    s = Session(app, email, temp)
    assert s.post("/api/v1/auth/password", {"current_password": temp, "new_password": NEW}).status_code == 204
    admin = login("admin")
    r = admin.post(f"/api/v1/admin/users/{uid}/reset-password")
    assert r.status_code == 200 and r.json()["user"]["id"] == uid
    reset = r.json()["temporary_password"]
    assert s.get("/api/v1/auth/me").status_code == 401                      # sessions revoked
    assert TestClient(app).post("/api/v1/auth/login", json={"email": email, "password": NEW}).status_code == 401
    again = Session(app, email, reset)
    assert again.login_response.json()["session"]["password_change_required"] is True
    assert again.get("/api/v1/sites").status_code == 403

    assert admin.post(f"/api/v1/admin/users/{world.users['admin']}/reset-password").status_code == 409    # not yourself
    assert admin.post(f"/api/v1/admin/users/{world.users['analyst_a']}/reset-password").status_code == 404  # other org
    assert login("manager").post(f"/api/v1/admin/users/{uid}/reset-password").status_code == 403
    assert any(e["resource_id"] == uid for e in audit_actions(owner, action="USER_PASSWORD_RESET"))
