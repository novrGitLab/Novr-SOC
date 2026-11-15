from fastapi.testclient import TestClient

from tests.conftest import PASSWORD, audit_actions


def test_login_sets_hardened_cookies_and_me_works(login, world):
    s = login("analyst_a")
    cookies = s.login_response.headers.get_list("set-cookie")
    session = next(c for c in cookies if c.startswith("novrsoc_session="))
    csrf = next(c for c in cookies if c.startswith("novrsoc_csrf="))
    assert "HttpOnly" in session and "samesite=lax" in session.lower()
    assert "HttpOnly" not in csrf and "samesite=strict" in csrf.lower()
    me = s.get("/api/v1/auth/me")
    assert me.status_code == 200
    body = me.json()
    assert body["role"] == "analyst" and body["active_org"]["id"] == str(world.alpha) and body["cross_org"] is False
    assert "sites:read" in body["permissions"] and "sites:manage" not in body["permissions"]


def test_unauthenticated_requests_are_refused(app):
    c = TestClient(app)
    r = c.get("/api/v1/auth/me")
    assert r.status_code == 401 and r.json()["error"]["code"] == "unauthenticated"
    assert c.get("/api/v1/sites").status_code == 401


def test_bad_credentials_are_generic_and_audited(app, owner, world):
    c = TestClient(app)
    for email, pw in (("analyst_a@test.novrsoc.invalid", "wrong-password-123"), ("nobody@test.novrsoc.invalid", PASSWORD)):
        r = c.post("/api/v1/auth/login", json={"email": email, "password": pw})
        assert r.status_code == 401 and r.json()["error"] == {**r.json()["error"], "code": "invalid_credentials",
                                                                 "message": "Invalid email or password"}
    reasons = {e["details"]["reason"] for e in audit_actions(owner, action="LOGIN_FAILED")}
    assert {"bad_password", "unknown_account"} <= reasons


def test_lockout_after_repeated_failures_even_with_right_password(app, world):
    c = TestClient(app)
    for _ in range(5):
        assert c.post("/api/v1/auth/login", json={"email": "locked@test.novrsoc.invalid", "password": "nope-nope-nope"}).status_code == 401
    r = c.post("/api/v1/auth/login", json={"email": "locked@test.novrsoc.invalid", "password": PASSWORD})
    assert r.status_code == 401


def test_disabled_account_cannot_sign_in(app, world):
    r = TestClient(app).post("/api/v1/auth/login", json={"email": "disabled@test.novrsoc.invalid", "password": PASSWORD})
    assert r.status_code == 401


def test_csrf_required_on_unsafe_methods(login):
    s = login("manager_b")
    r = s.post("/api/v1/sites", json={"name": "csrf-probe"}, csrf=False)
    assert r.status_code == 403 and r.json()["error"]["code"] == "csrf_failed"
    r = s.post("/api/v1/sites", json={"name": "csrf-probe"}, csrf=False, headers={"X-CSRF-Token": "forged-token-value"})
    assert r.status_code == 403


def test_logout_revokes_the_session(login):
    s = login("analyst_b")
    assert s.get("/api/v1/auth/me").status_code == 200
    assert s.post("/api/v1/auth/logout").status_code == 204
    s.client.cookies.clear()
    assert s.get("/api/v1/auth/me").status_code == 401


def test_revoked_session_token_is_refused_even_if_replayed(app, login):
    s = login("exec_a")
    token = s.client.cookies.get("novrsoc_session")
    assert s.post("/api/v1/auth/logout").status_code == 204
    replay = TestClient(app)
    replay.cookies.set("novrsoc_session", token)
    assert replay.get("/api/v1/auth/me").status_code == 401
