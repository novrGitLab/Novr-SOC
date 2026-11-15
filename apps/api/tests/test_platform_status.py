"""Dashboard readiness: never claims a connection that was not established."""
from fastapi.testclient import TestClient

from tests.conftest import PASSWORD


def _login(app, key):
    c = TestClient(app)
    assert c.post("/api/v1/auth/login", json={"email": f"{key}@test.novrsoc.invalid", "password": PASSWORD}).status_code == 200
    return c


def test_status_reports_true_connector_states(app, world):
    s = _login(app, "analyst_a").get("/api/v1/platform/status").json()
    states = {c["connector"]: c["state"] for c in s["connectors"]}
    assert states == {"wazuh_manager": "unconfigured", "wazuh_indexer": "unconfigured", "ollama": "unconfigured"}
    assert all(c["checked_at"] is None for c in s["connectors"]), "nothing claims a reachability check it did not do"
    assert s["database"] == "ok" and __import__("re").match(r"^\d{4}_[a-z0-9_]+$", s["migration"])


def test_modules_reflect_role_and_reality(app, world):
    analyst = {m["key"]: m["state"] for m in _login(app, "analyst_a").get("/api/v1/platform/status").json()["modules"]}
    assert analyst["alerts"] == "live" and analyst["vms"] == "live" and analyst["soar"] == "live" and analyst["nhai"] == "not_available"
    assert analyst["email_security"] == "live" and analyst["brand_protection"] == "live" and analyst["collectors"] == "live"
    assert analyst["cnii"] == "restricted"
    portal = {m["key"] for m in _login(app, "portal_a").get("/api/v1/platform/status").json()["modules"]}
    assert "alerts" not in portal and "cnii" not in portal and "sites" not in portal and "email_security" not in portal


def test_fixture_mode_is_reported_as_fixture_not_online(fixture_app, world):
    s = _login(fixture_app, "analyst_a").get("/api/v1/platform/status").json()
    wazuh = [c for c in s["connectors"] if c["connector"].startswith("wazuh")]
    assert all(c["state"] == "local_fixture" and "Not live" in c["detail"] for c in wazuh)
    assert next(c for c in s["connectors"] if c["connector"] == "ollama")["state"] == "unconfigured"


def test_nhai_readiness_is_claimed_only_after_a_real_inference(settings, owner, world):
    """Phase 5: the API never calls Ollama, so NHAI is `connected` only after a job actually succeeded."""
    from datetime import datetime, timedelta, timezone
    import uuid as _uuid
    from sqlalchemy import text as _text
    from app.main import create_app
    from tests.conftest import Session

    def nhai(backend):
        s = Session(create_app(settings.model_copy(update={"nhai_backend": backend})), "analyst_a@test.novrsoc.invalid")
        body = s.get("/api/v1/platform/status").json()
        return ({m["key"]: m for m in body["modules"]}["nhai"], {c["connector"]: c for c in body["connectors"]}["ollama"])

    module, conn = nhai("unconfigured")
    assert module["state"] == "not_available" and conn["state"] == "unconfigured"
    module, conn = nhai("test_adapter")
    assert module["state"] == "not_available" and conn["state"] == "local_fixture" and "not a" in module["note"]
    with owner.begin() as c:  # precondition, independent of other tests: the most recent finished job failed
        c.execute(_text("""INSERT INTO novrsoc.nhai_jobs (org_id, task, subject_type, subject_id, requested_by, status, deadline_at,
                                                          bundle, error_code, finished_at)
                           VALUES (:o, 'alert_explanation', 'alert', :s, :u, 'failed', now(), '{}', 'backend_unavailable',
                                   now())"""),
                  {"o": world.alpha, "s": str(_uuid.uuid4()), "u": world.users["analyst_a"]})
    module, conn = nhai("ollama")
    assert module["state"] == "not_available" and conn["state"] in ("unavailable",)
    with owner.begin() as c:
        c.execute(_text("""INSERT INTO novrsoc.nhai_jobs (org_id, task, subject_type, subject_id, requested_by, status, deadline_at,
                                                          bundle, result, finished_at)
                           VALUES (:o, 'alert_explanation', 'alert', :s, :u, 'succeeded', :d, '{}', '{}', now())"""),
                  {"o": world.alpha, "s": str(_uuid.uuid4()), "u": world.users["analyst_a"],
                   "d": datetime.now(timezone.utc) + timedelta(hours=1)})
    module, conn = nhai("ollama")
    assert module["state"] == "live" and conn["state"] == "connected" and conn["checked_at"]
