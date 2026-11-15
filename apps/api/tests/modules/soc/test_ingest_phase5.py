"""Phase 5 ingest semantics (workstream A): batch receipts, replay, conflicts, authoritative groups, evidence."""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed
from app.connectors import registry
from app.main import create_app
from tests.conftest import audit_actions
from tests.helpers.fake_wazuh import FakeWazuh
from tests.modules.endpoints.test_wazuh_live import live


def _alert(xid, groups, agent="201", level=8):
    return {"id": xid, "timestamp": "2026-11-10T08:00:00Z", "rule": {"id": "5710", "level": level, "description": "test"},
            "agent": {"id": agent, "name": "a", "groups": groups}, "raw": {"full_log": "token=abc123 login"}}


def _post(app, token, batch_id, alerts):
    return TestClient(app).post("/api/v1/soc/ingest/alerts", json={"batch_id": batch_id, "alerts": alerts},
                                headers={"Authorization": f"Bearer {token}"})


def test_replayed_batch_returns_the_stored_acknowledgement(fixture_app, forwarder_token, owner, world, mapped):
    bid = f"batch-{uuid.uuid4().hex}"
    alerts = [_alert(f"r-{uuid.uuid4().hex}", ["nv-beta-servers"]), _alert(f"r-{uuid.uuid4().hex}", ["lab-unmapped"])]
    first = _post(fixture_app, forwarder_token, bid, alerts).json()
    assert (first["accepted"], first["quarantined"], first["replayed"]) == (1, 1, False)
    again = _post(fixture_app, forwarder_token, bid, alerts).json()
    assert again == {**first, "replayed": True}                     # same acknowledgement, nothing ingested twice
    with owner.begin() as c:
        n = c.execute(text("SELECT count(*) FROM novrsoc.alerts WHERE external_id = :x"), {"x": alerts[0]["id"]}).scalar()
        rec = c.execute(text("SELECT alert_count, accepted, quarantined FROM novrsoc.ingest_batches WHERE batch_id = :b"), {"b": bid}).one()
    assert n == 1 and tuple(rec) == (2, 1, 1)
    assert "ALERT_BATCH_INGESTED" in {e["action"] for e in audit_actions(owner, org=world.platform)}


def test_reused_batch_id_with_other_content_or_identity_is_refused(fixture_app, forwarder_token, owner, world, mapped):
    bid = f"batch-{uuid.uuid4().hex}"
    assert _post(fixture_app, forwarder_token, bid, [_alert(f"c-{uuid.uuid4().hex}", ["nv-beta-servers"])]).status_code == 200
    r = _post(fixture_app, forwarder_token, bid, [_alert(f"c-{uuid.uuid4().hex}", ["nv-beta-servers"])])
    assert r.status_code == 409
    with owner.begin() as c:
        _, other = devseed.create_service_identity(c, world.platform, "forwarder", "fwd-2", scopes=["alerts:ingest"])
    assert _post(fixture_app, other, bid, [_alert(f"c-{uuid.uuid4().hex}", ["nv-beta-servers"])]).status_code == 409
    assert "ALERT_BATCH_CONFLICT" in {e["action"] for e in audit_actions(owner, org=world.platform)}


def test_revoked_forwarder_credential_is_refused(fixture_app, owner, world, mapped):
    with owner.begin() as c:
        ident, token = devseed.create_service_identity(c, world.platform, "forwarder", "fwd-revoked", scopes=["alerts:ingest"])
        devseed.revoke_service_identity(c, ident)
    assert _post(fixture_app, token, f"batch-{uuid.uuid4().hex}", [_alert("x-1", ["nv-beta-servers"])]).status_code == 401


def test_receipts_are_platform_only(app_engine, world):
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        assert c.execute(text("SELECT count(*) FROM novrsoc.ingest_batches")).scalar() == 0


@pytest.fixture
def live_ingest_app(settings, monkeypatch, mapped):
    fake = FakeWazuh()
    registry.reset()
    monkeypatch.setattr(registry, "live_factory", lambda env, app_env: live(fake))
    yield create_app(settings.model_copy(update={"wazuh_mode": "live"})), fake
    registry.reset()


def test_live_mode_takes_groups_from_the_manager_not_the_payload(live_ingest_app, forwarder_token, owner, world):
    app, fake = live_ingest_app
    xid = f"lv-{uuid.uuid4().hex}"
    # The payload claims beta's group, but the manager says agent 101 is in nv-alpha-servers: alpha owns it.
    r = _post(app, forwarder_token, f"batch-{uuid.uuid4().hex}", [_alert(xid, ["nv-beta-servers"], agent="101")])
    assert r.status_code == 200 and r.json()["accepted"] == 1
    with owner.begin() as c:
        org, groups = c.execute(text("SELECT org_id, agent_groups FROM novrsoc.alerts WHERE external_id = :x"), {"x": xid}).one()
    assert org == world.alpha and list(groups) == ["nv-alpha-servers"]
    unknown = _post(app, forwarder_token, f"batch-{uuid.uuid4().hex}", [_alert(f"lv-{uuid.uuid4().hex}", ["nv-alpha-servers"], agent="999")])
    assert unknown.json()["quarantined"] == 1                     # unknown agent: no groups, quarantined


def test_live_mode_manager_outage_is_not_acknowledged(live_ingest_app, forwarder_token, owner):
    app, fake = live_ingest_app
    fake.fail_next.extend(["503"] * 3)
    bid = f"batch-{uuid.uuid4().hex}"
    r = _post(app, forwarder_token, bid, [_alert(f"lv-{uuid.uuid4().hex}", [], agent="101")])
    assert r.status_code == 503 and r.json()["error"]["code"] == "integration_unavailable"
    with owner.begin() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.ingest_batches WHERE batch_id = :b"), {"b": bid}).scalar() == 0


def test_evidence_fixture_is_labelled_and_redacted_and_isolated(fixture_alerts, as_user, fixture_app):
    a = as_user("analyst_a")
    items = a.get("/api/v1/soc/alerts?limit=200").json()["items"]
    alert = next(x for x in items if x["source"] == "local_fixture")
    ev = a.get(f"/api/v1/soc/alerts/{alert['id']}/evidence").json()
    assert ev["source"]["state"] == "local_fixture" and ev["document"] is not None and ev["redacted"] is True
    real = next((x for x in items if x["source"] == "wazuh"), None)
    if real is not None:  # a real (non-fixture) alert in fixture mode is never labelled as fixture data
        ev2 = a.get(f"/api/v1/soc/alerts/{real['id']}/evidence").json()
        assert ev2["source"]["state"] == "unconfigured" and ev2["document"] is None
    assert as_user("manager_b").get(f"/api/v1/soc/alerts/{alert['id']}/evidence").status_code == 404
    assert as_user("portal_a").get(f"/api/v1/soc/alerts/{alert['id']}/evidence").status_code == 403


def test_evidence_live_reads_the_indexer_and_redacts(live_ingest_app, forwarder_token, owner, world, login):
    app, fake = live_ingest_app
    _post(app, forwarder_token, f"batch-{uuid.uuid4().hex}", [_alert("1731229200.101", [], agent="101")])
    from tests.modules.conftest import Client
    a = Client(app, "analyst_a")
    alert_id = next(x["id"] for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"] if x["external_id"] == "1731229200.101")
    ev = a.get(f"/api/v1/soc/alerts/{alert_id}/evidence").json()
    assert ev["source"]["state"] == "connected" and ev["document"]["rule"]["id"] == "5710"
    assert "hunter2" not in str(ev["document"])                       # secrets in the original are redacted
    registry.reset()
    fake.fail_next.extend(["503"] * 6)                               # manager and indexer health checks both fail
    ev2 = Client(app, "analyst_a").get(f"/api/v1/soc/alerts/{alert_id}/evidence").json()
    assert ev2["document"] is None and ev2["source"]["state"] == "unavailable"


def test_evidence_unconfigured_returns_no_document(app, forwarder_token, mapped):
    from tests.modules.conftest import Client
    xid = f"un-{uuid.uuid4().hex}"
    assert _post(app, forwarder_token, f"batch-{uuid.uuid4().hex}", [_alert(xid, ["nv-alpha-servers"], agent="003")]).json()["accepted"] == 1
    a = Client(app, "analyst_a")
    alert_id = next(x["id"] for x in a.get("/api/v1/soc/alerts?limit=200").json()["items"] if x["external_id"] == xid)
    ev = a.get(f"/api/v1/soc/alerts/{alert_id}/evidence").json()
    assert ev["source"]["state"] == "unconfigured" and ev["document"] is None
