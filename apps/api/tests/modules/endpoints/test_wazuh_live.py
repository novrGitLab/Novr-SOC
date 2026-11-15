"""Live Wazuh connectors (Phase 5, workstream C), against FAKE Wazuh services and throwaway TLS servers only."""
import uuid
from collections import deque

import pytest

from app.connectors import registry
from app.connectors.base import ConnectorRejected, ConnectorTimeout, ConnectorUnavailable, ConnectorUnconfigured, OrgScope, ScopeViolation
from app.connectors.wazuh_live import build_live
from app.core.tls import TlsConfigError
from app.main import create_app
from tests.helpers.fake_wazuh import LIVE_ENV, FakeWazuh
from tests.helpers.tls_server import JsonHttpsServer

ALPHA = OrgScope(org_id=uuid.uuid4(), wazuh_agent_groups=frozenset({"nv-alpha-servers", "nv-alpha-workstations"}))
BETA = OrgScope(org_id=uuid.uuid4(), wazuh_agent_groups=frozenset({"nv-beta-servers"}))


def live(fake: FakeWazuh, env=LIVE_ENV, sleeps=None):
    m, i = fake.transports()
    return build_live(env, "test", manager_transport=m, indexer_transport=i,
                      sleep=(sleeps.append if sleeps is not None else (lambda s: None)))


def test_inventory_is_scoped_and_excludes_the_manager():
    w = live(FakeWazuh())
    assert [a.agent_id for a in w.list_agents(ALPHA)] == ["101", "102"]
    assert [a.agent_id for a in w.list_agents(BETA)] == ["201"]
    assert w.list_agents(OrgScope(org_id=uuid.uuid4())) == []          # empty scope: nothing, no request widening
    assert w.raw_agent("101")["os"]["name"] == "Ubuntu" and w.raw_agent("101")["ip"] == "10.1.0.5"
    assert w.get_agent(ALPHA, "201") is None and w.get_agent(BETA, "201").name == "beta-app"


def test_a_broken_upstream_filter_is_a_scope_violation_never_a_leak():
    with pytest.raises(ScopeViolation):
        live(FakeWazuh(out_of_scope_leak=True)).list_agents(ALPHA)


def test_sca_vulnerabilities_and_alert_evidence_are_scoped():
    w = live(FakeWazuh())
    pol = w.sca_policies(ALPHA, "101")[0]
    assert (pol.policy_id, pol.passed, pol.failed, pol.not_applicable, pol.score_percent) == ("cis_ubuntu22-04", 120, 40, 10, 75)
    assert w.sca_policies(BETA, "101") == []                            # another organization's agent: nothing
    assert w.vulnerability_counts(ALPHA, "101") == {"critical": 2, "high": 3, "medium": 4, "low": 0}
    assert w.vulnerability_counts(BETA, "201") is None                  # no documents: unavailable, never zero
    assert w.vulnerability_counts(BETA, "101") is None
    assert w.alert_document(ALPHA, "101", "1731229200.101")["rule"]["id"] == "5710"
    assert w.alert_document(BETA, "101", "1731229200.101") is None


def test_token_is_reused_and_refreshed_once_when_rejected():
    fake = FakeWazuh()
    w = live(fake)
    w.list_agents(ALPHA)
    assert fake.auth_count == 1
    fake.expire_tokens = 1
    w.get_agent(ALPHA, "101")
    assert fake.auth_count == 2


def test_bounded_retries_with_backoff_and_honest_errors():
    sleeps = []
    fake = FakeWazuh(fail_next=deque(["503", "timeout"]))
    assert live(fake, sleeps=sleeps).manager.health().reachable is True   # 2 failures, then success
    assert sleeps == [0.5, 1.0]
    with pytest.raises(ConnectorUnavailable, match="answered 503"):
        live(FakeWazuh(fail_next=deque(["503"] * 5))).manager.health()
    with pytest.raises(ConnectorTimeout):
        live(FakeWazuh(fail_next=deque(["timeout"] * 5))).manager.health()
    with pytest.raises(ConnectorUnavailable, match="could not be reached"):
        live(FakeWazuh(fail_next=deque(["connect"] * 5))).manager.health()
    no_retry = FakeWazuh(reject_auth=True)
    with pytest.raises(ConnectorRejected):
        live(no_retry).manager.health()
    assert len([c for c in no_retry.calls if c[2] == "/security/user/authenticate"]) == 1   # 401 is not retried


def test_configuration_is_validated_by_name_without_values():
    with pytest.raises(ConnectorUnconfigured, match="WAZUH_URL must use https"):
        build_live({**LIVE_ENV, "WAZUH_URL": "http://wazuh.test:55000"}, "production")
    with pytest.raises(ConnectorUnconfigured, match="WAZUH_PASSWORD") as e:
        build_live({k: v for k, v in LIVE_ENV.items() if k != "WAZUH_PASSWORD"}, "production")
    assert "fake-not-a-secret" not in str(e.value)
    with pytest.raises(TlsConfigError, match="WAZUH_CA_CERT"):
        build_live({**LIVE_ENV, "WAZUH_CA_CERT": "not a certificate"}, "production")


# ---------------------------------------------------------------- real TLS handshakes (throwaway certificates)
def _env(port, **extra):
    return {**LIVE_ENV, "WAZUH_URL": f"https://127.0.0.1:{port}", "WAZUH_INDEXER_URL": "", **extra}


ROUTES = {"/security/user/authenticate": (200, {"data": {"token": "jwt-1"}}), "/": (200, {"data": {}})}


def test_pinned_certificate_with_server_name_is_accepted():
    with JsonHttpsServer("wazuh-manager.novrsoc.test", ROUTES) as srv:
        w = build_live(_env(srv.port, WAZUH_CA_CERT=srv.cert, WAZUH_TLS_SERVERNAME="wazuh-manager.novrsoc.test"), "production")
        assert w.manager.health().tls_verified is True


def test_unpinned_or_mismatched_certificates_are_refused_and_not_retried():
    with JsonHttpsServer("wazuh-manager.novrsoc.test", ROUTES) as srv:
        sleeps = []
        w = build_live(_env(srv.port), "production", sleep=sleeps.append)               # system trust store: self-signed refused
        with pytest.raises(ConnectorUnavailable, match="TLS certificate verification failed"):
            w.manager.health()
        assert sleeps == []
        wrong_name = build_live(_env(srv.port, WAZUH_CA_CERT=srv.cert, WAZUH_TLS_SERVERNAME="other.novrsoc.test"), "production")
        with pytest.raises(ConnectorUnavailable, match="TLS certificate verification failed"):
            wrong_name.manager.health()
        other_ca = JsonHttpsServer("wazuh-manager.novrsoc.test", ROUTES)
        pinned_wrong = build_live(_env(srv.port, WAZUH_CA_CERT=other_ca.cert, WAZUH_TLS_SERVERNAME="wazuh-manager.novrsoc.test"), "production")
        other_ca.httpd.server_close()
        with pytest.raises(ConnectorUnavailable, match="TLS certificate verification failed"):
            pinned_wrong.manager.health()


# ---------------------------------------------------------------- through the API, live mode with the fake Wazuh
@pytest.fixture
def live_app(settings, monkeypatch):
    fake = FakeWazuh()
    registry.reset()
    monkeypatch.setattr(registry, "live_factory", lambda env, app_env: live(fake))
    yield create_app(settings.model_copy(update={"wazuh_mode": "live"})), fake
    registry.reset()


@pytest.fixture
def live_mapped(owner, world):
    from sqlalchemy import text
    groups = {"nv-alpha-servers": world.alpha, "nv-alpha-workstations": world.alpha, "nv-beta-servers": world.beta}
    with owner.begin() as c:
        for g, org in groups.items():
            c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g) ON CONFLICT DO NOTHING"),
                      {"o": org, "g": g})


def test_api_live_mode_reports_connected_only_after_a_health_check(live_app, live_mapped, as_user):
    app, fake = live_app
    inv = as_user("analyst_a", app).get("/api/v1/endpoints").json()
    assert inv["source"]["state"] == "connected" and inv["source"]["checked_at"]
    assert [i["agent_id"] for i in inv["items"]] == ["101", "102"]
    assert [i["agent_id"] for i in as_user("manager_b", app).get("/api/v1/endpoints").json()["items"]] == ["201"]
    d = as_user("analyst_a", app).get("/api/v1/endpoints/101").json()
    assert d["vulnerabilities"]["total"] == 9 and d["vulnerabilities"]["source"]["state"] == "connected"
    assert d["sca"]["policies"][0]["score_percent"] == 75
    assert as_user("analyst_a", app).get("/api/v1/endpoints/201").status_code == 404
    status = as_user("analyst_a", app).get("/api/v1/platform/status").json()
    assert {c["connector"]: c["state"] for c in status["connectors"]}["wazuh_manager"] == "connected"


def test_api_live_mode_failure_is_unavailable_never_an_empty_inventory(live_app, live_mapped, as_user):
    app, fake = live_app
    fake.fail_next.extend(["503"] * 3)                                   # the health check fails (3 attempts)
    inv = as_user("analyst_a", app).get("/api/v1/endpoints").json()
    assert inv["source"]["state"] == "unavailable" and inv["items"] == [] and "503" in inv["source"]["detail"]
    r = as_user("analyst_a", app).get("/api/v1/endpoints/101")
    assert r.status_code == 503 and r.json()["error"]["code"] == "integration_unavailable"


def test_api_live_mode_with_missing_settings_is_unconfigured_naming_settings(settings, monkeypatch, as_user, live_mapped):
    registry.reset()
    monkeypatch.setattr(registry, "live_factory", lambda env, app_env: build_live({"WAZUH_URL": ""}, app_env))
    app = create_app(settings.model_copy(update={"wazuh_mode": "live"}))
    inv = as_user("analyst_a", app).get("/api/v1/endpoints").json()
    assert inv["source"]["state"] == "unconfigured" and "WAZUH_URL" in inv["source"]["detail"]
    registry.reset()
