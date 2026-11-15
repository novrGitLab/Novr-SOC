"""Connector interfaces: configuration safety, organization scoping, telemetry attribution. No network."""
import uuid
from datetime import datetime, timezone

import pytest

from app.auth.deps import ServicePrincipal
from app.connectors.base import ConnectorUnconfigured, OrgScope, ScopeViolation, load_endpoint
from app.connectors.inference import ollama_endpoint
from app.connectors.insights_telemetry import attribute_events
from app.connectors.wazuh import WazuhAgent, filter_agents, indexer_endpoint, indexer_scope_query, manager_endpoint
from app.core.tls import TlsConfigError
from novrsoc_contracts.v1.collector import TelemetryBatch

SECRET = "super-secret-password-value"
NOW = datetime.now(timezone.utc)


def test_endpoints_require_https_and_named_credentials_without_leaking_values():
    env = {"WAZUH_URL": "http://wazuh.internal:55000", "WAZUH_USER": "u", "WAZUH_PASSWORD": SECRET}
    with pytest.raises(ConnectorUnconfigured, match="https") as e:
        manager_endpoint(env, "development")
    assert SECRET not in str(e.value)
    with pytest.raises(ConnectorUnconfigured, match="WAZUH_PASSWORD"):
        manager_endpoint({"WAZUH_URL": "https://wazuh.internal:55000", "WAZUH_USER": "u"}, "development")
    with pytest.raises(ConnectorUnconfigured, match="WAZUH_INDEXER_URL is not set"):
        indexer_endpoint({}, "development")
    with pytest.raises(ConnectorUnconfigured, match="embedded credentials"):
        load_endpoint("X", {"X_URL": f"https://user:{SECRET}@host"}, app_env="development")


def test_endpoint_tls_is_verified_and_a_broken_pin_refuses():
    ok = manager_endpoint({"WAZUH_URL": "https://wazuh.internal:55000", "WAZUH_USER": "u", "WAZUH_PASSWORD": SECRET}, "test")
    assert ok.tls is not None and ok.tls.context.check_hostname is True
    with pytest.raises(TlsConfigError):
        manager_endpoint({"WAZUH_URL": "https://w:55000", "WAZUH_USER": "u", "WAZUH_PASSWORD": SECRET,
                          "WAZUH_CA_CERT": "garbage"}, "test")


def test_ollama_plain_http_only_for_a_loopback_proxy_outside_production():
    env = {"OLLAMA_URL": "http://127.0.0.1:11435", "OLLAMA_PROXY_TOKEN": "t" * 40}
    assert ollama_endpoint(env, "development").tls is None
    with pytest.raises(ConnectorUnconfigured, match="https"):
        ollama_endpoint(env, "production")
    with pytest.raises(ConnectorUnconfigured, match="https"):
        ollama_endpoint({**env, "OLLAMA_URL": "http://ollama.lan:11434"}, "development")
    with pytest.raises(ConnectorUnconfigured, match="OLLAMA_PROXY_TOKEN"):
        ollama_endpoint({"OLLAMA_URL": "https://ai.internal"}, "development")


def test_indexer_query_always_carries_the_org_filter_and_wraps_caller_queries():
    scope = OrgScope(uuid.uuid4(), frozenset({"org-a-servers"}), frozenset({"10.1.1.1"}))
    q = indexer_scope_query(scope, since=NOW, query={"match_all": {}, "bool": {"should": []}})
    org_filter = q["bool"]["filter"][0]["bool"]
    assert {"terms": {"agent.groups": ["org-a-servers"]}} in org_filter["should"] and org_filter["minimum_should_match"] == 1
    assert q["bool"]["must"][0] == {"match_all": {}, "bool": {"should": []}}, "caller query is nested, never merged into the filter"
    empty = indexer_scope_query(OrgScope(uuid.uuid4()), since=NOW)
    assert empty == {"bool": {"must_not": [{"match_all": {}}]}}, "an empty scope matches nothing"


def test_manager_results_are_rechecked_against_scope():
    scope = OrgScope(uuid.uuid4(), frozenset({"org-a"}))
    a = WazuhAgent("001", "web-1", ("org-a",), "active")
    b = WazuhAgent("002", "db-9", ("org-b",), "active")
    assert filter_agents([a, b], scope, strict=False) == [a]
    with pytest.raises(ScopeViolation):
        filter_agents([a, b], scope)


def _batch(site, ips):
    return TelemetryBatch.model_validate({"batch_id": "batch-0000000000000001", "sent_at": NOW.isoformat(), "events": [
        {"event_id": f"evt-{i:05d}", "observed_at": NOW.isoformat(), "source_id": str(uuid.uuid4()),
         "sender": {"site_id": str(s), "ip": ip}, "format": "syslog_rfc5424", "raw": "<13>1 test"}
        for i, (s, ip) in enumerate(zip(site, ips))]})


def test_telemetry_is_attributed_only_to_the_identitys_own_site_and_networks():
    org, site, other_site = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    ident = ServicePrincipal(uuid.uuid4(), org, site, "collector", frozenset({"telemetry:write"}))
    batch = _batch([site, site, other_site], ["10.0.0.5", "172.16.9.9", "10.0.0.5"])
    r = attribute_events(ident, ["10.0.0.0/24"], batch)
    assert [e.sender.ip for e in r.accepted] == ["10.0.0.5"]
    assert sorted(reason for _, reason in r.quarantined) == ["sender_outside_site_networks", "sender_site_mismatch"]
    with pytest.raises(PermissionError):
        attribute_events(ServicePrincipal(uuid.uuid4(), org, None, "collector", frozenset()), ["10.0.0.0/24"], batch)
