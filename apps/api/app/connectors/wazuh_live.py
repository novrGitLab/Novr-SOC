"""Live Wazuh Manager API and Wazuh Indexer clients (Phase 5, workstream C). Read-only.

Selected only with NOVRSOC_WAZUH_MODE=live. Nothing here is exercised against a real Wazuh in automated tests:
tests use fake HTTP transports and throwaway TLS servers. A connector is reported `connected` only after a
health check against the real service succeeded (registry.py), never because this code exists.

Security properties:
  * TLS verification is always on (app.core.tls.service_tls): optional CA pin <PREFIX>_CA_CERT and server name
    <PREFIX>_TLS_SERVERNAME. A certificate failure is reported as such and is never retried or bypassed.
  * Credentials come from the environment by name (WAZUH_USER/WAZUH_PASSWORD for a read-only manager API user;
    WAZUH_INDEXER_USER/WAZUH_INDEXER_PASSWORD for a read-only indexer user). Values never appear in errors.
  * Organization scoping: the manager is queried per mapped agent group and every returned agent is re-checked
    (filter_agents strict). Indexer queries are restricted server-side to the agent ids of the organization's
    in-scope agents (standard Wazuh alert documents carry agent.id; they are not expected to carry the agent's
    groups; confirm this against the installation's own mapping before gate G-C1).
  * Bounded retries with exponential backoff for timeouts, connection errors, 429 and 5xx; none for 4xx.
"""
from __future__ import annotations

import base64
import ssl
import threading
import time
from collections.abc import Callable, Mapping
from datetime import datetime
from typing import Any

import httpx

from app.connectors.base import (ConnectorError, ConnectorHealth, ConnectorRejected, ConnectorTimeout, ConnectorUnavailable,
                                 Endpoint, OrgScope, ScopeViolation)
from app.connectors.wazuh import (ScaCheck, ScaPolicySummary, WazuhAgent, agent_in_scope, filter_agents, indexer_endpoint,
                                  manager_endpoint)

MAX_AGENTS = 10_000
PAGE = 500
AGENT_FIELDS = "id,name,group,status,os.platform,os.name,os.version,version,lastKeepAlive,ip"
ALERT_INDEX = "wazuh-alerts-*"
VULN_INDEX = "wazuh-states-vulnerabilities-*"
STATUSES = {"active", "disconnected", "never_connected", "pending"}


def _ts(v: str | None) -> datetime | None:
    if not v or v.startswith("9999"):
        return None
    try:
        return datetime.fromisoformat(v.replace("Z", "+00:00"))
    except ValueError:
        return None


def _tls_failure(exc: BaseException) -> bool:
    seen, cur = 0, exc
    while cur is not None and seen < 10:
        if isinstance(cur, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(cur):
            return True
        cur, seen = cur.__cause__ or cur.__context__, seen + 1
    return False



_SHOWN = {"WAZUH": "NovrSIEM", "WAZUH_INDEXER": "NovrSIEM event store"}


def shown(endpoint_name: str) -> str:
    """The product name of an endpoint in messages people read (never the vendor or configuration prefix)."""
    return _SHOWN.get(endpoint_name, endpoint_name)

class HttpService:
    """One TLS-verified HTTP service with bounded retries. Raises only ConnectorError subclasses."""

    def __init__(self, ep: Endpoint, *, transport: httpx.BaseTransport | None = None, retries: int = 2,
                 backoff_seconds: float = 0.5, sleep: Callable[[float], None] = time.sleep):
        self.ep, self.retries, self.backoff, self.sleep = ep, max(0, min(retries, 5)), backoff_seconds, sleep
        verify: Any = ep.tls.context if ep.tls else True
        self._ext = {"sni_hostname": ep.tls.server_hostname} if ep.tls and ep.tls.server_hostname else {}
        self.client = httpx.Client(base_url=ep.base_url, verify=verify, timeout=ep.timeout_seconds, transport=transport,
                                   follow_redirects=False, headers={"Accept": "application/json"})

    def request(self, method: str, path: str, *, headers: Mapping[str, str] | None = None,
                params: Mapping[str, Any] | None = None, json: Any = None) -> httpx.Response:
        last: ConnectorError = ConnectorUnavailable(f"{shown(self.ep.name)} could not be reached")
        for attempt in range(self.retries + 1):
            try:
                r = self.client.request(method, path, headers=headers, params=params, json=json, extensions=self._ext)
            except httpx.TimeoutException:
                last = ConnectorTimeout(f"{shown(self.ep.name)} did not answer within {self.ep.timeout_seconds:g} s")
            except httpx.HTTPError as e:
                if _tls_failure(e):
                    raise ConnectorUnavailable(f"{shown(self.ep.name)}: TLS certificate verification failed "
                                               "(check its CA certificate and TLS server name)") from None
                last = ConnectorUnavailable(f"{shown(self.ep.name)} could not be reached")
            else:
                if r.status_code in (401, 403):
                    raise ConnectorRejected(f"{shown(self.ep.name)} refused the request ({r.status_code}); check its read-only credentials")
                if r.status_code == 429 or r.status_code >= 500:
                    last = ConnectorUnavailable(f"{shown(self.ep.name)} answered {r.status_code}")
                else:
                    return r
            if attempt < self.retries:
                self.sleep(self.backoff * (2 ** attempt))
        raise last

    def close(self) -> None:
        self.client.close()


def _basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


class LiveWazuhManager:
    """Wazuh Manager API (read-only user). JWT obtained from /security/user/authenticate and refreshed on expiry."""

    TOKEN_SECONDS = 600  # Wazuh default token lifetime is 900 s; refresh earlier.

    def __init__(self, http: HttpService, user: str, password: str, clock: Callable[[], float] = time.time):
        self.http, self._basic, self.clock = http, _basic(user, password), clock
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = threading.Lock()
        self._raw: dict[str, dict] = {}
        self._groups_cache: dict[str, tuple[float, tuple[str, ...] | None]] = {}

    def _auth(self) -> str:
        with self._lock:
            if self._token and self.clock() < self._token_exp:
                return self._token
            r = self.http.request("POST", "/security/user/authenticate", headers={"Authorization": self._basic})
            if r.status_code != 200:
                raise ConnectorRejected(f"NovrSIEM authentication failed ({r.status_code})")
            try:
                self._token = r.json()["data"]["token"]
            except (ValueError, KeyError, TypeError):
                raise ConnectorUnavailable("NovrSIEM returned an unexpected authentication response") from None
            self._token_exp = self.clock() + self.TOKEN_SECONDS
            return self._token

    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> dict:
        for attempt in (0, 1):
            token = self._auth()
            try:
                r = self.http.request("GET", path, headers={"Authorization": f"Bearer {token}"}, params=params)
            except ConnectorRejected:
                if attempt == 0:  # token revoked or expired early: authenticate once more
                    with self._lock:
                        self._token = None
                    continue
                raise
            if r.status_code == 404:
                return {"data": {"affected_items": [], "total_affected_items": 0}}
            if r.status_code != 200:
                raise ConnectorUnavailable(f"NovrSIEM answered {r.status_code} for a read request")
            try:
                return r.json()
            except ValueError:
                raise ConnectorUnavailable("NovrSIEM returned a response that is not JSON") from None
        raise ConnectorRejected("NovrSIEM refused the request")

    @staticmethod
    def _items(body: dict) -> list[dict]:
        data = body.get("data") or {}
        items = data.get("affected_items") or []
        return [i for i in items if isinstance(i, dict)]

    def _to_agent(self, a: dict) -> WazuhAgent | None:
        aid = str(a.get("id") or "")
        if not aid.isdigit() or aid == "000":  # 000 is the manager itself, never an endpoint
            return None
        os_ = a.get("os") or {}
        self._raw[aid] = {"os": {"platform": os_.get("platform"), "name": os_.get("name"), "version": os_.get("version")},
                          "ip": a.get("ip") if a.get("ip") not in (None, "any") else None}
        status = a.get("status") if a.get("status") in STATUSES else "pending"
        return WazuhAgent(agent_id=aid, name=str(a.get("name") or aid), groups=tuple(a.get("group") or ()), status=status,
                          os_platform=os_.get("platform"), os_version=os_.get("version"), agent_version=a.get("version"),
                          last_keepalive_at=_ts(a.get("lastKeepAlive")))

    def raw_agent(self, agent_id: str) -> dict | None:
        return self._raw.get(agent_id)

    def list_agents(self, scope: OrgScope) -> list[WazuhAgent]:
        found: dict[str, WazuhAgent] = {}
        for group in sorted(scope.wazuh_agent_groups):
            offset = 0
            while True:
                body = self._get("/agents", {"group": group, "limit": PAGE, "offset": offset, "select": AGENT_FIELDS})
                items = self._items(body)
                for a in items:
                    agent = self._to_agent(a)
                    if agent is not None:
                        found[agent.agent_id] = agent
                if len(found) > MAX_AGENTS:
                    raise ConnectorUnavailable(f"NovrSIEM returned more than {MAX_AGENTS} agents for one organization")
                total = (body.get("data") or {}).get("total_affected_items") or 0
                offset += PAGE
                if not items or offset >= total:
                    break
        return filter_agents(sorted(found.values(), key=lambda a: a.agent_id), scope, strict=True)

    def get_agent(self, scope: OrgScope, agent_id: str) -> WazuhAgent | None:
        if scope.empty:
            return None
        items = self._items(self._get("/agents", {"agents_list": agent_id, "select": AGENT_FIELDS}))
        agents = [x for x in (self._to_agent(a) for a in items) if x is not None and x.agent_id == agent_id]
        if not agents:
            return None
        return agents[0] if agent_in_scope(agents[0], scope) else None

    def agent_groups(self, agent_id: str, ttl_seconds: float = 300.0) -> tuple[str, ...] | None:
        """Authoritative groups of one agent (platform-level, used by alert ingest). None = unknown agent."""
        now = self.clock()
        hit = self._groups_cache.get(agent_id)
        if hit and now - hit[0] < ttl_seconds:
            return hit[1]
        items = self._items(self._get("/agents", {"agents_list": agent_id, "select": "id,group"}))
        groups = next((tuple(a.get("group") or ()) for a in items if str(a.get("id")) == agent_id), None)
        self._groups_cache[agent_id] = (now, groups)
        return groups

    def sca_policies(self, scope: OrgScope, agent_id: str) -> list[ScaPolicySummary]:
        if self.get_agent(scope, agent_id) is None:
            return []
        out = []
        for p in self._items(self._get(f"/sca/{agent_id}")):
            passed, failed, na = int(p.get("pass") or 0), int(p.get("fail") or 0), int(p.get("invalid") or 0)
            scanned = _ts(p.get("end_scan"))
            if scanned is None:
                continue
            applicable = passed + failed
            out.append(ScaPolicySummary(agent_id=agent_id, policy_id=str(p.get("policy_id")), name=str(p.get("name") or ""),
                                        passed=passed, failed=failed, not_applicable=na,
                                        score_percent=round(100 * passed / applicable) if applicable else 0, scanned_at=scanned))
        return out

    def sca_checks(self, scope: OrgScope, agent_id: str, policy_id: str) -> list[ScaCheck]:
        if self.get_agent(scope, agent_id) is None:
            return []
        out = []
        for c in self._items(self._get(f"/sca/{agent_id}/checks/{policy_id}", {"limit": PAGE})):
            result = {"passed": "passed", "failed": "failed"}.get(str(c.get("result") or "").lower(), "not_applicable")
            comp: dict[str, list[str]] = {}
            for item in c.get("compliance") or []:
                if isinstance(item, dict) and item.get("key"):
                    comp.setdefault(str(item["key"]), []).extend(str(item.get("value", "")).split(","))
            out.append(ScaCheck(check_id=int(c.get("id") or 0), title=str(c.get("title") or ""), result=result,
                                rationale=str(c.get("rationale") or ""), remediation=str(c.get("remediation") or ""),
                                compliance={k: tuple(v) for k, v in comp.items()}))
        return out

    def health(self) -> ConnectorHealth:
        self._get("/")
        return ConnectorHealth("WAZUH", configured=True, reachable=True, tls_verified=True, detail="manager API answered")


class LiveWazuhIndexer:
    """Wazuh Indexer (OpenSearch) with a read-only user. Every query is restricted to explicit agent ids."""

    def __init__(self, http: HttpService, user: str, password: str):
        self.http, self._basic = http, _basic(user, password)

    def _search(self, index: str, body: dict) -> dict | None:
        r = self.http.request("POST", f"/{index}/_search", headers={"Authorization": self._basic}, json=body)
        if r.status_code == 404:
            return None  # index not present (e.g. vulnerability detection disabled)
        if r.status_code != 200:
            raise ConnectorUnavailable(f"NovrSIEM event store answered {r.status_code} for a search")
        try:
            return r.json()
        except ValueError:
            raise ConnectorUnavailable("NovrSIEM event store returned a response that is not JSON") from None

    def vulnerability_counts(self, agent_id: str) -> dict[str, int] | None:
        body = self._search(VULN_INDEX, {"size": 0, "track_total_hits": True, "query": {"term": {"agent.id": agent_id}},
                                         "aggs": {"sev": {"terms": {"field": "vulnerability.severity", "size": 10}}}})
        if body is None:
            return None
        total = ((body.get("hits") or {}).get("total") or {}).get("value", 0)
        if not total:
            return None  # no documents: "not scanned" and "no findings" are indistinguishable, so say unavailable
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for b in ((body.get("aggregations") or {}).get("sev") or {}).get("buckets") or []:
            key = str(b.get("key", "")).lower()
            if key in counts:
                counts[key] += int(b.get("doc_count") or 0)
        return counts

    def alert_document(self, agent_ids: list[str], external_id: str) -> dict | None:
        if not agent_ids:
            return None
        body = self._search(ALERT_INDEX, {"size": 1, "query": {"bool": {"filter": [
            {"term": {"id": external_id}}, {"terms": {"agent.id": sorted(agent_ids)}}]}}})
        hits = ((body or {}).get("hits") or {}).get("hits") or []
        doc = hits[0].get("_source") if hits else None
        if doc is not None and str((doc.get("agent") or {}).get("id")) not in agent_ids:
            raise ScopeViolation("the NovrSIEM event store returned an alert outside the organization scope")
        return doc

    def health(self) -> ConnectorHealth:
        r = self.http.request("GET", "/", headers={"Authorization": self._basic})
        if r.status_code != 200:
            raise ConnectorUnavailable(f"NovrSIEM event store answered {r.status_code}")
        return ConnectorHealth("WAZUH_INDEXER", configured=True, reachable=True, tls_verified=True, detail="NovrSIEM event store answered")


class LiveWazuh:
    """Facade used by the API modules (same surface as FixtureWazuh, plus alert evidence and group lookup)."""

    label = "live"

    def __init__(self, manager: LiveWazuhManager, indexer: LiveWazuhIndexer | None):
        self.manager, self.indexer = manager, indexer

    def list_agents(self, scope: OrgScope) -> list[WazuhAgent]:
        return self.manager.list_agents(scope)

    def get_agent(self, scope: OrgScope, agent_id: str) -> WazuhAgent | None:
        return self.manager.get_agent(scope, agent_id)

    def raw_agent(self, agent_id: str) -> dict | None:
        return self.manager.raw_agent(agent_id)

    def sca_policies(self, scope: OrgScope, agent_id: str) -> list[ScaPolicySummary]:
        return self.manager.sca_policies(scope, agent_id)

    def sca_checks(self, scope: OrgScope, agent_id: str, policy_id: str) -> list[ScaCheck]:
        return self.manager.sca_checks(scope, agent_id, policy_id)

    def vulnerability_counts(self, scope: OrgScope, agent_id: str) -> dict[str, int] | None:
        if self.indexer is None or self.manager.get_agent(scope, agent_id) is None:
            return None
        return self.indexer.vulnerability_counts(agent_id)

    def alert_document(self, scope: OrgScope, agent_id: str, external_id: str) -> dict | None:
        if self.indexer is None:
            raise ConnectorUnavailable("NovrSIEM event store is not configured")
        if self.manager.get_agent(scope, agent_id) is None:
            return None
        return self.indexer.alert_document([agent_id], external_id)

    def agent_groups(self, agent_id: str) -> tuple[str, ...] | None:
        return self.manager.agent_groups(agent_id)


def build_live(env: Mapping[str, str], app_env: str, *, manager_transport: httpx.BaseTransport | None = None,
               indexer_transport: httpx.BaseTransport | None = None, sleep: Callable[[float], None] = time.sleep) -> LiveWazuh:
    """Builds the live clients from the environment. Raises ConnectorUnconfigured naming missing settings.
    The indexer is optional: without WAZUH_INDEXER_URL, vulnerability counts and alert evidence are unavailable."""
    mep = manager_endpoint(env, app_env)
    manager = LiveWazuhManager(HttpService(mep, transport=manager_transport, sleep=sleep), env["WAZUH_USER"], env["WAZUH_PASSWORD"])
    indexer = None
    if (env.get("WAZUH_INDEXER_URL") or "").strip():
        iep = indexer_endpoint(env, app_env)
        indexer = LiveWazuhIndexer(HttpService(iep, transport=indexer_transport, sleep=sleep),
                                   env["WAZUH_INDEXER_USER"], env["WAZUH_INDEXER_PASSWORD"])
    return LiveWazuh(manager, indexer)
