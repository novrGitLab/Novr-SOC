"""Fake Wazuh Manager API and Wazuh Indexer for automated tests (httpx MockTransport). Never a real Wazuh.

The data mirrors the local fixture's shape: agents with groups, SCA policies, vulnerability documents and alert
documents. Failure injection: `fail_next` (status codes or "timeout"/"connect" to return/raise before the next
successful answers), `reject_auth`, and `out_of_scope_leak` (the manager ignores the group filter, as a broken
upstream would; the client must refuse).
"""
from __future__ import annotations

import json
from collections import deque
from dataclasses import dataclass, field

import httpx

AGENTS = [
    {"id": "000", "name": "wazuh-manager", "group": [], "status": "active"},
    {"id": "101", "name": "alpha-web", "group": ["nv-alpha-servers"], "status": "active", "ip": "10.1.0.5",
     "os": {"platform": "ubuntu", "name": "Ubuntu", "version": "22.04"}, "version": "Wazuh v4.9.0",
     "lastKeepAlive": "2026-11-10T09:00:00+00:00"},
    {"id": "102", "name": "alpha-ws", "group": ["nv-alpha-workstations"], "status": "disconnected", "ip": "10.1.4.7",
     "os": {"platform": "windows", "name": "Microsoft Windows 11 Pro", "version": "10.0.22631"}, "version": "Wazuh v4.9.0",
     "lastKeepAlive": "2026-11-08T17:00:00+00:00"},
    {"id": "201", "name": "beta-app", "group": ["nv-beta-servers"], "status": "active", "ip": "10.2.0.9",
     "os": {"platform": "debian", "name": "Debian GNU/Linux", "version": "12"}, "version": "Wazuh v4.9.0",
     "lastKeepAlive": "2026-11-10T09:01:00+00:00"},
]
SCA = {"101": [{"policy_id": "cis_ubuntu22-04", "name": "CIS Ubuntu 22.04", "pass": 120, "fail": 40, "invalid": 10,
                "score": 75, "end_scan": "2026-11-09T02:00:00+00:00"}]}
VULNS = {"101": {"Critical": 2, "High": 3, "Medium": 4}}  # 201 has none: "not scanned" must stay unavailable
ALERTS = {"1731229200.101": {"id": "1731229200.101", "timestamp": "2026-11-10T09:00:00.000+0000",
                             "agent": {"id": "101", "name": "alpha-web"},
                             "rule": {"id": "5710", "level": 10, "description": "sshd: attempt to login using a non-existent user"},
                             "data": {"srcip": "203.0.113.50"}, "full_log": "sshd[1]: Invalid user admin password=hunter2"}}


@dataclass
class FakeWazuh:
    fail_next: deque = field(default_factory=deque)
    reject_auth: bool = False
    out_of_scope_leak: bool = False
    expire_tokens: int = 0
    calls: list = field(default_factory=list)
    auth_count: int = 0

    def _inject(self, request):
        if self.fail_next:
            f = self.fail_next.popleft()
            if f == "timeout":
                raise httpx.ReadTimeout("fake timeout", request=request)
            if f == "connect":
                raise httpx.ConnectError("fake connection refused", request=request)
            return httpx.Response(int(f))
        return None

    # ---- manager
    def manager(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(("manager", request.method, request.url.path, dict(request.url.params)))
        injected = self._inject(request)
        if injected is not None:
            return injected
        path = request.url.path
        if path == "/security/user/authenticate":
            if self.reject_auth or not request.headers.get("authorization", "").startswith("Basic "):
                return httpx.Response(401, json={"title": "Unauthorized"})
            self.auth_count += 1
            return httpx.Response(200, json={"data": {"token": f"jwt-{self.auth_count}"}})
        if not request.headers.get("authorization", "").startswith("Bearer jwt-"):
            return httpx.Response(401)
        if self.expire_tokens > 0:
            self.expire_tokens -= 1
            return httpx.Response(401)
        params = request.url.params
        if path == "/":
            return httpx.Response(200, json={"data": {"title": "Wazuh API REST", "api_version": "4.9.0"}})
        if path == "/agents":
            items = AGENTS
            if "group" in params and not self.out_of_scope_leak:
                items = [a for a in AGENTS if params["group"] in a["group"]]
            if "agents_list" in params:
                ids = params["agents_list"].split(",")
                items = [a for a in AGENTS if a["id"] in ids]
            return httpx.Response(200, json={"data": {"affected_items": items, "total_affected_items": len(items)}})
        if path.startswith("/sca/"):
            parts = path.split("/")
            items = SCA.get(parts[2], []) if len(parts) == 3 else []
            return httpx.Response(200, json={"data": {"affected_items": items, "total_affected_items": len(items)}})
        return httpx.Response(404)

    # ---- indexer
    def indexer(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(("indexer", request.method, request.url.path, request.content.decode() if request.content else ""))
        injected = self._inject(request)
        if injected is not None:
            return injected
        if not request.headers.get("authorization", "").startswith("Basic "):
            return httpx.Response(401)
        if request.url.path == "/":
            return httpx.Response(200, json={"cluster_name": "wazuh-indexer-fake"})
        body = json.loads(request.content or b"{}")
        if request.url.path.startswith("/wazuh-states-vulnerabilities-"):
            agent = body["query"]["term"]["agent.id"]
            counts = VULNS.get(agent, {})
            return httpx.Response(200, json={"hits": {"total": {"value": sum(counts.values())}},
                                             "aggregations": {"sev": {"buckets": [{"key": k, "doc_count": v} for k, v in counts.items()]}}})
        if request.url.path.startswith("/wazuh-alerts-"):
            f = body["query"]["bool"]["filter"]
            xid = f[0]["term"]["id"]
            agents = f[1]["terms"]["agent.id"]
            doc = ALERTS.get(xid)
            hits = [{"_source": doc}] if doc and doc["agent"]["id"] in agents else []
            return httpx.Response(200, json={"hits": {"hits": hits}})
        return httpx.Response(404)

    def transports(self):
        return httpx.MockTransport(self.manager), httpx.MockTransport(self.indexer)


LIVE_ENV = {"WAZUH_URL": "https://wazuh-manager.test:55000", "WAZUH_USER": "novrsoc-ro", "WAZUH_PASSWORD": "fake-not-a-secret",
            "WAZUH_INDEXER_URL": "https://wazuh-indexer.test:9200", "WAZUH_INDEXER_USER": "novrsoc-ro",
            "WAZUH_INDEXER_PASSWORD": "fake-not-a-secret"}  # gitleaks:allow (synthetic test values)
