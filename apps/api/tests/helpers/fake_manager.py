"""A fake NovrSIEM manager API (enrollment endpoints only), served through httpx.MockTransport. No network."""
from __future__ import annotations

import base64
import json

import httpx

from app.connectors.base import Endpoint
from app.connectors.enrollment import ManagerEnrollment
from app.connectors.wazuh_live import HttpService


class FakeManager:
    def __init__(self, version: str = "v4.9.2"):
        self.version = version
        self.groups: set[str] = {"default"}
        self.agents: dict[str, dict] = {}
        self.fail_group_assignment = False
        self.calls: list[tuple[str, str]] = []
        self._next = 101

    def handler(self, req: httpx.Request) -> httpx.Response:
        path, method = req.url.path, req.method
        self.calls.append((method, path))
        ok = lambda data=None, status=200: httpx.Response(status, json={"error": 0, "data": data or {}})  # noqa: E731
        if path == "/security/user/authenticate":
            return ok({"token": "t"})
        if req.headers.get("authorization") != "Bearer t":
            return httpx.Response(401, json={"title": "Unauthorized"})
        if method == "GET" and path == "/":
            return ok({"api_version": self.version})
        if path == "/groups" and method == "GET":
            want = req.url.params.get("groups_list")
            return ok({"affected_items": [{"name": want}] if want in self.groups else []})
        if path == "/groups" and method == "POST":
            self.groups.add(json.loads(req.content)["group_id"])
            return ok()
        if path == "/agents" and method == "POST":
            name = json.loads(req.content)["name"]
            if any(a["name"] == name for a in self.agents.values()):
                return httpx.Response(400, json={"error": 1, "title": "Bad Request", "detail": f"Agent {name} already exists"})
            aid = f"{self._next:03d}"
            self._next += 1
            key = base64.b64encode(f"{aid} {name} any {'f' * 64}".encode()).decode()
            self.agents[aid] = {"name": name, "groups": ["default"], "key": key}
            return ok({"id": aid, "key": key})
        if path.startswith("/agents/") and "/group/" in path and method == "PUT":
            aid, group = path.split("/")[2], path.split("/")[4]
            if self.fail_group_assignment or group not in self.groups:
                return httpx.Response(400, json={"error": 1, "title": "Bad Request", "detail": "group does not exist"})
            assert req.url.params.get("force_single_group") == "true"
            self.agents[aid]["groups"] = [group]
            return ok()
        if path == "/agents" and method == "DELETE":
            self.agents.pop(req.url.params.get("agents_list"), None)
            return ok()
        return httpx.Response(404, json={"error": 1, "title": "Not found"})

    def client(self) -> ManagerEnrollment:
        ep = Endpoint(name="WAZUH_ENROLLMENT", base_url="https://siem.test:55000", tls=None, timeout_seconds=5, credential_names=())
        return ManagerEnrollment(HttpService(ep, transport=httpx.MockTransport(self.handler), retries=0), "enroll", "secret")
