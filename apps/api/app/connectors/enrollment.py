"""NovrSIEM manager API client for SERVER-CONTROLLED agent enrollment (the only write-capable manager client).

NovrSOC registers each agent itself, in the organization's provisioned group, when an installer presents a valid,
organization-bound enrollment ticket. Agents therefore never self-enroll: the manager's own password-based enrollment
(authd) can be switched off, and no organization can place an agent in another organization's group.

Least privilege: a dedicated manager API user (WAZUH_ENROLLMENT_USER / WAZUH_ENROLLMENT_PASSWORD) whose role allows
only: manager:read (version), group:read and group:create, agent:create, agent:modify_group, and agent:delete (to undo a
registration whose group assignment failed). TLS verification always on (WAZUH_ENROLLMENT_CA_CERT /
WAZUH_ENROLLMENT_TLS_SERVERNAME). No automatic retry: a repeated POST could register an agent twice.
"""
from __future__ import annotations

import base64
import re
import threading
import time
from collections.abc import Callable, Mapping
from typing import Any

from app.connectors.base import ConnectorError, ConnectorRejected, ConnectorUnavailable, load_endpoint
from app.connectors.wazuh_live import HttpService

CREDENTIALS = ("WAZUH_ENROLLMENT_USER", "WAZUH_ENROLLMENT_PASSWORD")
NAME = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
VERSION = re.compile(r"^v?(\d+)\.(\d+)\.(\d+)")


class EnrollmentRejected(ConnectorError):
    """The manager refused the operation itself (e.g. the agent name is taken)."""


class ManagerEnrollment:
    TOKEN_SECONDS = 600

    def __init__(self, http: HttpService, user: str, password: str, clock: Callable[[], float] = time.time):
        self.http, self.clock = http, clock
        self._basic = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()
        self._token: str | None = None
        self._token_exp = 0.0
        self._lock = threading.Lock()

    def _auth(self) -> str:
        with self._lock:
            if self._token and self.clock() < self._token_exp:
                return self._token
            r = self.http.request("POST", "/security/user/authenticate", headers={"Authorization": self._basic})
            if r.status_code != 200:
                raise ConnectorRejected(f"NovrSIEM enrollment authentication failed ({r.status_code})")
            try:
                self._token = r.json()["data"]["token"]
            except (ValueError, KeyError, TypeError):
                raise ConnectorUnavailable("NovrSIEM returned an unexpected authentication response") from None
            self._token_exp = self.clock() + self.TOKEN_SECONDS
            return self._token

    def _call(self, method: str, path: str, *, params: Mapping[str, Any] | None = None, json: Any = None) -> dict:
        r = self.http.request(method, path, headers={"Authorization": f"Bearer {self._auth()}"}, params=params, json=json)
        try:
            body = r.json()
        except ValueError:
            raise ConnectorUnavailable("NovrSIEM returned a response that is not JSON") from None
        if r.status_code >= 400 or body.get("error") not in (0, None):
            detail = str(body.get("detail") or body.get("message") or body.get("title") or r.status_code)[:200]
            raise EnrollmentRejected(f"NovrSIEM refused the enrollment step: {detail}")
        return body

    @staticmethod
    def _items(body: dict) -> list[dict]:
        return list(((body.get("data") or {}).get("affected_items")) or [])

    def version(self) -> str:
        """The manager's version, e.g. '4.9.2'."""
        body = self._call("GET", "/")
        v = str((body.get("data") or {}).get("api_version") or "")
        m = VERSION.match(v)
        if not m:
            raise ConnectorUnavailable("NovrSIEM did not report its version")
        return ".".join(m.groups())

    def has_group(self, group: str) -> bool:
        return any(g.get("name") == group for g in self._items(self._call("GET", "/groups", params={"groups_list": group})))

    def ensure_group(self, group: str) -> bool:
        """Create the group if it does not exist. Returns True when it was created now."""
        if not NAME.match(group):
            raise EnrollmentRejected("invalid group name")
        if any(g.get("name") == group for g in self._items(self._call("GET", "/groups", params={"groups_list": group}))):
            return False
        self._call("POST", "/groups", json={"group_id": group})
        return True

    def register(self, name: str) -> tuple[str, str]:
        """Register an agent (any source address). Returns (agent id, agent key)."""
        if not NAME.match(name):
            raise EnrollmentRejected("invalid agent name")
        data = self._call("POST", "/agents", json={"name": name, "ip": "any"}).get("data") or {}
        agent_id, key = str(data.get("id") or ""), str(data.get("key") or "")
        if not re.fullmatch(r"\d{3,6}", agent_id) or not key:
            raise ConnectorUnavailable("NovrSIEM did not return the registered agent")
        return agent_id, key

    def assign_only_group(self, agent_id: str, group: str) -> None:
        """Make `group` the agent's ONLY group (the organization's provisioned group, never `default`)."""
        self._call("PUT", f"/agents/{agent_id}/group/{group}", params={"force_single_group": "true"})

    def remove(self, agent_id: str) -> None:
        self._call("DELETE", "/agents", params={"agents_list": agent_id, "status": "all", "older_than": "0s"})

    def health(self) -> None:
        self.version()


def enrollment_from_env(env: Mapping[str, str], app_env: str, *, transport=None) -> ManagerEnrollment:
    ep = load_endpoint("WAZUH_ENROLLMENT", env, app_env=app_env, credential_names=CREDENTIALS)
    return ManagerEnrollment(HttpService(ep, transport=transport, retries=0), env["WAZUH_ENROLLMENT_USER"], env["WAZUH_ENROLLMENT_PASSWORD"])
