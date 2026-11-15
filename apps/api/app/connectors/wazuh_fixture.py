"""LOCAL FIXTURE implementation of the Wazuh connector interfaces (development and tests only).

Serves `fixtures/local_wazuh.json`. It applies the same organization scoping as a real client would
(agent groups from the organization's mappings) and re-checks every agent with filter_agents(strict=True).
Settings refuse fixture mode outside development/test, and every API response that uses it reports the
source state `local_fixture`, so fixture data is never presented as live telemetry.
"""
from __future__ import annotations

import json
from datetime import datetime
from functools import lru_cache
from pathlib import Path

from app.connectors.base import ConnectorHealth, OrgScope
from app.connectors.wazuh import ScaCheck, ScaPolicySummary, WazuhAgent, agent_in_scope, filter_agents

FIXTURE = Path(__file__).resolve().parent / "fixtures" / "local_wazuh.json"


def _ts(v: str | None) -> datetime | None:
    return datetime.fromisoformat(v.replace("Z", "+00:00")) if v else None


@lru_cache
def load_fixture() -> dict:
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


class FixtureWazuh:
    """Implements WazuhManager plus the indexer's vulnerability counts, from the local fixture."""

    label = "local_fixture"

    def __init__(self, data: dict | None = None):
        self.data = data or load_fixture()
        self._agents = {a["agent_id"]: a for a in self.data["agents"]}

    def _to_agent(self, a: dict) -> WazuhAgent:
        os = a.get("os") or {}
        return WazuhAgent(agent_id=a["agent_id"], name=a["name"], groups=tuple(a["groups"]), status=a["status"],
                          os_platform=os.get("platform"), os_version=os.get("version"),
                          agent_version=a.get("version"), last_keepalive_at=_ts(a.get("last_keepalive_at")))

    def raw_agent(self, agent_id: str) -> dict | None:
        return self._agents.get(agent_id)

    def list_agents(self, scope: OrgScope) -> list[WazuhAgent]:
        found = [self._to_agent(a) for a in self.data["agents"] if set(a["groups"]) & scope.wazuh_agent_groups]
        return filter_agents(found, scope)

    def get_agent(self, scope: OrgScope, agent_id: str) -> WazuhAgent | None:
        a = self._agents.get(agent_id)
        if a is None:
            return None
        agent = self._to_agent(a)
        return agent if agent_in_scope(agent, scope) else None

    def sca_policies(self, scope: OrgScope, agent_id: str) -> list[ScaPolicySummary]:
        if self.get_agent(scope, agent_id) is None:
            return []
        out = []
        for p in self.data["sca"].get(agent_id, []):
            applicable = p["passed"] + p["failed"]
            out.append(ScaPolicySummary(agent_id=agent_id, policy_id=p["policy_id"], name=p["name"], passed=p["passed"],
                                        failed=p["failed"], not_applicable=p["not_applicable"],
                                        score_percent=round(100 * p["passed"] / applicable) if applicable else 0,
                                        scanned_at=_ts(p["scanned_at"])))
        return out

    def sca_checks(self, scope: OrgScope, agent_id: str, policy_id: str) -> list[ScaCheck]:
        return []  # the fixture carries policy summaries only

    def vulnerability_counts(self, scope: OrgScope, agent_id: str) -> dict[str, int] | None:
        if self.get_agent(scope, agent_id) is None:
            return None
        v = self.data["vulnerabilities"].get(agent_id)
        return dict(v) if v is not None else None

    def health(self) -> ConnectorHealth:
        return ConnectorHealth("WAZUH", configured=True, reachable=None, tls_verified=False, detail="local fixture")
