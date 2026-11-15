"""Response bridge tests. Simulated adapter only; no Wazuh, no real agent, nothing executed.
Run: python -m unittest discover -s services/edge/response_bridge/tests"""
from __future__ import annotations

import json
import os
import sys
import unittest
import uuid
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from novrsoc_bridge.core import Bridge, SimulatedAdapter, make_request, verify  # noqa: E402

KEY = b"k" * 48
ORG_A, ORG_B = str(uuid.uuid4()), str(uuid.uuid4())
NOW = 1_800_000_000.0
CFG = {"actions": ["block_ip", "isolate_agent"], "never_block": ["10.66.0.0/24"],
       "tenants": {ORG_A: {"actions": ["block_ip", "isolate_agent"], "agent_groups": ["nv-alpha-servers"]},
                   ORG_B: {"actions": ["block_ip"], "agent_groups": ["nv-beta-servers"]}}}


def req(**kw):
    issued = datetime.fromtimestamp(NOW, tz=timezone.utc)
    base = {"v": 1, "request_id": str(uuid.uuid4()), "org_id": ORG_A, "run_id": str(uuid.uuid4()), "step_key": "block",
            "action": "block_ip", "agent_id": None, "target": "203.0.113.50", "approval_id": str(uuid.uuid4()),
            "approved_by": str(uuid.uuid4()), "issued_at": issued.isoformat(),
            "expires_at": (issued + timedelta(minutes=5)).isoformat(), "mode": "live"}
    base.update(kw)
    return base


class BridgeTests(unittest.TestCase):
    def setUp(self):
        self.adapter = SimulatedAdapter({"001": ["nv-alpha-servers"], "004": ["nv-beta-servers"]})
        self.bridge = Bridge(CFG, {"server2": KEY}, self.adapter, clock=lambda: NOW)

    def send(self, body, key=KEY, key_id="server2", clock=lambda: NOW, raw=None):
        headers, data = make_request(key_id, key, body, clock=clock)
        status, h, out = self.bridge.handle(headers, raw if raw is not None else data)
        return status, h, json.loads(out)

    def test_signed_live_request_executes_on_the_simulated_adapter_with_a_signed_receipt(self):
        status, h, r = self.send(req())
        self.assertEqual((status, r["status"], r["adapter"], r["command"]), (200, "executed", "simulated", "firewall-drop"))
        self.assertTrue(verify(KEY, int(h["X-NovrSOC-Timestamp"]), json.dumps(r, sort_keys=True, separators=(",", ":")).encode(),
                               h["X-NovrSOC-Signature"]))
        self.assertEqual(len(self.adapter.executed), 1)

    def test_signature_key_and_clock_skew(self):
        self.assertEqual(self.send(req(), key=b"x" * 48)[0], 401)
        self.assertEqual(self.send(req(), key_id="unknown")[0], 401)
        self.assertEqual(self.send(req(), clock=lambda: NOW - 600)[0], 401)
        headers, data = make_request("server2", KEY, req(), clock=lambda: NOW)
        self.assertEqual(self.bridge.handle(headers, data.replace(b"203.0.113.50", b"203.0.113.51"))[0], 401)  # tampered body
        self.assertEqual(self.adapter.executed, [])

    def test_replay_is_idempotent_and_conflicts_are_refused(self):
        r1 = req()
        first = self.send(r1)[2]
        again = self.send(r1)[2]
        self.assertTrue(again["replayed"])
        self.assertEqual(again["executed_at"], first["executed_at"])
        self.assertEqual(len(self.adapter.executed), 1)                     # executed once
        status, _, conflict = self.send({**r1, "target": "198.51.100.9"})
        self.assertEqual((status, conflict["reason"]), (409, "request_id_conflict"))

    def test_expiry_and_ttl(self):
        past = datetime.fromtimestamp(NOW - 600, tz=timezone.utc)
        self.assertEqual(self.send(req(issued_at=past.isoformat(), expires_at=(past + timedelta(minutes=5)).isoformat()))[2]["reason"], "expired")
        now = datetime.fromtimestamp(NOW, tz=timezone.utc)
        self.assertEqual(self.send(req(expires_at=(now + timedelta(hours=2)).isoformat()))[2]["reason"], "expired")

    def test_tenant_action_and_agent_authorization_held_by_the_bridge(self):
        self.assertEqual(self.send(req(org_id=ORG_B, action="isolate_agent", agent_id="004", target="004"))[2]["reason"], "action_not_authorized")
        self.assertEqual(self.send(req(org_id=str(uuid.uuid4())))[2]["reason"], "action_not_authorized")
        self.assertEqual(self.send(req(action="disable_account", target="jdoe"))[2]["reason"], "action_not_authorized")
        # Cross-tenant: org A asks to isolate org B's agent -> refused by the bridge's own group check.
        self.assertEqual(self.send(req(action="isolate_agent", agent_id="004", target="004"))[2]["reason"], "agent_not_authorized")
        self.assertEqual(self.send(req(action="isolate_agent", agent_id="999", target="999"))[2]["reason"], "agent_not_authorized")
        self.assertEqual(self.send(req(action="isolate_agent", agent_id="001", target="001"))[2]["status"], "executed")

    def test_protected_targets_and_dry_run(self):
        for t, reason in (("10.66.0.2", "protected_target"), ("127.0.0.1", "protected_target"), ("not-an-ip", "invalid_target")):
            self.assertEqual(self.send(req(target=t))[2]["reason"], reason)
        dry = self.send(req(mode="dry_run"))[2]
        self.assertEqual(dry["status"], "dry_run")
        self.assertEqual(self.adapter.executed, [])

    def test_live_wazuh_adapter_is_refused_without_explicit_allow_live(self):
        class FakeWazuh(SimulatedAdapter):
            name = "wazuh"
        bridge = Bridge(CFG, {"server2": KEY}, FakeWazuh({}), clock=lambda: NOW)
        headers, data = make_request("server2", KEY, req(), clock=lambda: NOW)
        self.assertEqual(json.loads(bridge.handle(headers, data)[2])["reason"], "live_execution_disabled")
        self.assertEqual(bridge.adapter.executed, [])


if __name__ == "__main__":
    unittest.main()
