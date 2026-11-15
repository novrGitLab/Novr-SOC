"""NovrSOC V2 Wazuh response execution bridge (Server 1). Standard library only.

The bridge EXECUTES; it never decides. Decisions (playbooks, policies, approvals, audit) live in the SOAR engine on
Server 2. A request is executed only when every check passes, in this order:
  1. HMAC-SHA256 signature over "<unix timestamp>\\n<body>" with the key named by X-NovrSOC-Key-Id; timestamp within
     ±120 s of the bridge clock.
  2. Protocol v1 body; expires_at in the future and at most 15 minutes after issued_at.
  3. Idempotency and replay: a request_id already seen returns its stored receipt (nothing runs twice); the same
     request_id with a different body is refused (request_id_conflict).
  4. Tenant authorization held by the BRIDGE (config, not the request): the organization is known, the action is in
     its allow-list and in the global allow-list, and for agent-targeted actions the agent's Wazuh groups intersect the
     organization's authorized groups (looked up by the adapter, never taken from the request).
  5. Target guards: block_ip refuses invalid, loopback, link-local, multicast and configured never-block networks.
  6. mode dry_run returns a dry_run receipt without touching Wazuh. mode live calls the adapter: `simulated` (default;
     records the command, executes nothing) or `wazuh` (PUT /active-response on the local manager; refused unless the
     configuration says allow_live: true).
Every answer is a receipt signed with the same key, stored durably (SQLite) before it is returned.
"""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import re
import sqlite3
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, Optional, Tuple

ACTIONS = {"block_ip": "firewall-drop", "isolate_agent": "novrsoc-isolate", "disable_account": "disable-account"}
AGENT = re.compile(r"^\d{3,6}$")
ACCOUNT = re.compile(r"^[A-Za-z0-9._\\-]{1,64}$")
MAX_SKEW = 120
MAX_TTL = timedelta(minutes=15)


def canonical(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign(key: bytes, ts: int, body: bytes) -> str:
    return hmac.new(key, str(ts).encode() + b"\n" + body, hashlib.sha256).hexdigest()


def verify(key: bytes, ts: int, body: bytes, signature: str) -> bool:
    return hmac.compare_digest(sign(key, ts, body), signature or "")


def _ts(v: str) -> Optional[datetime]:
    try:
        d = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.tzinfo else None


class SimulatedAdapter:
    """Executes nothing. Agent groups come from configuration (the fake 'manager'). Records every command."""
    name = "simulated"

    def __init__(self, agent_groups: Dict[str, list]):
        self.agent_groups = agent_groups
        self.executed: list = []

    def groups(self, agent_id: str) -> Optional[list]:
        return self.agent_groups.get(agent_id)

    def execute(self, command: str, agent_id: Optional[str], arguments: list) -> Tuple[bool, str]:
        self.executed.append({"command": command, "agent_id": agent_id, "arguments": arguments})
        return True, f"simulated: {command} recorded for agent {agent_id or 'n/a'}; nothing was executed"


class Bridge:
    def __init__(self, config: dict, keys: Dict[str, bytes], adapter, db_path: str = ":memory:",
                 clock: Callable[[], float] = time.time, bridge_id: str = "server1-bridge"):
        self.cfg, self.keys, self.adapter, self.clock, self.bridge_id = config, keys, adapter, clock, bridge_id
        self.never_block = [ipaddress.ip_network(n, strict=False) for n in config.get("never_block", [])]
        self.allowed = set(config.get("actions", [])) & set(ACTIONS)
        self.allow_live = bool(config.get("allow_live", False))
        self._lock = threading.Lock()
        self.db = sqlite3.connect(db_path, check_same_thread=False)
        self.db.execute("CREATE TABLE IF NOT EXISTS receipts (request_id TEXT PRIMARY KEY, body_sha TEXT NOT NULL, "
                        "receipt TEXT NOT NULL, created_at TEXT NOT NULL)")
        self.db.commit()

    # ---- receipts -------------------------------------------------------------------------------
    def _receipt(self, req: dict, status: str, reason: str, command: Optional[str] = None) -> dict:
        return {"v": 1, "request_id": req.get("request_id"), "org_id": req.get("org_id"), "action": req.get("action"),
                "agent_id": req.get("agent_id"), "target": req.get("target"), "status": status, "reason": reason,
                "adapter": self.adapter.name, "command": command, "bridge_id": self.bridge_id,
                "executed_at": datetime.fromtimestamp(self.clock(), tz=timezone.utc).isoformat()}

    def _signed(self, key_id: str, receipt: dict, http_status: int = 200) -> Tuple[int, Dict[str, str], bytes]:
        body = canonical(receipt)
        ts = int(self.clock())
        return http_status, {"X-NovrSOC-Key-Id": key_id, "X-NovrSOC-Timestamp": str(ts),
                             "X-NovrSOC-Signature": sign(self.keys[key_id], ts, body), "Content-Type": "application/json"}, body

    # ---- the request ----------------------------------------------------------------------------
    def handle(self, headers: Dict[str, str], body: bytes) -> Tuple[int, Dict[str, str], bytes]:
        h = {k.lower(): v for k, v in headers.items()}
        key_id = h.get("x-novrsoc-key-id", "")
        if key_id not in self.keys:
            return 401, {"Content-Type": "application/json"}, b'{"error":"unknown_key"}'
        try:
            ts = int(h.get("x-novrsoc-timestamp", ""))
        except ValueError:
            return 401, {"Content-Type": "application/json"}, b'{"error":"bad_timestamp"}'
        if abs(self.clock() - ts) > MAX_SKEW or not verify(self.keys[key_id], ts, body, h.get("x-novrsoc-signature", "")):
            return 401, {"Content-Type": "application/json"}, b'{"error":"bad_signature"}'
        try:
            req = json.loads(body)
            assert isinstance(req, dict)
        except (ValueError, AssertionError):
            return 400, {"Content-Type": "application/json"}, b'{"error":"bad_body"}'
        body_sha = hashlib.sha256(canonical(req)).hexdigest()
        with self._lock:
            row = self.db.execute("SELECT body_sha, receipt FROM receipts WHERE request_id = ?", (str(req.get("request_id")),)).fetchone()
            if row is not None:
                if row[0] != body_sha:
                    return self._signed(key_id, self._receipt(req, "rejected", "request_id_conflict"), 409)
                stored = json.loads(row[1])
                stored["replayed"] = True
                return self._signed(key_id, stored)
            receipt = self._decide(req)
            if receipt["status"] != "rejected" or receipt["reason"] not in ("expired", "bad_request"):
                self.db.execute("INSERT INTO receipts VALUES (?, ?, ?, ?)",
                                (str(req.get("request_id")), body_sha, json.dumps(receipt), receipt["executed_at"]))
                self.db.commit()
        return self._signed(key_id, receipt)

    def _decide(self, req: dict) -> dict:
        try:
            uuid.UUID(str(req.get("request_id"))), uuid.UUID(str(req.get("org_id"))), uuid.UUID(str(req.get("approval_id")))
        except ValueError:
            return self._receipt(req, "rejected", "bad_request")
        issued, expires = _ts(req.get("issued_at", "")), _ts(req.get("expires_at", ""))
        now = datetime.fromtimestamp(self.clock(), tz=timezone.utc)
        if req.get("v") != 1 or issued is None or expires is None or req.get("mode") not in ("dry_run", "live"):
            return self._receipt(req, "rejected", "bad_request")
        if expires <= now or expires - issued > MAX_TTL:
            return self._receipt(req, "rejected", "expired")
        action = req.get("action")
        tenant = (self.cfg.get("tenants") or {}).get(str(req["org_id"]))
        if action not in self.allowed or tenant is None or action not in tenant.get("actions", []):
            return self._receipt(req, "rejected", "action_not_authorized")
        agent_id = req.get("agent_id")
        target = str(req.get("target") or "")
        if action == "isolate_agent" or agent_id is not None:
            if not AGENT.match(str(agent_id or "")):
                return self._receipt(req, "rejected", "agent_required")
            groups = self.adapter.groups(str(agent_id))
            if not groups or not set(groups) & set(tenant.get("agent_groups", [])):
                return self._receipt(req, "rejected", "agent_not_authorized")
        if action == "block_ip":
            try:
                ip = ipaddress.ip_address(target)
            except ValueError:
                return self._receipt(req, "rejected", "invalid_target")
            if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or any(ip in n for n in self.never_block):
                return self._receipt(req, "rejected", "protected_target")
        if action == "disable_account" and not ACCOUNT.match(target):
            return self._receipt(req, "rejected", "invalid_target")
        command = ACTIONS[action]
        if req["mode"] == "dry_run":
            return self._receipt(req, "dry_run", "validated; nothing executed (dry run)", command)
        if self.adapter.name != "simulated" and not self.allow_live:
            return self._receipt(req, "rejected", "live_execution_disabled", command)
        ok, detail = self.adapter.execute(command, agent_id, [target])
        return self._receipt(req, "executed" if ok else "failed", detail[:300], command)


def make_request(key_id: str, key: bytes, req: dict, clock: Callable[[], float] = time.time) -> Tuple[Dict[str, str], bytes]:
    """Client side (used by tests and documented for the Server 2 engine): signed headers and canonical body."""
    body = canonical(req)
    ts = int(clock())
    return {"X-NovrSOC-Key-Id": key_id, "X-NovrSOC-Timestamp": str(ts), "X-NovrSOC-Signature": sign(key, ts, body),
            "Content-Type": "application/json"}, body
