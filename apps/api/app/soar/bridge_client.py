"""Client for the Server 1 response execution bridge (protocol v1, services/edge/response_bridge).

Signs each request (HMAC-SHA256 over "<unix ts>\\n<canonical body>") and accepts a receipt only when its signature is
valid, it names the same request_id and its timestamp is within the allowed skew. Network failures raise
BridgeUnavailable (the step stays dispatchable with the SAME request_id; the bridge executes it at most once).
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

from app.core.config import Settings
from novrsoc_contracts.v1.soar import ExecutionReceipt

LOOPBACK = {"127.0.0.1", "::1", "localhost"}


class BridgeUnconfigured(Exception):
    pass


class BridgeUnavailable(Exception):
    pass


class BridgeProtocolError(Exception):
    pass


def canonical(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def sign(key: bytes, ts: int, body: bytes) -> str:
    return hmac.new(key, str(ts).encode() + b"\n" + body, hashlib.sha256).hexdigest()


class BridgeClient:
    def __init__(self, url: str, key_id: str, key: bytes, *, ca_cert: str = "", transport: httpx.BaseTransport | None = None,
                 timeout: float = 15.0, clock=time.time):
        parts = urlsplit(url)
        if parts.scheme != "https" and not (parts.scheme == "http" and (parts.hostname or "") in LOOPBACK):
            raise BridgeUnconfigured("NOVRSOC_SOAR_BRIDGE_URL must use https (plain http only for a loopback bridge)")
        if len(key) < 32:
            raise BridgeUnconfigured("the SOAR bridge key must be at least 32 bytes")
        self.key_id, self.key, self.clock = key_id, key, clock
        self.client = httpx.Client(base_url=url.rstrip("/"), timeout=timeout, transport=transport,
                                   verify=(ca_cert or True), follow_redirects=False)

    def execute(self, request: dict) -> ExecutionReceipt:
        body = canonical(request)
        ts = int(self.clock())
        headers = {"X-NovrSOC-Key-Id": self.key_id, "X-NovrSOC-Timestamp": str(ts), "X-NovrSOC-Signature": sign(self.key, ts, body),
                   "Content-Type": "application/json"}
        try:
            r = self.client.post("/v1/execute", content=body, headers=headers)
        except httpx.HTTPError:
            raise BridgeUnavailable("NovrSOAR could not be reached") from None
        if r.status_code not in (200, 409):
            raise BridgeUnavailable(f"NovrSOAR answered {r.status_code}")
        try:
            rts = int(r.headers.get("X-NovrSOC-Timestamp", ""))
        except ValueError:
            raise BridgeProtocolError("receipt without timestamp") from None
        if abs(self.clock() - rts) > 300 or not hmac.compare_digest(sign(self.key, rts, r.content), r.headers.get("X-NovrSOC-Signature", "")):
            raise BridgeProtocolError("the receipt signature is not valid")
        data = json.loads(r.content)
        if data.get("request_id") != request["request_id"]:
            raise BridgeProtocolError("the receipt names another request")
        return ExecutionReceipt.model_validate({k: data.get(k) for k in ("request_id", "status", "reason", "adapter", "command",
                                                                          "executed_at", "replayed") if k in data})


def from_settings(settings: Settings) -> BridgeClient:
    if not settings.soar_bridge_url or not settings.soar_bridge_key_file:
        raise BridgeUnconfigured("NovrSOAR execution is not configured; nothing can be executed")
    try:
        key = Path(settings.soar_bridge_key_file).read_bytes().strip()
    except OSError:
        raise BridgeUnconfigured("NOVRSOC_SOAR_BRIDGE_KEY_FILE cannot be read") from None
    return BridgeClient(settings.soar_bridge_url, settings.soar_bridge_key_id, key, ca_cert=settings.soar_bridge_ca_cert)


# Tests replace this factory to inject a transport to an in-process bridge.
factory = from_settings
