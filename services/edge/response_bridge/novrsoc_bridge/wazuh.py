"""Live Wazuh active-response adapter. NOT used in tests against a real manager and refused by the bridge unless the
configuration sets allow_live: true (a separate, signed approval). TLS is verified (optional CA file)."""
from __future__ import annotations

import base64
import json
import ssl
import urllib.request
from typing import Optional, Tuple


class WazuhAdapter:
    name = "wazuh"

    def __init__(self, cfg: dict):
        self.url = cfg["url"].rstrip("/")
        if not self.url.startswith("https://"):
            raise SystemExit("wazuh.url must use https")
        with open(cfg["password_file"], encoding="utf-8") as f:
            password = f.read().strip()
        self.basic = "Basic " + base64.b64encode(f"{cfg['user']}:{password}".encode()).decode()
        ctx = ssl.create_default_context(cafile=cfg.get("ca_file"))
        ctx.check_hostname, ctx.verify_mode = True, ssl.CERT_REQUIRED
        self.ctx = ctx

    def _call(self, method: str, path: str, token: Optional[str] = None, body: Optional[dict] = None) -> dict:
        req = urllib.request.Request(self.url + path, method=method, data=json.dumps(body).encode() if body else None,
                                     headers={"Authorization": f"Bearer {token}" if token else self.basic,
                                              "Content-Type": "application/json"})
        with urllib.request.urlopen(req, context=self.ctx, timeout=15) as r:
            return json.loads(r.read() or b"{}")

    def _token(self) -> str:
        return self._call("POST", "/security/user/authenticate")["data"]["token"]

    def groups(self, agent_id: str) -> Optional[list]:
        items = self._call("GET", f"/agents?agents_list={agent_id}&select=id,group", self._token())["data"]["affected_items"]
        return next((a.get("group") or [] for a in items if a.get("id") == agent_id), None)

    def execute(self, command: str, agent_id: Optional[str], arguments: list) -> Tuple[bool, str]:
        path = "/active-response" + (f"?agents_list={agent_id}" if agent_id else "")
        r = self._call("PUT", path, self._token(), {"command": f"!{command}", "arguments": arguments})
        failed = (r.get("data") or {}).get("total_failed_items", 0)
        return failed == 0, f"wazuh active-response {command}: {r.get('message', '')}"
