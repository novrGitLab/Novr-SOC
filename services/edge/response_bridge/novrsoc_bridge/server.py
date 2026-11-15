"""HTTP(S) front end of the bridge. Listens on the WireGuard address (or loopback in development) only.

  python -m novrsoc_bridge --config /etc/novrsoc-bridge/bridge.json

bridge.json (no secrets inline; keys are files):
  {"listen": "10.66.0.1", "port": 8650, "tls_cert": "...", "tls_key": "...",     # TLS required unless listen is loopback
   "keys": {"server2-soar": "/etc/novrsoc-bridge/server2-soar.key"},
   "state_db": "/var/lib/novrsoc-bridge/receipts.sqlite3",
   "adapter": "simulated" | "wazuh", "allow_live": false,
   "wazuh": {"url": "https://127.0.0.1:55000", "user": "...", "password_file": "...", "ca_file": "..."},
   "simulated_agents": {"001": ["nv-alpha-servers"]},
   "actions": ["block_ip"], "never_block": ["10.66.0.0/24"],
   "tenants": {"<org uuid>": {"actions": ["block_ip"], "agent_groups": ["nv-alpha-servers"]}}}
"""
from __future__ import annotations

import argparse
import json
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from .core import Bridge, SimulatedAdapter
from .wazuh import WazuhAdapter

LOOPBACK = {"127.0.0.1", "::1", "localhost"}
MAX_BODY = 16 * 1024


def build(cfg: dict) -> Bridge:
    keys = {}
    for key_id, path in cfg["keys"].items():
        with open(path, "rb") as f:
            keys[key_id] = f.read().strip()
        if len(keys[key_id]) < 32:
            raise SystemExit(f"key {key_id} is shorter than 32 bytes")
    adapter = (WazuhAdapter(cfg["wazuh"]) if cfg.get("adapter") == "wazuh"
               else SimulatedAdapter(cfg.get("simulated_agents", {})))
    return Bridge(cfg, keys, adapter, db_path=cfg.get("state_db", ":memory:"), bridge_id=cfg.get("bridge_id", "server1-bridge"))


def serve(cfg: dict) -> None:
    bridge = build(cfg)

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            if self.path != "/v1/execute":
                self.send_error(404)
                return
            n = int(self.headers.get("Content-Length") or 0)
            if n <= 0 or n > MAX_BODY:
                self.send_error(413)
                return
            status, headers, body = bridge.handle(dict(self.headers), self.rfile.read(n))
            self.send_response(status)
            for k, v in headers.items():
                self.send_header(k, v)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            if self.path == "/v1/health":
                body = json.dumps({"status": "ok", "adapter": bridge.adapter.name, "allow_live": bridge.allow_live}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            else:
                self.send_error(404)

        def log_message(self, fmt, *args):  # structured, no bodies
            sys.stdout.write(json.dumps({"event": "http", "path": self.path, "status": args[1] if len(args) > 1 else ""}) + "\n")

    httpd = ThreadingHTTPServer((cfg.get("listen", "127.0.0.1"), int(cfg.get("port", 8650))), Handler)
    if cfg.get("listen", "127.0.0.1") not in LOOPBACK:
        if not cfg.get("tls_cert"):
            raise SystemExit("TLS (tls_cert/tls_key) is required unless the bridge listens on loopback")
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cfg["tls_cert"], cfg["tls_key"])
        httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    print(json.dumps({"event": "started", "listen": cfg.get("listen"), "port": cfg.get("port"), "adapter": bridge.adapter.name}), flush=True)
    httpd.serve_forever()


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m novrsoc_bridge")
    ap.add_argument("--config", required=True)
    args = ap.parse_args(argv)
    with open(args.config, encoding="utf-8") as f:
        serve(json.load(f))
    return 0
