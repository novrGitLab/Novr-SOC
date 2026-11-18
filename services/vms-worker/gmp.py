"""A minimal Greenbone Management Protocol (GMP) client, standard library only (no python-gvm, no lxml).

It implements exactly the calls NovrVMS uses (worker.GreenboneScan and the health check): authenticate, get_version,
get_feeds, get_scan_config, get_tasks / get_task, get_targets / get_target, create_target, create_task, start_task,
stop_task, delete_task, delete_target, get_report. Every command is one XML document; every answer is one XML document
whose `status` attribute is 2xx on success.

Transport, in order of preference:
  * gvmd's Unix socket (GVM_SOCKET), shared from the isolated Greenbone stack through a host directory: no port;
  * TLS to gvmd's GMP listener (GVM_HOST + GVM_PORT, verified against GVM_CA_CERT): for a gvmd on another host.
Authentication is a dedicated Greenbone user (GVM_USER / GVM_PASSWORD) on every session. Errors use python-gvm's class
names (GvmError, GvmResponseError, GvmServerError) so worker.gvm_problem maps them to the same plain reasons.
Responses come from the operator's own gvmd; they are parsed incrementally with ElementTree (expat: no external entity
is ever fetched) and bounded by GVM_MAX_RESPONSE_BYTES.
"""
from __future__ import annotations

import os
import socket
import ssl
import xml.etree.ElementTree as ET
from xml.sax.saxutils import escape, quoteattr

MAX_RESPONSE = int(os.environ.get("GVM_MAX_RESPONSE_BYTES", str(256 * 1024 * 1024)))   # a large report stays well under this


class GvmError(Exception):
    def __init__(self, message: str, status: str = ""):
        super().__init__(message)
        self.message, self.status = message, status


class GvmResponseError(GvmError):
    """gvmd answered 4xx (bad request, authentication, permission)."""


class GvmServerError(GvmError):
    """gvmd answered 5xx (for example 503 while a feed synchronisation holds its lock)."""


def _el(tag: str, attrs: dict | None = None, children: str = "") -> str:
    a = "".join(f" {k}={quoteattr(str(v))}" for k, v in (attrs or {}).items() if v is not None)
    return f"<{tag}{a}>{children}</{tag}>" if children else f"<{tag}{a}/>"


def _text(tag: str, value: str) -> str:
    return f"<{tag}>{escape(str(value))}</{tag}>"


class GmpClient:
    """One GMP session (use as `with GmpClient(...) as gmp:`). Not thread-safe: one session per step, as GreenboneScan does."""

    def __init__(self, *, socket_path: str | None = None, host: str | None = None, port: int = 9390, ca_cert: str | None = None,
                 timeout: float = 300, connect=None):
        if not socket_path and not host:
            raise GvmError("no GMP transport: set GVM_SOCKET (preferred) or GVM_HOST with GVM_CA_CERT")
        if host and not socket_path and not ca_cert:
            raise GvmError("GMP over TCP needs GVM_CA_CERT: the gvmd certificate is always verified")
        self.socket_path, self.host, self.port, self.ca_cert, self.timeout = socket_path, host, port, ca_cert, timeout
        self._connect = connect
        self.sock = None

    # -- transport
    def __enter__(self) -> "GmpClient":
        if self._connect is not None:
            self.sock = self._connect()
        elif self.socket_path:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect(self.socket_path)
            self.sock = s
        else:
            ctx = ssl.create_default_context(cafile=self.ca_cert)
            raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
            self.sock = ctx.wrap_socket(raw, server_hostname=self.host)
        return self

    def __exit__(self, *exc) -> None:
        try:
            if self.sock is not None:
                self.sock.close()
        finally:
            self.sock = None

    def send_command(self, xml: str) -> ET.Element:
        if self.sock is None:
            raise GvmError("the GMP session is not open")
        self.sock.sendall(xml.encode("utf-8"))
        parser = ET.XMLPullParser(events=("start", "end"))
        depth, received, root, tail = 0, 0, None, b""
        while True:
            chunk = self.sock.recv(65536)
            if not chunk:
                raise GvmError("gvmd closed the connection before the answer was complete")
            received += len(chunk)
            if received > MAX_RESPONSE:
                raise GvmError(f"the GMP answer exceeds {MAX_RESPONSE} bytes (GVM_MAX_RESPONSE_BYTES)")
            parser.feed(chunk)
            tail = (tail + chunk)[-512:].rstrip()
            done = None
            for event, el in parser.read_events():
                depth += 1 if event == "start" else -1
                if event == "start" and root is None:
                    root = el
                if event == "end" and depth == 0:
                    done = el
            if done is not None:
                return self._checked(done)
            # expat holds back the LAST token until more input arrives, and gvmd sends nothing after an answer: once
            # the bytes end with the root's closing tag (or a self-closing root), close the parser to flush it.
            closing = (depth == 1 and root is not None and tail.endswith(f"</{root.tag}>".encode())) or \
                      (depth == 0 and tail.endswith(b"/>"))
            if closing:
                parser.close()
                for event, el in parser.read_events():
                    if event == "start" and root is None:
                        root = el
                return self._checked(root)

    @staticmethod
    def _checked(resp: ET.Element) -> ET.Element:
        status = resp.get("status", "")
        text = resp.get("status_text", "") or resp.tag
        if status.startswith("2"):
            return resp
        if status.startswith("4"):
            raise GvmResponseError(text, status)
        if status.startswith("5"):
            raise GvmServerError(text, status)
        raise GvmError(f"unexpected GMP status {status or 'missing'}: {text}", status)

    # -- commands (the subset NovrVMS uses)
    def authenticate(self, username: str, password: str) -> ET.Element:
        if not username or not password:
            raise GvmResponseError("authentication failed: GVM_USER / GVM_PASSWORD are not set", "400")
        return self.send_command(_el("authenticate", children=_el("credentials", children=_text("username", username) + _text("password", password))))

    def get_version(self) -> ET.Element:
        return self.send_command(_el("get_version"))

    def get_feeds(self) -> ET.Element:
        return self.send_command(_el("get_feeds"))

    def get_scan_config(self, config_id: str) -> ET.Element:
        resp = self.send_command(_el("get_configs", {"config_id": config_id, "details": "1"}))
        cfg = resp.find("config")
        if cfg is None:
            raise GvmResponseError(f"scan configuration {config_id} not found", "404")
        return cfg

    def get_tasks(self, filter_string: str = "") -> ET.Element:
        return self.send_command(_el("get_tasks", {"filter": filter_string or None}))

    def get_task(self, task_id: str) -> ET.Element:
        return self.send_command(_el("get_tasks", {"task_id": task_id, "details": "1"}))

    def get_targets(self, filter_string: str = "") -> ET.Element:
        return self.send_command(_el("get_targets", {"filter": filter_string or None}))

    def get_target(self, target_id: str) -> ET.Element:
        return self.send_command(_el("get_targets", {"target_id": target_id}))

    def create_target(self, name: str, hosts: list[str], port_list_id: str, alive_test: str | None = None) -> ET.Element:
        body = _text("name", name) + _text("hosts", ",".join(hosts)) + _el("port_list", {"id": port_list_id})
        if alive_test:
            body += _text("alive_tests", alive_test)
        return self.send_command(_el("create_target", children=body))

    def create_task(self, name: str, config_id: str, target_id: str, scanner_id: str) -> ET.Element:
        body = _text("name", name) + _el("config", {"id": config_id}) + _el("target", {"id": target_id}) + _el("scanner", {"id": scanner_id})
        return self.send_command(_el("create_task", children=body))

    def start_task(self, task_id: str) -> ET.Element:
        return self.send_command(_el("start_task", {"task_id": task_id}))

    def stop_task(self, task_id: str) -> ET.Element:
        return self.send_command(_el("stop_task", {"task_id": task_id}))

    def delete_task(self, task_id: str, ultimate: bool = False) -> ET.Element:
        return self.send_command(_el("delete_task", {"task_id": task_id, "ultimate": "1" if ultimate else "0"}))

    def delete_target(self, target_id: str, ultimate: bool = False) -> ET.Element:
        return self.send_command(_el("delete_target", {"target_id": target_id, "ultimate": "1" if ultimate else "0"}))

    def get_report(self, report_id: str, filter_string: str = "", report_format_id: str | None = None, ignore_pagination: bool = False,
                   details: bool = False) -> ET.Element:
        return self.send_command(_el("get_reports", {"report_id": report_id, "filter": filter_string or None,
                                                     "format_id": report_format_id, "ignore_pagination": "1" if ignore_pagination else None,
                                                     "details": "1" if details else None}))


def session_from_env(env=os.environ):
    """The factory GreenboneScan calls for every step: a fresh session on the configured transport."""
    sock = env.get("GVM_SOCKET", "").strip()
    host = env.get("GVM_HOST", "").strip()
    return GmpClient(socket_path=sock if sock and (os.path.exists(sock) or not host) else None, host=host or None,
                     port=int(env.get("GVM_PORT", "9390")), ca_cert=env.get("GVM_CA_CERT") or None,
                     timeout=max(30, int(env.get("GVM_SOCKET_TIMEOUT_SECONDS", "300"))))
