"""Minimal JSON-over-HTTPS client (standard library only). TLS verification is always on.

A CA file (PEM) pins the trusted root for one service (e.g. the Wazuh indexer's own CA); without it the system
trust store is used. There is no option to disable verification. Redirects are not followed.
"""
from __future__ import annotations

import json
import socket
import ssl
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple


class HttpError(Exception):
    """Network-level failure (connection, timeout, TLS). The message never contains credentials."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw):
        return None


def tls_context(ca_file: Optional[str]) -> ssl.SSLContext:
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=ca_file) if ca_file else ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


class Http:
    def __init__(self, name: str, ca_file: Optional[str], timeout: float):
        self.name, self.timeout = name, timeout
        self.ctx = tls_context(ca_file)
        self.opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=self.ctx), _NoRedirect())

    def request(self, method: str, url: str, *, headers: Optional[Dict[str, str]] = None,
                body: Any = None) -> Tuple[int, bytes]:
        data = json.dumps(body).encode() if body is not None else None
        h = {"Accept": "application/json", "User-Agent": "novrsoc-forwarder/2"}
        if data is not None:
            h["Content-Type"] = "application/json"
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, method=method, headers=h)
        try:
            with self.opener.open(req, timeout=self.timeout) as r:
                return r.status, r.read()
        except urllib.error.HTTPError as e:
            return e.code, e.read() if e.fp else b""
        except (socket.timeout, TimeoutError):
            raise HttpError(f"{self.name} timed out") from None
        except urllib.error.URLError as e:
            reason = e.reason
            if isinstance(reason, ssl.SSLCertVerificationError) or "CERTIFICATE_VERIFY_FAILED" in str(reason):
                raise HttpError(f"{self.name}: TLS certificate verification failed") from None
            if isinstance(reason, (socket.timeout, TimeoutError)):
                raise HttpError(f"{self.name} timed out") from None
            raise HttpError(f"{self.name} could not be reached") from None
        except (ssl.SSLError, OSError):
            raise HttpError(f"{self.name} could not be reached") from None
