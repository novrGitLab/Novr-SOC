"""TAXII 2.1 client (OASIS TAXII Version 2.1, sections 3-5). Standard library only.

Implements what a consumer needs: Server Discovery (GET /taxii2/), API Root information, Get Collections, and Get
Objects with `added_after`, `limit` and `next` pagination (envelope: more / next / objects), the TAXII 2.1 media type in
Accept, the X-TAXII-Date-Added-Last header as the resume cursor, HTTP Basic authentication and verified TLS.
"""
from __future__ import annotations

import base64
import json
import ssl
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

MEDIA = "application/taxii+json;version=2.1"


class TaxiiError(Exception):
    def __init__(self, message: str, status: int = 0):
        super().__init__(message)
        self.status = status


class TaxiiClient:
    def __init__(self, user: str = "", password: str = "", ca_file: Optional[str] = None, timeout: float = 30.0,
                 allow_loopback_http: bool = False):
        self.auth = "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode() if user else None
        self.ctx = ssl.create_default_context(cafile=ca_file) if ca_file else ssl.create_default_context()
        self.timeout, self.allow_http = timeout, allow_loopback_http

    def _get(self, url: str) -> tuple[dict, dict]:
        parts = urllib.parse.urlsplit(url)
        if parts.scheme != "https" and not (self.allow_http and parts.hostname in ("127.0.0.1", "localhost", "::1")):
            raise TaxiiError("TAXII servers must be reached over https")
        headers = {"Accept": MEDIA}
        if self.auth:
            headers["Authorization"] = self.auth
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, context=self.ctx, timeout=self.timeout) as r:
                ctype = r.headers.get("Content-Type", "")
                if "taxii+json" not in ctype:
                    raise TaxiiError(f"unexpected content type {ctype!r}")
                return json.loads(r.read() or b"{}"), dict(r.headers)
        except urllib.error.HTTPError as e:
            raise TaxiiError(f"TAXII server answered {e.code}", e.code) from None
        except urllib.error.URLError as e:
            raise TaxiiError("TAXII server could not be reached" + (" (TLS verification failed)" if "CERTIFICATE" in str(e.reason) else "")) from None

    def discover(self, server_url: str) -> dict:
        body, _ = self._get(server_url.rstrip("/") + "/taxii2/")
        return body

    def api_root(self, api_root_url: str) -> dict:
        body, _ = self._get(api_root_url.rstrip("/") + "/")
        if MEDIA not in (body.get("versions") or []):
            raise TaxiiError("the API root does not support TAXII 2.1")
        return body

    def collections(self, api_root_url: str) -> list[dict]:
        body, _ = self._get(api_root_url.rstrip("/") + "/collections/")
        return body.get("collections") or []

    def get_objects(self, api_root_url: str, collection_id: str, *, added_after: Optional[str] = None, limit: int = 100,
                    next_token: Optional[str] = None) -> tuple[list[dict], bool, Optional[str], Optional[str]]:
        """One page: (objects, more, next, date_added_last)."""
        q = {"limit": str(limit)}
        if added_after:
            q["added_after"] = added_after
        if next_token:
            q["next"] = next_token
        url = f"{api_root_url.rstrip('/')}/collections/{urllib.parse.quote(collection_id)}/objects/?{urllib.parse.urlencode(q)}"
        body, headers = self._get(url)
        h = {k.lower(): v for k, v in headers.items()}
        return body.get("objects") or [], bool(body.get("more")), body.get("next"), h.get("x-taxii-date-added-last")
