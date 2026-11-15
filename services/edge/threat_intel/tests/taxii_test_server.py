"""A minimal TAXII 2.1 server for interoperability tests (never deployed). Serves one API root with one collection.

Implements: Server Discovery, API Root, Get Collections, Get Objects with added_after / limit / next, the
X-TAXII-Date-Added-First/Last headers, HTTP Basic auth (401), and media-type negotiation (406 without
application/taxii+json;version=2.1 in Accept).
"""
from __future__ import annotations

import base64
import json
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MEDIA = "application/taxii+json;version=2.1"
COLLECTION = "91a7b528-80eb-42ed-a74d-c6fbd5a26116"
USER, PASSWORD = "feeder", "feeder-test-password"  # gitleaks:allow (synthetic test credential)

DEMO_BUNDLE_OBJECTS = [
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f",
     "created": "2026-11-01T00:00:00.000Z", "modified": "2026-11-01T00:00:00.000Z", "name": "SSH brute force source",
     "pattern": "[ipv4-addr:value = '203.0.113.45']", "pattern_type": "stix", "valid_from": "2026-11-01T00:00:00Z",
     "confidence": 80, "object_marking_refs": ["marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421"]},
    {"type": "malware", "spec_version": "2.1", "id": "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc",
     "created": "2026-10-20T00:00:00.000Z", "modified": "2026-10-20T00:00:00.000Z", "name": "SSHBrute (demo family)", "is_family": True},
    {"type": "relationship", "spec_version": "2.1", "id": "relationship--44298a74-ba52-4f0c-87a3-1824e67d7fad",
     "created": "2026-11-01T00:00:00.000Z", "modified": "2026-11-01T00:00:00.000Z", "relationship_type": "indicates",
     "source_ref": "indicator--8e2e2d2b-17d4-4cbf-938f-98ee46b3cd3f", "target_ref": "malware--31b940d4-6f7f-459a-80ea-9c1f17b58abc"},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--0a6f2e0e-8f7b-4a1c-9c66-1b2b3c4d5e6f",
     "created": "2026-11-02T00:00:00.000Z", "modified": "2026-11-02T00:00:00.000Z", "name": "Phishing lookalike",
     "pattern": "[domain-name:value = 'devalpah.com']", "pattern_type": "stix", "valid_from": "2026-11-02T00:00:00Z", "confidence": 70},
    {"type": "indicator", "spec_version": "2.1", "id": "indicator--bad", "created": "2026-11-03T00:00:00.000Z",
     "modified": "2026-11-03T00:00:00.000Z", "pattern": "[x:y = 'z']", "pattern_type": "stix", "valid_from": "2026-11-03T00:00:00Z"},
]


class TaxiiTestServer:
    def __init__(self, objects=None):
        # date_added is the server's own ingestion time (strictly increasing), per TAXII 2.1.
        self.entries = [(f"2026-11-1{i}T00:00:0{i}.000Z", o) for i, o in enumerate(objects or DEMO_BUNDLE_OBJECTS)]
        self.requests = []
        server = self

        class H(BaseHTTPRequestHandler):
            def _send(self, status, body=None, headers=None):
                data = json.dumps(body).encode() if body is not None else b""
                self.send_response(status)
                self.send_header("Content-Type", MEDIA)
                for k, v in (headers or {}).items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                server.requests.append(self.path)
                if self.headers.get("Authorization") != "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode():
                    return self._send(401, {"title": "Unauthorized"})
                if MEDIA not in (self.headers.get("Accept") or ""):
                    return self._send(406, {"title": "Not Acceptable"})
                path, _, query = self.path.partition("?")
                q = dict(urllib.parse.parse_qsl(query))
                if path == "/taxii2/":
                    return self._send(200, {"title": "Test TAXII", "default": "/api1/", "api_roots": ["/api1/"]})
                if path == "/api1/":
                    return self._send(200, {"title": "API 1", "versions": [MEDIA], "max_content_length": 10485760})
                if path == "/api1/collections/":
                    return self._send(200, {"collections": [{"id": COLLECTION, "title": "Demo", "can_read": True, "can_write": False,
                                                             "media_types": ["application/stix+json;version=2.1"]}]})
                if path == f"/api1/collections/{COLLECTION}/objects/":
                    rows = [e for e in server.entries if not q.get("added_after") or e[0] > q["added_after"]]
                    start = int(q.get("next") or 0)
                    limit = int(q.get("limit") or 100)
                    page = rows[start:start + limit]
                    more = start + limit < len(rows)
                    hdr = {"X-TAXII-Date-Added-First": page[0][0], "X-TAXII-Date-Added-Last": page[-1][0]} if page else {}
                    return self._send(200, {"more": more, "next": str(start + limit) if more else None, "objects": [o for _, o in page]}, hdr)
                return self._send(404, {"title": "Not Found"})

            def log_message(self, *a):
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.url = f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def __enter__(self):
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        return self

    def __exit__(self, *a):
        self.httpd.shutdown()
        self.httpd.server_close()
