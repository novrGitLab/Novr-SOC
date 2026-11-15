"""Organization-scoped TAXII feeder (Server 1). Disabled until a source is configured and enabled.

For each enabled source: page through the collection from its cursor (added_after), normalize the objects with the
shared STIX 2.1 validator (novrsoc_contracts.stix21), deliver them to the NovrSOC API with the organization-bound
`ti_feeder` identity of that source, and move the cursor (X-TAXII-Date-Added-Last) only after the API acknowledged.
The organization is never in the request: it is the identity's organization. Invalid objects are counted, not sent.

config.json:
  {"api_url": "https://<api>", "api_ca": "<pem path or null>", "state_file": "/var/lib/novrsoc-ti/state.json",
   "sources": [{"name": "isac-feed", "api_root": "https://taxii.example/api1/", "collection_id": "<id>",
                "user": "...", "password_file": "...", "ca_file": null, "token_file": "/etc/novrsoc-ti/<org>.token",
                "enabled": false, "page_size": 100, "max_pages": 20}]}
"""
from __future__ import annotations

import json
import os
import ssl
import urllib.error
import urllib.request
import uuid
from typing import Callable, Optional

from novrsoc_contracts import stix21

from .taxii import TaxiiClient, TaxiiError


def _read(path: str) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read().strip()


class ApiSink:
    def __init__(self, api_url: str, ca: Optional[str] = None, opener=None):
        if not (api_url.startswith("https://") or api_url.startswith("http://127.0.0.1")):
            raise SystemExit("api_url must use https (plain http only for a loopback API)")
        self.url = api_url.rstrip("/")
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.opener = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def deliver(self, token: str, source: str, collection: str, objects: list) -> dict:
        body = json.dumps({"source": source, "collection": collection,
                           "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}}).encode()
        req = urllib.request.Request(f"{self.url}/api/v1/insights/ingest/stix", data=body, method="POST",
                                     headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=60) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            raise TaxiiError(f"NovrSOC API refused the bundle ({e.code})", e.code) from None


class State:
    def __init__(self, path: str):
        self.path = path
        try:
            with open(path, encoding="utf-8") as f:
                self.data = json.load(f)
        except FileNotFoundError:
            self.data = {}

    def cursor(self, source: str) -> Optional[str]:
        return self.data.get(source, {}).get("added_after")

    def advance(self, source: str, added_after: str) -> None:
        self.data.setdefault(source, {})["added_after"] = added_after
        tmp = self.path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(self.data, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.path)


def poll_source(src: dict, client: TaxiiClient, sink: ApiSink, state: State, log: Callable[[str, dict], None]) -> dict:
    token = _read(src["token_file"])
    totals = {"pages": 0, "received": 0, "sent": 0, "invalid": 0, "indicators": 0}
    client.api_root(src["api_root"])
    after, nxt = state.cursor(src["name"]), None
    for _ in range(int(src.get("max_pages", 20))):
        objects, more, nxt, last = client.get_objects(src["api_root"], src["collection_id"], added_after=after,
                                                       limit=int(src.get("page_size", 100)), next_token=nxt)
        totals["pages"] += 1
        totals["received"] += len(objects)
        valid, rejected = stix21.normalize_bundle({"type": "bundle", "objects": objects})
        totals["invalid"] += len(rejected)
        if valid:
            ack = sink.deliver(token, src["name"], src["collection_id"], valid)
            totals["sent"] += len(valid)
            totals["indicators"] += int(ack.get("indicators_imported", 0))
        if last:
            state.advance(src["name"], last)        # only after the API acknowledged this page
        if not more:
            break
    log("source_polled", {"source": src["name"], **totals})
    return totals


def run_once(config: dict, log: Callable[[str, dict], None], client_factory=None, sink: Optional[ApiSink] = None) -> dict:
    enabled = [s for s in config.get("sources", []) if s.get("enabled")]
    if not enabled:
        log("idle", {"reason": "no TAXII source is configured and enabled"})
        return {}
    sink = sink or ApiSink(config["api_url"], config.get("api_ca"))
    state = State(config["state_file"])
    results = {}
    for src in enabled:
        client = (client_factory or (lambda s: TaxiiClient(s.get("user", ""), _read(s["password_file"]) if s.get("password_file") else "",
                                                            s.get("ca_file"))))(src)
        try:
            results[src["name"]] = poll_source(src, client, sink, state, log)
        except TaxiiError as e:
            log("source_failed", {"source": src["name"], "reason": str(e)})
            results[src["name"]] = {"error": str(e)}
    return results
