"""TAXII 2.1 client and feeder against the local TAXII test server (no external service).
Run: python -m unittest discover -s services/edge/threat_intel/tests   (PYTHONPATH must include packages/contracts/python)"""
import json
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", "..", ".."))
sys.path[:0] = [os.path.dirname(HERE), HERE, os.path.join(ROOT, "packages", "contracts", "python")]

from novrsoc_ti.feeder import run_once  # noqa: E402
from novrsoc_ti.taxii import MEDIA, TaxiiClient, TaxiiError  # noqa: E402
from taxii_test_server import COLLECTION, PASSWORD, USER, TaxiiTestServer  # noqa: E402


class FakeSink:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    def deliver(self, token, source, collection, objects):
        if self.fail:
            raise TaxiiError("NovrSOC API refused the bundle (503)", 503)
        self.calls.append((token, source, collection, [o["id"] for o in objects]))
        return {"indicators_imported": sum(1 for o in objects if o["type"] == "indicator")}


def client(user=USER, password=PASSWORD):
    return TaxiiClient(user, password, allow_loopback_http=True)


class TaxiiClientTests(unittest.TestCase):
    def test_discovery_api_root_collections_and_paged_objects(self):
        with TaxiiTestServer() as srv:
            c = client()
            self.assertEqual(c.discover(srv.url)["api_roots"], ["/api1/"])
            root = srv.url + "/api1/"
            self.assertIn(MEDIA, c.api_root(root)["versions"])
            self.assertEqual(c.collections(root)[0]["id"], COLLECTION)
            objs, more, nxt, last = c.get_objects(root, COLLECTION, limit=2)
            self.assertEqual((len(objs), more, nxt), (2, True, "2"))
            objs2, more2, _, last2 = c.get_objects(root, COLLECTION, limit=10, added_after=last)
            self.assertEqual((len(objs2), more2), (3, False))
            self.assertGreater(last2, last)

    def test_auth_media_type_and_https_rules(self):
        with TaxiiTestServer() as srv:
            with self.assertRaises(TaxiiError) as e:
                client(password="wrong").discover(srv.url)
            self.assertEqual(e.exception.status, 401)
            with self.assertRaises(TaxiiError):
                TaxiiClient(USER, PASSWORD).discover(srv.url)          # plain http refused unless loopback is allowed explicitly
        import urllib.request
        with TaxiiTestServer() as srv:
            req = urllib.request.Request(srv.url + "/taxii2/", headers={"Accept": "application/json",
                                         "Authorization": "Basic " + __import__("base64").b64encode(f"{USER}:{PASSWORD}".encode()).decode()})
            with self.assertRaises(urllib.error.HTTPError) as e:
                urllib.request.urlopen(req)
            self.assertEqual(e.exception.code, 406)


class FeederTests(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.token = os.path.join(self.dir, "org.token")
        with open(self.token, "w") as f:
            f.write("nsk_" + "b" * 32 + ".feeder-token-value-0001")  # gitleaks:allow (synthetic)
        self.events = []

    def cfg(self, url, enabled=True):
        return {"api_url": "http://127.0.0.1:1", "state_file": os.path.join(self.dir, "state.json"),
                "sources": [{"name": "demo-feed", "api_root": url + "/api1/", "collection_id": COLLECTION, "user": USER,
                             "token_file": self.token, "enabled": enabled, "page_size": 2}]}

    def log(self, e, f):
        self.events.append((e, f))

    def test_disabled_until_configured(self):
        self.assertEqual(run_once({"sources": []}, self.log), {})
        self.assertEqual(self.events[0][0], "idle")

    def test_pages_normalizes_delivers_and_resumes_from_the_cursor(self):
        with TaxiiTestServer() as srv:
            sink = FakeSink()
            out = run_once(self.cfg(srv.url), self.log, client_factory=lambda s: client(), sink=sink)["demo-feed"]
            self.assertEqual((out["received"], out["sent"], out["invalid"], out["indicators"]), (5, 4, 1, 2))
            self.assertEqual((out["pages"], len(sink.calls)), (3, 2))  # 3 pages; the last holds only the invalid object, so nothing is sent
            self.assertTrue(all(c[0].startswith("nsk_") and c[1] == "demo-feed" for c in sink.calls))
            again = run_once(self.cfg(srv.url), self.log, client_factory=lambda s: client(), sink=sink)["demo-feed"]
            self.assertEqual(again["received"], 0)                     # nothing new after the cursor
            with open(os.path.join(self.dir, "state.json")) as f:
                self.assertTrue(json.load(f)["demo-feed"]["added_after"].startswith("2026-11-14"))

    def test_api_refusal_does_not_move_the_cursor(self):
        with TaxiiTestServer() as srv:
            out = run_once(self.cfg(srv.url), self.log, client_factory=lambda s: client(), sink=FakeSink(fail=True))
            self.assertIn("error", out["demo-feed"])
            self.assertFalse(os.path.exists(os.path.join(self.dir, "state.json")))


if __name__ == "__main__":
    unittest.main()
