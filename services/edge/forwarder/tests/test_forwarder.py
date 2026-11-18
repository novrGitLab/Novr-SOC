"""Forwarder tests (standard library only). Fake indexer, fake manager and fake API; no real service.

Run: python -m unittest discover -s services/edge/forwarder/tests -t services/edge/forwarder
"""
from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from novrsoc_forwarder import logs  # noqa: E402
from novrsoc_forwarder.core import EXIT_FATAL, Config, Fatal, Forwarder, Retryable, batch_id_for, to_ingest  # noqa: E402
from novrsoc_forwarder.http import HttpError  # noqa: E402
from novrsoc_forwarder.state import LockError, State  # noqa: E402

TOKEN = "nsk_" + "a" * 32 + ".forwarder-secret-value-XYZ123"  # gitleaks:allow (synthetic)
NOW = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
T0 = NOW - timedelta(hours=1)


def alert(i: int, ts: datetime, agent="101", level=7, **extra):
    a = {"id": f"{int(ts.timestamp())}.{i}", "timestamp": ts.strftime("%Y-%m-%dT%H:%M:%S.000+0000"),
         "rule": {"id": "5710", "level": level, "description": f"rule {i}", "mitre": {"id": ["T1110", "bad"]}},
         "agent": {"id": agent, "name": f"host-{agent}"}, "data": {"srcip": "203.0.113.9"},
         "full_log": "Accepted password=hunter2 for root"}
    a.update(extra)
    return a


class FakeIndexer:
    def __init__(self, docs):
        self.docs = sorted(docs, key=lambda d: (self.ms(d), d["id"]))
        self.fail = []
        self.partial = False
        self.queries = []

    @staticmethod
    def ms(d):
        from novrsoc_forwarder.core import parse_ts
        return int(parse_ts(d["timestamp"]).timestamp() * 1000)

    def request(self, method, url, headers=None, body=None):
        self.queries.append(body)
        if self.fail:
            f = self.fail.pop(0)
            if f == "net":
                raise HttpError("indexer could not be reached")
            return f, b"{}"
        if not (headers or {}).get("Authorization", "").startswith("Basic "):
            return 401, b"{}"
        if self.partial:
            return 200, json.dumps({"_shards": {"failed": 1}, "hits": {"hits": []}}).encode()
        rng = body["query"]["bool"]["filter"][0]["range"]["timestamp"]
        lo, hi = datetime.fromisoformat(rng["gte"]), datetime.fromisoformat(rng.get("lte") or rng["lt"])
        exclusive = "lt" in rng   # the backfill reads [start, end); the live forwarder [since, until]
        after = body.get("search_after")
        out = []
        for d in self.docs:
            pos = [self.ms(d), d["id"]]
            t = datetime.fromtimestamp(pos[0] / 1000, tz=timezone.utc)
            if not (lo <= t and (t < hi if exclusive else t <= hi)) or (after and pos <= after):
                continue
            out.append({"_source": d, "sort": pos})
            if len(out) >= body["size"]:
                break
        return 200, json.dumps({"_shards": {"failed": 0}, "hits": {"hits": out}}).encode()


class FakeManager:
    def __init__(self, groups=None):
        self.groups = groups if groups is not None else {"101": ["nv-alpha-servers"], "201": ["nv-beta-servers"]}
        self.fail = 0
        self.list_calls = 0

    def request(self, method, url, headers=None, body=None):
        if self.fail:
            self.fail -= 1
            raise HttpError("manager could not be reached")
        if url.endswith("/security/user/authenticate"):
            return 200, json.dumps({"data": {"token": "jwt"}}).encode()
        self.list_calls += 1
        items = [{"id": k, "group": v} for k, v in self.groups.items()]
        return 200, json.dumps({"data": {"affected_items": items, "total_affected_items": len(items)}}).encode()


class FakeApi:
    """The V2 ingest semantics: dedupe per alert id, receipts per batch_id, quarantine for unmapped groups."""

    def __init__(self):
        self.stored, self.receipts, self.posts, self.fail = {}, {}, [], []
        self.invalid_ids = set()
        self.lose_answer = 0
        self.mapped = {"nv-alpha-servers", "nv-beta-servers"}

    def request(self, method, url, headers=None, body=None):
        self.posts.append(body)
        if self.fail:
            f = self.fail.pop(0)
            if f == "net":
                raise HttpError("api could not be reached")
            return f, b'{"error": {}}'
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, b"{}"
        assert "org_id" not in body and all("org_id" not in a and "severity" not in a for a in body["alerts"])
        if any(a["id"] in self.invalid_ids for a in body["alerts"]):
            return 422, b"{}"
        ids = [a["id"] for a in body["alerts"]]
        bid = body["batch_id"]
        if bid in self.receipts:
            r = self.receipts[bid]
            if r["ids"] != ids:
                return 409, b"{}"
            return 200, json.dumps({**r["ack"], "replayed": True}).encode()
        acc = dup = q = 0
        for a in body["alerts"]:
            if not set(a["agent"]["groups"]) & self.mapped:
                q += 1
            elif a["id"] in self.stored:
                dup += 1
            else:
                self.stored[a["id"]] = a
                acc += 1
        ack = {"batch_id": bid, "accepted": acc, "duplicates": dup, "quarantined": q, "durable": True, "replayed": False}
        self.receipts[bid] = {"ids": ids, "ack": ack}
        if self.lose_answer:
            self.lose_answer -= 1
            raise HttpError("api timed out")  # stored, but the forwarder never sees the answer
        return 200, json.dumps(ack).encode()


class Base(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.secrets = {}
        for name, value in (("token", TOKEN), ("idx", "indexer-pass"), ("mgr", "manager-pass")):
            path = os.path.join(self.dir, name)
            with open(path, "w") as f:
                f.write(value)
            self.secrets[name] = path
        self.env = {"NOVRSOC_API_URL": "https://novrsoc-api.test", "WAZUH_INDEXER_URL": "https://127.0.0.1:9200",
                    "WAZUH_API_URL": "https://127.0.0.1:55000", "NOVRSOC_FORWARDER_TOKEN_FILE": self.secrets["token"],
                    "WAZUH_INDEXER_USER": "novrsoc-ro", "WAZUH_INDEXER_PASSWORD_FILE": self.secrets["idx"],
                    "WAZUH_API_USER": "novrsoc-ro", "WAZUH_API_PASSWORD_FILE": self.secrets["mgr"],
                    "FORWARDER_STATE_DIR": os.path.join(self.dir, "state"), "FORWARDER_START_AT": T0.isoformat(),
                    "FORWARDER_BATCH": "3", "FORWARDER_SETTLE_SECONDS": "60", "FORWARDER_LATE_EVERY": "0"}
        self.out = io.StringIO()
        logs.set_sink(self.out)
        self.sleeps = []

    def tearDown(self):
        logs.set_sink(sys.stdout)
        shutil.rmtree(self.dir, ignore_errors=True)

    def make(self, docs, api=None, manager=None, env=None):
        cfg = Config({**self.env, **(env or {})})
        self.indexer, self.api, self.manager = FakeIndexer(docs), api or FakeApi(), manager or FakeManager()
        self.state = State(cfg.state_dir)
        return Forwarder(cfg, api=self.api, indexer=self.indexer, manager=self.manager, state=self.state,
                         now=lambda: NOW, sleep=self.sleeps.append)


class TestForwarding(Base):
    def test_first_run_starts_at_the_configured_time_and_saves_the_position(self):
        docs = [alert(i, T0 + timedelta(minutes=i)) for i in range(5)] + [alert(99, T0 - timedelta(minutes=5))]
        f = self.make(docs)
        self.assertEqual(f.forward_once(1), 5)
        self.assertEqual(len(self.api.stored), 5)
        cp = self.state.load()
        self.assertEqual(cp.sort[1], docs[4]["id"])
        self.assertEqual(f.forward_once(2), 0)  # strictly after the checkpoint: nothing again

    def test_batches_respect_the_cap_and_carry_groups_never_org(self):
        f = self.make([alert(i, T0 + timedelta(seconds=i)) for i in range(7)])
        f.forward_once(1)
        self.assertEqual([len(p["alerts"]) for p in self.api.posts], [3, 3, 1])
        a = self.api.posts[0]["alerts"][0]
        self.assertEqual(a["agent"]["groups"], ["nv-alpha-servers"])
        self.assertEqual(a["rule"]["mitre_ids"], ["T1110"])
        self.assertTrue(all(b["batch_id"].startswith("fwd-") for b in self.api.posts))

    def test_unsettled_alerts_wait_for_a_later_cycle(self):
        f = self.make([alert(1, NOW - timedelta(seconds=10))])
        self.assertEqual(f.forward_once(1), 0)

    def test_unmapped_agents_are_counted_as_quarantined(self):
        f = self.make([alert(1, T0, agent="555")], manager=FakeManager({"101": ["nv-alpha-servers"]}))
        f.forward_once(1)
        self.assertEqual(self.api.receipts[self.api.posts[0]["batch_id"]]["ack"]["quarantined"], 1)
        self.assertIsNotNone(self.state.load().sort)  # acknowledged (quarantined), so the checkpoint advances


class TestFailuresAndRecovery(Base):
    def test_api_outage_keeps_the_checkpoint_and_retries_with_backoff(self):
        f = self.make([alert(i, T0 + timedelta(seconds=i)) for i in range(2)])
        self.api.fail = ["net", 503, 429]
        rc = f.run(max_cycles=4)
        self.assertEqual(rc, 0)
        self.assertEqual(len(self.api.stored), 2)
        self.assertEqual(len(self.sleeps), 4)
        self.assertTrue(all(s <= 300 for s in self.sleeps))
        events = [json.loads(l)["event"] for l in self.out.getvalue().splitlines()]
        self.assertEqual(events.count("cycle_retry"), 3)

    def test_failed_cycle_never_advances(self):
        f = self.make([alert(1, T0)])
        self.api.fail = [503]
        with self.assertRaises(Retryable):
            f.forward_once(1)
        self.assertIsNone(self.state.load().sort)

    def test_lost_acknowledgement_is_replayed_with_the_same_batch_id(self):
        f = self.make([alert(i, T0 + timedelta(seconds=i)) for i in range(3)])
        self.api.lose_answer = 1
        with self.assertRaises(Retryable):
            f.forward_once(1)
        self.assertEqual(f.forward_once(2), 3)
        first, second = self.api.posts[0]["batch_id"], self.api.posts[1]["batch_id"]
        self.assertEqual(first, second)
        self.assertEqual(len(self.api.stored), 3)  # nothing stored twice

    def test_restart_mid_burst_resumes_exactly_where_it_stopped(self):
        docs = [alert(i, T0 + timedelta(seconds=i)) for i in range(7)]
        f = self.make(docs)
        self.api.fail = ["net"] * 0
        f.cfg.max_pages = 1
        f.forward_once(1)  # one page of 3, then "crash"
        self.assertEqual(len(self.api.stored), 3)
        g = Forwarder(Config(self.env), api=self.api, indexer=self.indexer, manager=self.manager,
                      state=State(self.env["FORWARDER_STATE_DIR"]), now=lambda: NOW, sleep=self.sleeps.append)
        g.forward_once(2)
        self.assertEqual(sorted(self.api.stored), sorted(d["id"] for d in docs))
        self.assertEqual(sum(len(p["alerts"]) for p in self.api.posts), 7)  # no page sent twice

    def test_credential_refused_or_batch_conflict_stops_the_service(self):
        f = self.make([alert(1, T0)])
        self.api.fail = [401]
        self.assertEqual(f.run(max_cycles=3), EXIT_FATAL)
        f2 = self.make([alert(1, T0)])
        self.api.fail = [409]
        self.assertEqual(f2.run(max_cycles=3), EXIT_FATAL)

    def test_invalid_alerts_are_isolated_and_dead_lettered_without_content(self):
        docs = [alert(i, T0 + timedelta(seconds=i)) for i in range(3)]
        api = FakeApi()
        api.invalid_ids = {docs[1]["id"]}
        f = self.make(docs, api=api)
        f.forward_once(1)
        self.assertEqual(set(api.stored), {docs[0]["id"], docs[2]["id"]})
        with open(self.state.dead) as fh:
            dead = [json.loads(l) for l in fh]
        self.assertEqual([d["alert_id"] for d in dead], [docs[1]["id"]])
        self.assertNotIn("hunter2", json.dumps(dead))

    def test_locally_invalid_alerts_never_reach_the_api(self):
        f = self.make([alert(1, T0, level=99), alert(2, T0 + timedelta(seconds=1))])
        f.forward_once(1)
        self.assertEqual([len(p["alerts"]) for p in self.api.posts], [1])

    def test_indexer_failures_and_partial_answers_never_advance(self):
        f = self.make([alert(1, T0)])
        self.indexer.partial = True
        with self.assertRaises(Retryable):
            f.forward_once(1)
        self.assertIsNone(self.state.load().sort)
        self.indexer.partial = False
        self.indexer.fail = [500]
        with self.assertRaises(Retryable):
            f.forward_once(2)
        self.indexer.fail = [401]
        with self.assertRaises(Fatal):
            f.forward_once(3)

    def test_group_cache_stale_tolerance_then_refusal(self):
        f = self.make([alert(1, T0)])
        f.groups.refresh()
        self.manager.fail = 10
        f.groups.loaded_at -= 400            # past the 5-minute cache, within max-stale: stale map is used
        self.assertEqual(f.groups.get("101"), ["nv-alpha-servers"])
        f.groups.loaded_at -= 4000           # past max-stale: refuse to send
        with self.assertRaises(Retryable):
            f.groups.get("101")

    def test_corrupt_cursor_stops_instead_of_restarting(self):
        f = self.make([alert(1, T0)])
        os.makedirs(self.env["FORWARDER_STATE_DIR"], exist_ok=True)
        with open(os.path.join(self.env["FORWARDER_STATE_DIR"], "cursor.json"), "w") as fh:
            fh.write("{not json")
        with self.assertRaises(Fatal):
            f.forward_once(1)

    def test_single_instance_lock(self):
        s1 = State(self.env["FORWARDER_STATE_DIR"])
        s1.lock()
        try:
            with self.assertRaises(LockError):
                State(self.env["FORWARDER_STATE_DIR"]).lock()
        finally:
            s1.unlock()

    def test_late_sweep_resends_the_overlap_without_moving_the_checkpoint(self):
        docs = [alert(i, T0 + timedelta(seconds=i)) for i in range(2)]
        f = self.make(docs, env={"FORWARDER_LATE_EVERY": "1"})
        f.forward_once(1)
        cp = self.state.load()
        late = alert(50, T0)   # indexed late; its position (T0, '.50') is before the checkpoint (T0+1s)
        self.indexer.docs = sorted(self.indexer.docs + [late], key=lambda d: (FakeIndexer.ms(d), d["id"]))
        f.forward_once(1)
        self.assertIn(late["id"], self.api.stored)
        self.assertEqual(self.state.load().sort, cp.sort)


class TestConfigAndLogs(Base):
    def test_configuration_is_strict(self):
        for change, msg in ((dict(NOVRSOC_API_URL="http://x.test"), "https"), (dict(NOVRSOC_API_URL=""), "NOVRSOC_API_URL"),
                            (dict(FORWARDER_START_AT=""), "FORWARDER_START_AT")):
            with self.assertRaisesRegex(Fatal, msg):
                Config({**self.env, **change})
        with open(self.secrets["token"], "w") as fh:
            fh.write("not-a-token")
        with self.assertRaisesRegex(Fatal, "nsk_"):
            Config(self.env)

    def test_secrets_are_never_logged(self):
        f = self.make([alert(1, T0)])
        self.api.fail = [401]
        f.run(max_cycles=1)
        logs.log("info", "probe", note=f"Authorization: Bearer {TOKEN} password=indexer-pass")
        text = self.out.getvalue()
        for secret in (TOKEN, "indexer-pass", "manager-pass", "hunter2"):
            self.assertNotIn(secret, text)

    def test_ingest_shape(self):
        class G:
            def get(self, agent_id):
                return ["g1"]
        out, reason = to_ingest(alert(1, T0), G())
        self.assertIsNone(reason)
        self.assertEqual(set(out), {"id", "timestamp", "rule", "agent", "src_ip", "raw"})
        self.assertEqual(to_ingest(alert(2, T0, agent="x"), G()), (None, "agent_id_invalid"))
        self.assertEqual(batch_id_for([[1, "a"]]), batch_id_for([[1, "a"]]))


class TestTls(unittest.TestCase):
    def test_unverified_certificate_is_refused(self):
        try:
            sys.path.insert(0, os.path.join(HERE, "..", "..", "..", "..", "apps", "api"))
            import cryptography  # noqa: F401  (test-only: builds throwaway certificates)
            from tests.helpers.tls_server import JsonHttpsServer
        except Exception as e:  # cryptography not installed in a minimal runtime: the API CI job runs this test
            self.skipTest(f"TLS helper unavailable: {e}")
        from novrsoc_forwarder.http import Http
        with JsonHttpsServer("novrsoc-api.test", {"/": (200, {"ok": True})}) as srv:
            with self.assertRaisesRegex(HttpError, "TLS certificate verification failed"):
                Http("api", None, 5).request("GET", f"https://127.0.0.1:{srv.port}/")
            ca = os.path.join(tempfile.mkdtemp(), "ca.pem")
            with open(ca, "w") as fh:
                fh.write(srv.cert)
            # Pinned CA but the URL host (127.0.0.1) is not the certificate's name: still refused.
            with self.assertRaisesRegex(HttpError, "TLS certificate verification failed"):
                Http("api", ca, 5).request("GET", f"https://127.0.0.1:{srv.port}/")


if __name__ == "__main__":
    unittest.main()
