"""Historical backfill (novrsoc_forwarder.backfill): read-only planning, explicit approval, cross-tenant filtering,
duplicate replay, interrupted batches, stale ownership, historical cutoffs and state isolation from the live forwarder.
Fakes only (indexer, manager, API); the real API contract is covered by apps/api/tests/modules/soc/test_backfill_contract.py.
    python -m unittest discover -s tests"""
import io
import json
import os
import sys
import tempfile
import unittest
from datetime import timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from novrsoc_forwarder import backfill as bf  # noqa: E402
from novrsoc_forwarder import logs  # noqa: E402
from novrsoc_forwarder.core import Fatal, Retryable  # noqa: E402
from novrsoc_forwarder.http import HttpError  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from test_forwarder import NOW, T0, FakeIndexer, FakeManager, alert  # noqa: E402

TOKEN = "nsk_" + "b" * 32 + ".backfill-secret-value-xyz"
ORGS = {"nv-alpha-servers": ("11111111-1111-1111-1111-111111111111", "alpha"),
        "nv-beta-servers": ("22222222-2222-2222-2222-222222222222", "beta")}
SOURCES = {"10.20.0.1": ("11111111-1111-1111-1111-111111111111", "alpha")}   # alpha's registered syslog sender


class FakeOwnerApi:
    """The API's ownership semantics: one organization per alert from its groups (two -> ambiguous), agent 000 only
    through a registered source, dedupe per (organization, alert id), receipts per batch_id; classify stores nothing."""

    def __init__(self):
        self.orgs, self.sources = dict(ORGS), dict(SOURCES)
        self.stored, self.receipts, self.ingests, self.classifies = {}, {}, [], 0
        self.lose_answer = 0
        self.fail = []

    def _owner(self, a):
        if a["agent"]["id"] == "000":
            src = self.sources.get(str((a.get("raw") or {}).get("location") or ""))
            return (src, None) if src else (None, "unknown_log_source")
        owners = {self.orgs[g] for g in a["agent"]["groups"] if g in self.orgs}
        if len(owners) == 1:
            return owners.pop(), None
        return None, "ambiguous_organization" if owners else "no_organization_for_groups"

    def request(self, method, url, headers=None, body=None):
        if self.fail:
            f = self.fail.pop(0)
            if f == "net":
                raise HttpError("api could not be reached")
            return f, b"{}"
        if headers.get("Authorization") != f"Bearer {TOKEN}":
            return 401, b"{}"
        if url.endswith("/api/v1/soc/ingest/classify"):
            self.classifies += 1
            items = []
            for a in body["alerts"]:
                owner, reason = self._owner(a)
                if owner is None:
                    items.append({"id": a["id"], "verdict": "quarantine", "reason": reason})
                else:
                    items.append({"id": a["id"], "verdict": "duplicate" if (owner[0], a["id"]) in self.stored else "new",
                                  "org_id": owner[0], "org_slug": owner[1]})
            return 200, json.dumps({"items": items, "classified_at": NOW.isoformat()}).encode()
        assert url.endswith("/api/v1/soc/ingest/alerts")
        self.ingests.append(body)
        bid, ids = body["batch_id"], [a["id"] for a in body["alerts"]]
        if bid in self.receipts:
            r = self.receipts[bid]
            return (409, b"{}") if r["ids"] != ids else (200, json.dumps({**r["ack"], "replayed": True}).encode())
        acc = dup = q = 0
        for a in body["alerts"]:
            owner, _ = self._owner(a)
            if owner is None:
                q += 1
            elif (owner[0], a["id"]) in self.stored:
                dup += 1
            else:
                self.stored[(owner[0], a["id"])] = owner[1]
                acc += 1
        ack = {"batch_id": bid, "accepted": acc, "duplicates": dup, "quarantined": q, "durable": True, "replayed": False}
        self.receipts[bid] = {"ids": ids, "ack": ack}
        if self.lose_answer:
            self.lose_answer -= 1
            raise HttpError("api timed out")
        return 200, json.dumps(ack).encode()


def docs():
    """Seven historical alerts in [T0, T0+7s) and one at the window end (excluded), plus a manager event and an alert
    without an agent id."""
    out = [alert(i, T0 + timedelta(seconds=i), agent=a) for i, a in enumerate(["101", "201", "101", "777", "301", "201"])]
    out.append(alert(6, T0 + timedelta(seconds=6), agent="000", location="10.20.0.1"))
    out.append(alert(7, T0 + timedelta(seconds=7), agent="000", location="10.99.9.9"))     # unregistered sender
    out.append({**alert(8, T0 + timedelta(seconds=8)), "agent": {"name": "no-id"}})        # missing agent identity
    out.append(alert(9, T0 + timedelta(seconds=10), agent="101"))                         # at END: outside the window
    return out


START, END = T0, T0 + timedelta(seconds=10)
GROUPS = {"101": ["nv-alpha-servers"], "201": ["nv-beta-servers"], "777": ["lab-unmapped"],
          "301": ["nv-alpha-servers", "nv-beta-servers"], "000": []}


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        for name, value in (("token", TOKEN), ("idx", "x"), ("mgr", "y")):
            with open(os.path.join(d, name), "w") as f:
                f.write(value)
        self.env = {"NOVRSOC_API_URL": "https://api.test", "WAZUH_INDEXER_URL": "https://idx.test", "WAZUH_API_URL": "https://mgr.test",
                    "NOVRSOC_BACKFILL_TOKEN_FILE": os.path.join(d, "token"), "WAZUH_INDEXER_USER": "ro",
                    "WAZUH_INDEXER_PASSWORD_FILE": os.path.join(d, "idx"), "WAZUH_API_USER": "ro", "WAZUH_API_PASSWORD_FILE": os.path.join(d, "mgr"),
                    "BACKFILL_STATE_DIR": os.path.join(d, "backfill"), "FORWARDER_STATE_DIR": os.path.join(d, "forwarder"),
                    "BACKFILL_PAGE_SIZE": "3", "BACKFILL_SETTLE_SECONDS": "60"}
        self.api, self.indexer, self.manager = FakeOwnerApi(), FakeIndexer(docs()), FakeManager(dict(GROUPS))
        self.out = io.StringIO()
        logs.set_sink(self.out)

    def tearDown(self):
        logs.set_sink(sys.stdout)
        self.tmp.cleanup()

    def make(self, **env) -> bf.Backfill:
        cfg = bf.BackfillConfig({**self.env, **env})
        state = bf.BackfillState(cfg.state_dir, cfg.forwarder_state_dir)
        return bf.Backfill(cfg, api=self.api, indexer=self.indexer, manager=self.manager, state=state, now=lambda: NOW, sleep=lambda s: None)


class TestPlan(Base):
    def test_plan_is_read_only_and_classifies_every_record(self):
        plan, report = self.make().plan(START, END)
        self.assertEqual(self.api.ingests, [])                       # nothing imported
        c = report["counts"]
        self.assertEqual((c["scanned"], c["new"], c["quarantine"], c["invalid"]), (9, 5, 3, 1))
        self.assertEqual(c["eligible"], 5)                           # attributed only; quarantine is not sent by default
        self.assertEqual(report["by_organization"], {"alpha": {"new": 3}, "beta": {"new": 2}})
        self.assertEqual(report["quarantine_by_reason"], {"no_organization_for_groups": 1, "ambiguous_organization": 1,
                                                          "unknown_log_source": 1, "invalid:agent_id_invalid": 1})
        self.assertIn(["10.99.9.9", 1], [list(x) for x in report["unattributed_sources_top"]])
        self.assertEqual(plan["plan_sha256"], bf.plan_hash(plan))
        self.assertNotIn(TOKEN, self.out.getvalue())

    def test_historical_cutoff_excludes_the_window_end(self):
        plan, _ = self.make().plan(START, END)
        ids = set()
        for p in plan["pages"]:
            hits = self.make().search(START, END, p["after"], 3)
            ids |= {h["_source"]["id"] for h in hits}
        self.assertNotIn(docs()[-1]["id"], ids)                      # the alert AT the end belongs to the live forwarder


class TestImport(Base):
    def plan(self, **kw):
        plan, _ = self.make().plan(START, END, **kw)
        return plan

    def test_import_needs_the_explicit_approval_of_exactly_this_plan(self):
        plan = self.plan()
        with self.assertRaises(Fatal):
            self.make().run_import(plan, "0" * 64)
        tampered = {**plan, "limit": 1}
        with self.assertRaises(Fatal):
            self.make().run_import(tampered, plan["plan_sha256"])
        self.assertEqual(self.api.ingests, [])

    def test_only_attributed_alerts_go_to_their_own_organization(self):
        plan = self.plan(orgs=["alpha"])
        counts = self.make().run_import(plan, plan["plan_sha256"])
        self.assertEqual(counts["accepted"], 3)                      # 101 x2 + the registered syslog sender
        self.assertEqual(set(self.api.stored.values()), {"alpha"})
        sent = [a for b in self.api.ingests for a in b["alerts"]]
        self.assertTrue(all(a["agent"]["id"] in ("101", "000") for a in sent))
        self.assertTrue(all(b["batch_id"].startswith("bkf-") for b in self.api.ingests))

    def test_replaying_a_finished_import_or_a_new_one_never_duplicates(self):
        plan = self.plan()
        first = self.make().run_import(plan, plan["plan_sha256"])
        self.assertEqual(first["accepted"], 5)
        again = self.make().run_import(plan, plan["plan_sha256"])     # same state: every page is already done
        self.assertEqual(again["accepted"], 5)
        self.assertEqual(len(self.api.stored), 5)
        fresh = self.make(BACKFILL_STATE_DIR=os.path.join(self.tmp.name, "other"))
        replay = fresh.run_import(plan, plan["plan_sha256"])         # a new state directory: receipts are replayed
        self.assertEqual((replay["accepted"], replay["replayed"]), (0, 5))
        self.assertEqual(len(self.api.stored), 5)

    def test_an_interrupted_batch_resumes_without_a_copy(self):
        plan = self.plan()
        self.api.lose_answer = 1                                     # the API stores the batch, the answer is lost
        b = self.make(BACKFILL_MAX_RETRIES="0")                      # and the run stops there (crash, network loss)
        with self.assertRaises(Retryable):
            b.run_import(plan, plan["plan_sha256"])
        self.assertEqual(b.failed, 1)
        self.assertEqual(b.state.load(), None)                       # the checkpoint did not move
        done = self.make().run_import(plan, plan["plan_sha256"])
        self.assertGreaterEqual(done["replayed"], 1)                 # the interrupted batch's stored receipt
        self.assertEqual(len(self.api.stored), 5)                    # each alert stored once
        self.assertEqual(done["accepted"] + done["replayed"] + done["duplicates"], 5)

    def test_changed_ownership_stops_the_import_before_sending(self):
        plan = self.plan()
        self.manager.groups["201"] = ["nv-alpha-servers"]            # agent moved to another organization since the plan
        self.api.orgs = dict(ORGS)
        with self.assertRaises(bf.Stale):
            self.make().run_import(plan, plan["plan_sha256"])
        self.assertEqual(self.api.ingests, [])
        self.manager.groups["201"] = ["nv-beta-servers"]
        self.api.sources = {}                                        # the syslog registration was removed since the plan
        b = self.make()
        with self.assertRaises(bf.Stale):
            b.run_import(plan, plan["plan_sha256"])
        self.assertEqual(b.state.load()["next_page"], 2)            # pages before the changed one were imported

    def test_a_pilot_imports_exactly_its_limit(self):
        plan = self.plan(limit=3)
        counts = self.make().run_import(plan, plan["plan_sha256"])
        self.assertEqual(counts["eligible"], 3)
        self.assertEqual(len(self.api.stored), 3)

    def test_the_window_must_end_before_the_settle_period(self):
        plan = self.plan()
        with self.assertRaises(Fatal):
            self.make(BACKFILL_SETTLE_SECONDS="86400").run_import(plan, plan["plan_sha256"])


class TestIsolation(Base):
    def test_never_the_live_forwarder_state(self):
        with self.assertRaises(Fatal):
            self.make(BACKFILL_STATE_DIR=self.env["FORWARDER_STATE_DIR"])
        os.makedirs(os.path.join(self.tmp.name, "looks-live"))
        with open(os.path.join(self.tmp.name, "looks-live", "cursor.json"), "w") as f:
            f.write("{}")
        with self.assertRaises(Fatal):
            self.make(BACKFILL_STATE_DIR=os.path.join(self.tmp.name, "looks-live"))

    def test_another_plans_progress_is_never_reused(self):
        plan_a = TestImport.plan(self)
        b = self.make()
        b.state.save({"plan_sha256": "f" * 64, "next_page": 1, "counts": {}})
        with self.assertRaises(Fatal):
            b.run_import(plan_a, plan_a["plan_sha256"])

    def test_cli_refuses_an_overlapping_or_existing_plan(self):
        target = os.path.join(self.tmp.name, "plan.json")
        argv = ["plan", "--start", START.isoformat(), "--end", END.isoformat(), "--plan", target, "--live-start", (END - timedelta(seconds=1)).isoformat()]
        self.assertEqual(bf.main(argv, env=self.env), bf.EXIT_FATAL)    # end after the live forwarder's start
        self.assertFalse(os.path.exists(target))


if __name__ == "__main__":
    unittest.main()
