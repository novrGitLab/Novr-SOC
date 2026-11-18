"""The greenbone_gmp engine (v2_adapter) and the standard-library GMP client (gmp.py). No Greenbone, no network: the
engine runs against test_greenbone's fake gvmd; the client speaks real GMP framing over a local socket pair.
    python -m unittest test_greenbone_gmp"""
import os
import socket
import sys
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import gmp  # noqa: E402
import v2_adapter  # noqa: E402
import worker  # noqa: E402
from test_greenbone import FakeGmp, World, config_xml, report_xml, result  # noqa: E402


class FakeApi:
    def __init__(self, job):
        self.job, self.calls = job, []

    def call(self, path, body=None):
        self.calls.append((path, body))
        if path == "/claim":
            return 200, {"job": self.job, "reason": "job"}
        return 200, {}

    def finish(self):
        return next(b for p, b in self.calls if p.endswith("/finish"))

    def observations(self):
        return [o for p, b in self.calls if p.endswith("/results") for o in b["observations"]]


JOB = {"job_id": "8d6f0c1e-1111-4222-8333-444455556666", "activity": "vuln_openvas", "max_rate_pps": 50,
       "targets": [{"kind": "ip", "value": "203.0.113.20"}, {"kind": "ip", "value": "10.9.9.9"},
                   {"kind": "ip", "value": "203.0.113.99"}, {"kind": "domain", "value": "app.example.test"}],
       "protected_networks": ["203.0.113.99/32"]}


class Engine(unittest.TestCase):
    def setUp(self):
        self.saved = {k: getattr(worker, k) for k in ("GVM_USER", "GVM_PASSWORD", "GVM_RETRY_DELAYS", "GVM_POLL_SECONDS", "GVM_SCAN_TIMEOUT")}
        worker.GVM_USER, worker.GVM_PASSWORD = "novrsoc", "not-a-real-password"
        worker.GVM_RETRY_DELAYS, worker.GVM_POLL_SECONDS, worker.GVM_SCAN_TIMEOUT = (0, 0, 0), 0, 3600
        self.w = World()
        self.w.report = report_xml(
            result("203.0.113.20", "443/tcp", "High", "8.1", "1.3.6.1.4.1.25623.1.0.100", "OpenSSL overflow", cves=("CVE-2022-3602",))
            + result("203.0.113.21", "443/tcp", "High", "8.1", "1.3.6.1.4.1.25623.1.0.101", "Discovered by OpenVAS itself")
            + result("203.0.113.30", "22/tcp", "Medium", "5.0", "1.3.6.1.4.1.25623.1.0.102", "Weak SSH"))
        self.cfg = v2_adapter.GreenboneConfig("203.0.113.0/24", max_targets=16, factory=lambda: FakeGmp(self.w),
                                              resolver=lambda name: {"app.example.test": ["203.0.113.30"]}.get(name, []))

    def tearDown(self):
        for k, v in self.saved.items():
            setattr(worker, k, v)

    def test_scans_only_checked_addresses_attributes_results_and_cleans_up(self):
        api = FakeApi(JOB)
        self.assertEqual(v2_adapter.run_once(api, "greenbone_gmp", None, greenbone=self.cfg), "completed")
        created = [c for c in self.w.calls if c[0] == "create_target"]
        self.assertEqual(len(created), 1)
        self.assertEqual(sorted(created[0][2]), ["203.0.113.20", "203.0.113.30"])     # pinned addresses, never the name
        obs = api.observations()
        self.assertEqual({o["target"]["value"] for o in obs}, {"203.0.113.20", "app.example.test"})   # .21 was not submitted
        ssl_ = next(o for o in obs if o["target"]["value"] == "203.0.113.20")
        self.assertEqual(ssl_["cves"], ["CVE-2022-3602"])
        self.assertEqual(next(o for o in obs if o["target"]["value"] == "app.example.test")["target"]["kind"], "domain")
        outcome = next(b for p, b in api.calls if p.endswith("/results"))["per_target_outcome"]
        self.assertEqual(outcome["10.9.9.9"], "no_route")
        self.assertEqual(outcome["203.0.113.99"], "refused_out_of_scope")
        self.assertEqual(outcome["203.0.113.20"], "completed")
        self.assertEqual(self.w.tasks, {})                                              # task and target deleted
        self.assertEqual(self.w.targets, {})
        self.assertEqual(api.finish()["outcome"], "completed")
        self.assertNotIn("not-a-real-password", repr(api.calls))

    def test_an_unsafe_scan_configuration_is_refused_before_any_task_exists(self):
        self.w.config = config_xml(expand="yes")
        api = FakeApi(JOB)
        self.assertEqual(v2_adapter.run_once(api, "greenbone_gmp", None, greenbone=self.cfg), "failed")
        self.assertFalse([c for c in self.w.calls if c[0] in ("create_target", "create_task")])
        self.assertIn("vhost expansion", api.finish()["detail"])

    def test_only_the_vuln_openvas_activity_and_a_target_cap(self):
        api = FakeApi({**JOB, "activity": "ports"})
        self.assertEqual(v2_adapter.run_once(api, "greenbone_gmp", None, greenbone=self.cfg), "refused")
        small = v2_adapter.GreenboneConfig("203.0.113.0/24", max_targets=1, factory=lambda: FakeGmp(self.w),
                                           resolver=lambda name: ["203.0.113.30"])
        obs, outcome, why = v2_adapter.greenbone_gmp(JOB, small)
        self.assertEqual(sum(1 for o in outcome.values() if o == "completed"), 1)
        self.assertTrue(any("VMS_GREENBONE_MAX_TARGETS" in r for r in why.values()))
        with self.assertRaises(SystemExit):
            v2_adapter.GreenboneConfig("", factory=lambda: None)                        # a declaration is required


class Check(Engine):
    def test_greenbone_check_is_read_only_and_reports_safety(self):
        r = v2_adapter.greenbone_check(factory=lambda: FakeGmp(self.w))
        self.assertTrue(r["ok"] and r["authenticated"] and r["scan_config_safe"])
        self.assertEqual(r["gvmd_version"], "22.7")
        self.assertFalse([c for c in self.w.calls if c[0] in ("create_target", "create_task", "start_task")])
        self.w.config = config_xml(safe="no")
        self.assertFalse(v2_adapter.greenbone_check(factory=lambda: FakeGmp(self.w))["ok"])
        self.w.auth_error = gmp.GvmResponseError("Authentication failed", "400")
        bad = v2_adapter.greenbone_check(factory=lambda: FakeGmp(self.w))
        self.assertIn("rejected GVM_USER / GVM_PASSWORD", bad["error"])
        self.assertNotIn("not-a-real-password", repr(bad))

class Wire(unittest.TestCase):
    """gmp.GmpClient over a real socket pair: framing, authentication, statuses, limits."""

    def serve(self, answers):
        a, b = socket.socketpair()
        got = []

        def run():
            try:
                for ans in answers:
                    got.append(b.recv(65536).decode())
                    for i in range(0, len(ans), 7):      # answer in small pieces: the client must reassemble them
                        b.sendall(ans[i:i + 7].encode())
            except OSError:
                pass                                     # the client hung up (the size-limit test): expected
            finally:
                b.close()
        threading.Thread(target=run, daemon=True).start()
        return gmp.GmpClient(socket_path="unused", connect=lambda: a), got

    def test_authenticates_and_reads_chunked_answers(self):
        c, got = self.serve(['<authenticate_response status="200" status_text="OK"><role>User</role></authenticate_response>',
                             '<create_target_response status="201" id="t-1"/>',
                             '<start_task_response status="202"><report_id>r-9</report_id></start_task_response>'])
        with c as g:
            g.authenticate("novrsoc", "p&ss<word>")
            self.assertEqual(g.create_target("novrsoc-j", ["203.0.113.20"], "pl-1").get("id"), "t-1")
            self.assertEqual(g.start_task("task-1").findtext("report_id"), "r-9")
        self.assertIn("<password>p&amp;ss&lt;word&gt;</password>", got[0])               # escaped, never raw XML
        self.assertIn("<hosts>203.0.113.20</hosts>", got[1])

    def test_statuses_map_to_the_workers_plain_reasons(self):
        c, _ = self.serve(['<authenticate_response status="400" status_text="Authentication failed"/>'])
        with c as g:
            with self.assertRaises(gmp.GvmResponseError) as e:
                g.authenticate("novrsoc", "wrong")
        self.assertIn("rejected GVM_USER / GVM_PASSWORD", str(worker.gvm_problem(e.exception)))
        c, _ = self.serve(['<get_tasks_response status="503" status_text="Service temporarily down"/>'])
        with c as g:
            with self.assertRaises(gmp.GvmServerError) as e:
                g.get_tasks()
        self.assertTrue(worker.gvm_problem(e.exception).retryable)

    def test_tls_needs_a_ca_and_answers_are_bounded(self):
        with self.assertRaises(gmp.GvmError):
            gmp.GmpClient(host="gvmd.example.test", port=9390)
        saved = gmp.MAX_RESPONSE
        gmp.MAX_RESPONSE = 64
        try:
            c, _ = self.serve(['<get_reports_response status="200">' + "x" * 200 + "</get_reports_response>"])
            with c as g:
                with self.assertRaises(gmp.GvmError):
                    g.get_report("r-1")
        finally:
            gmp.MAX_RESPONSE = saved


if __name__ == "__main__":
    unittest.main()
