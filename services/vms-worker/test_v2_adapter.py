"""V2 adapter tests: local test targets only; no network beyond a loopback socket opened here.
    python -m unittest test_v2_adapter"""
import os
import socket
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v2_adapter  # noqa: E402

REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "greenbone-report.xml")


class FakeApi:
    def __init__(self, job=None):
        self.job, self.calls = job, []

    def call(self, path, body=None):
        self.calls.append((path, body))
        if path == "/claim":
            return 200, {"job": self.job, "reason": "job" if self.job else "no_job"}
        return 200, {}


class AdapterTests(unittest.TestCase):
    def test_local_test_target_rule(self):
        for ok in ("127.0.0.1", "::1", "localhost", "app.alpha.test", "svc.localhost"):
            self.assertTrue(v2_adapter.is_local_test_target(ok), ok)
        for bad in ("10.0.0.5", "192.0.2.10", "example.com", "alpha.test.example.com"):
            self.assertFalse(v2_adapter.is_local_test_target(bad), bad)

    def test_greenbone_replay_uses_the_tested_parser_and_labels_the_source(self):
        obs = v2_adapter.greenbone_replay(REPORT, "app.alpha.test")
        self.assertEqual(len(obs), 4)                       # same count as test_openvas_report
        self.assertTrue(all(o["target"]["value"] == "app.alpha.test" and o["evidence_ref"].startswith("replayed-report:") for o in obs))
        self.assertTrue(any(o["cves"] for o in obs))

    def test_tcp_connect_finds_a_local_listener_and_ignores_other_targets(self):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        port = srv.getsockname()[1]
        try:
            obs = v2_adapter.tcp_connect(["127.0.0.1", "10.0.0.5"], ports=(port,))
        finally:
            srv.close()
        self.assertEqual([(o["port"], o["target"]["value"]) for o in obs], [(port, "127.0.0.1")])

    def test_run_once_refuses_a_non_test_target_even_if_the_api_hands_one_out(self):
        api = FakeApi({"job_id": "j1", "targets": [{"kind": "ip", "value": "10.0.0.5"}]})
        self.assertEqual(v2_adapter.run_once(api, "tcp_connect", None), "refused")
        self.assertEqual(api.calls[-1][1]["outcome"], "failed")
        self.assertEqual(v2_adapter.run_once(FakeApi(None), "tcp_connect", None), "no_job")

    def test_run_once_completes_a_replay_job(self):
        api = FakeApi({"job_id": "j2", "targets": [{"kind": "domain", "value": "app.alpha.test"}]})
        self.assertEqual(v2_adapter.run_once(api, "greenbone_report", REPORT), "completed")
        paths = [c[0] for c in api.calls]
        self.assertEqual(paths, ["/heartbeat", "/claim", "/jobs/j2/results", "/jobs/j2/finish"])
        self.assertEqual(len(api.calls[2][1]["observations"]), 4)


if __name__ == "__main__":
    unittest.main()
