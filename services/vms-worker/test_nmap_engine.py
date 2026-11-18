"""nmap_service engine tests. No network and no nmap binary: the runner and the resolver are injected, and every test
asserts on the exact argument list nmap WOULD receive (or that it is never called).
    python -m unittest test_nmap_engine"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import v2_adapter  # noqa: E402


def nmap_xml(addr, ports, status="up"):
    body = "".join(f'<port protocol="tcp" portid="{p}"><state state="{st}" reason="syn-ack"/>'
                   f'<service name="{name}" product="{prod}" version="{ver}"/></port>' for p, st, name, prod, ver in ports)
    return (f'<?xml version="1.0"?><nmaprun scanner="nmap"><host><status state="{status}" reason="user-set"/>'
            f'<address addr="{addr}" addrtype="ipv4"/><ports>{body}<extraports state="closed" count="997"/></ports></host>'
            f'<runstats><finished exit="success"/></runstats></nmaprun>')


class Recorder:
    def __init__(self, outputs):
        self.outputs, self.calls = outputs, []

    def __call__(self, args):
        self.calls.append(args)
        out = self.outputs[args[-1]]
        if isinstance(out, Exception):
            raise out
        return out


class FakeApi:
    def __init__(self, job):
        self.job, self.calls = job, []

    def call(self, path, body=None):
        self.calls.append((path, body))
        if path == "/claim":
            return 200, {"job": self.job, "reason": "job" if self.job else "no_job"}
        return 200, {}


def job(targets, **kw):
    return {"job_id": "j-1", "activity": "ports", "targets": [{"kind": k, "value": v} for k, v in targets], "max_rate_pps": 40,
            "protected_networks": [], **kw}


class NmapEngineTests(unittest.TestCase):
    def cfg(self, outputs, allowed="10.20.0.0/24", resolver=None, **kw):
        self.rec = Recorder(outputs)
        return v2_adapter.NmapConfig(allowed, runner=self.rec, resolver=resolver or (lambda n: []), **kw)

    def test_open_services_become_observations_and_the_policy_rate_is_never_exceeded(self):
        cfg = self.cfg({"10.20.0.5": nmap_xml("10.20.0.5", [(22, "open", "ssh", "OpenSSH", "8.9p1"), (80, "closed", "http", "", "")])},
                       max_rate=100)
        obs, outcome, _ = v2_adapter.nmap_service(job([("ip", "10.20.0.5")]), cfg)
        self.assertEqual(outcome, {"10.20.0.5": "completed"})
        svc = [o for o in obs if o["kind"] == "service"]
        self.assertEqual([(o["port"], o["title"], o["check_id"]) for o in svc], [(22, "OpenSSH 8.9p1", "ssh")])
        args = self.rec.calls[0]
        self.assertEqual(args[args.index("--max-rate") + 1], "40")         # min(policy 40, worker 100)
        for flag in ("-sT", "-sV", "-Pn", "-n", "--"):
            self.assertIn(flag, args)
        self.assertNotIn("-sS", args)                                       # never raw packets
        self.assertFalse(any(a.startswith("--script") or a == "-sC" for a in args))   # never scripts
        self.assertEqual(args[-1], "10.20.0.5")

    def test_targets_outside_the_declared_networks_or_inside_protected_ones_are_never_probed(self):
        cfg = self.cfg({})
        obs, outcome, why = v2_adapter.nmap_service(job([("ip", "10.99.0.1"), ("ip", "10.20.0.9")],
                                                        protected_networks=["10.20.0.8/29"]), cfg)
        self.assertEqual(outcome, {"10.99.0.1": "no_route", "10.20.0.9": "refused_out_of_scope"})
        self.assertEqual(self.rec.calls, [])
        self.assertEqual(obs, [])
        self.assertIn("VMS_ALLOWED_NETWORKS", why["10.99.0.1"])

    def test_a_name_is_scanned_at_the_checked_address_and_refused_if_any_address_is_outside(self):
        resolved = {"app.corp.example": ["10.20.0.7"], "split.corp.example": ["10.20.0.8", "198.18.0.1"]}
        cfg = self.cfg({"10.20.0.7": nmap_xml("10.20.0.7", [(443, "open", "https", "nginx", "1.24.0")])}, resolver=resolved.__getitem__)
        obs, outcome, _ = v2_adapter.nmap_service(job([("domain", "app.corp.example"), ("domain", "split.corp.example")]), cfg)
        self.assertEqual(outcome, {"app.corp.example": "completed", "split.corp.example": "no_route"})
        self.assertEqual([c[-1] for c in self.rec.calls], ["10.20.0.7"])    # pinned address, never the name
        self.assertTrue(all(o["target"]["value"] == "app.corp.example" for o in obs))

    def test_a_silent_host_is_unreachable_and_a_tool_failure_fails_only_its_target(self):
        cfg = self.cfg({"10.20.0.2": nmap_xml("10.20.0.2", [], status="down"), "10.20.0.3": RuntimeError("nmap exited 1: boom")})
        _, outcome, why = v2_adapter.nmap_service(job([("ip", "10.20.0.2"), ("ip", "10.20.0.3")]), cfg)
        self.assertEqual(outcome, {"10.20.0.2": "unreachable", "10.20.0.3": "failed"})
        self.assertIn("boom", why["10.20.0.3"])

    def test_run_once_reports_per_target_outcomes_and_refuses_other_activities(self):
        cfg = self.cfg({"10.20.0.5": nmap_xml("10.20.0.5", [(22, "open", "ssh", "OpenSSH", "9.6")])})
        api = FakeApi(job([("ip", "10.20.0.5"), ("ip", "10.50.0.1")]))
        self.assertEqual(v2_adapter.run_once(api, "nmap_service", None, nmap=cfg), "completed")
        paths = [c[0] for c in api.calls]
        self.assertEqual(paths, ["/heartbeat", "/claim", "/jobs/j-1/results", "/jobs/j-1/finish"])
        self.assertEqual(api.calls[2][1]["per_target_outcome"], {"10.20.0.5": "completed", "10.50.0.1": "no_route"})
        self.assertIn("declared networks: 10.20.0.0/24", api.calls[0][1]["dependencies"][0]["detail"])
        other = FakeApi(job([("ip", "10.20.0.5")], activity="vuln_nuclei"))
        self.assertEqual(v2_adapter.run_once(other, "nmap_service", None, nmap=cfg), "refused")
        self.assertEqual(other.calls[-1][1]["outcome"], "failed")
        self.assertEqual(len(self.rec.calls), 1)

    def test_the_worker_declaration_is_required_and_bounded(self):
        for bad in ("", "0.0.0.0/0", "10.0.0.0/7"):
            with self.assertRaises(SystemExit):
                v2_adapter.NmapConfig(bad)
        with self.assertRaises(SystemExit):
            v2_adapter.NmapConfig("10.0.0.0/24", max_rate=5000)
        with self.assertRaises(SystemExit):
            v2_adapter.NmapConfig("10.0.0.0/24", ports="1-65535; rm -rf /")
        self.assertEqual(v2_adapter.NmapConfig("10.0.0.0/24", ports="22,80,8000-8100").args("10.0.0.1", 10)[-6:-4], ["-p", "22,80,8000-8100"])


if __name__ == "__main__":
    unittest.main()
