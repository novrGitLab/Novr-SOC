"""NovrSOC V2 adapter for the local VMS worker (runs on the owner's local host, never on Server 1 or Server 2).

Speaks the V2 worker protocol (/api/v1/vms/worker/, contracts in novrsoc_contracts.v1.vms): heartbeat, claim, results, finish, with an
organization-bound `nsk_` vms_worker credential read from a file. Two engines, both restricted to LOCAL TEST TARGETS
(loopback addresses, *.test and *.localhost names), checked again here before anything is touched:
  tcp_connect       a real TCP connect check of a fixed port list on loopback targets (no payloads, no exploits);
  greenbone_report  replays a Greenbone GMP report FILE through the worker's tested parser (worker.openvas_results),
                    attributing its results to the claimed target. Nothing is scanned; the report is labelled as such.
Production scanning (real Greenbone / nmap against client networks) is NOT enabled by this adapter.

  python v2_adapter.py --once      claim at most one job, run it, finish it
  python v2_adapter.py             loop (heartbeat every 60 s)
Environment: NOVRSOC_API_URL, NOVRSOC_VMS_TOKEN_FILE, NOVRSOC_API_CA_CERT (optional), VMS_ENGINE, VMS_GREENBONE_REPORT,
VMS_TCP_PORTS (comma list).
"""
from __future__ import annotations

import ipaddress
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "2.0.0"
DEFAULT_PORTS = (22, 80, 443, 3210, 5432, 8000, 8080, 55432)


def is_local_test_target(value: str) -> bool:
    v = value.strip().lower()
    try:
        ip = ipaddress.ip_address(v)
        return ip.is_loopback
    except ValueError:
        return v == "localhost" or v.endswith(".test") or v.endswith(".localhost")


class Api:
    def __init__(self, url: str, token: str, ca: str | None = None, opener=None):
        if not (url.startswith("https://") or url.startswith("http://127.0.0.1") or url.startswith("http://localhost")):
            raise SystemExit("NOVRSOC_API_URL must use https (plain http only for a loopback API)")
        self.url, self.token = url.rstrip("/"), token
        ctx = ssl.create_default_context(cafile=ca) if ca else ssl.create_default_context()
        self.opener = opener or urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def call(self, path: str, body: dict | None = None) -> tuple[int, dict]:
        req = urllib.request.Request(f"{self.url}/api/v1/vms/worker{path}", method="POST",
                                     data=json.dumps(body or {}).encode(),
                                     headers={"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"})
        try:
            with self.opener.open(req, timeout=30) as r:
                raw = r.read()
                return r.status, json.loads(raw) if raw else {}
        except urllib.error.HTTPError as e:
            return e.code, {}


def tcp_connect(targets: list[str], ports=DEFAULT_PORTS, timeout=0.5) -> list[dict]:
    obs = []
    for t in targets:
        if not is_local_test_target(t):
            continue
        addr = t if t[0].isdigit() or ":" in t else "127.0.0.1" if t == "localhost" else None
        if addr is None:
            continue  # *.test names are not resolved by this engine
        for port in ports:
            try:
                with socket.create_connection((addr, port), timeout=timeout):
                    obs.append({"kind": "service", "target": {"kind": "ip", "value": t}, "port": port, "protocol": "tcp",
                                "title": f"Open TCP port {port}"})
            except OSError:
                continue
    return obs


# The hosts the replayed report was originally run against (the fixture's submitted targets). Only results for these
# are attributed to the claimed local test target; hosts the scanner discovered by itself are dropped, as the parser's
# attribution contract requires.
DEFAULT_REPLAY_SOURCE_HOSTS = ("192.0.2.10", "app.qa-alpha.test", "192.0.2.20")


def greenbone_replay(report_path: str, target: str, source_hosts=DEFAULT_REPLAY_SOURCE_HOSTS) -> list[dict]:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import worker  # noqa: PLC0415  (the tested 1.8.x parser; imported only for this engine)
    hosts = {h.lower() for h in source_hosts}
    with open(report_path, encoding="utf-8") as f:
        findings, _ = worker.openvas_results(
            f.read(), attribute=lambda ip, name: target if ((ip or "").lower() in hosts or (name or "").lower() in hosts) else None)
    out = []
    for f_ in findings:
        out.append({"kind": "finding", "target": {"kind": "ip" if target[0].isdigit() else "domain", "value": target},
                    "port": f_.get("port"), "protocol": f_.get("protocol") or "tcp", "check_id": f_.get("rule_id"),
                    "title": (f_.get("title") or "")[:200], "severity": f_.get("severity"), "cvss_v3": f_.get("cvss"),
                    "cves": [c for c in (f_.get("cve_ids") or []) if c.startswith("CVE-")][:50],
                    "evidence_ref": f"replayed-report:{os.path.basename(report_path)}"})
    return out


def run_once(api: Api, engine: str, report: str | None, ports=DEFAULT_PORTS) -> str:
    api.call("/heartbeat", {"sent_at": datetime.now(timezone.utc).isoformat(), "component_version": VERSION, "state": "ok",
                            "dependencies": [{"name": f"engine.{engine}", "state": "ok", "detail": "local test targets only"}]})
    status, claim = api.call("/claim")
    if status != 200 or not claim.get("job"):
        return claim.get("reason", f"claim_http_{status}")
    job = claim["job"]
    targets = [t["value"] for t in job["targets"]]
    if not all(is_local_test_target(t) for t in targets):  # defence in depth: never touch a non-test target
        api.call(f"/jobs/{job['job_id']}/finish", {"outcome": "failed", "detail": "refused: target is not a local test target"})
        return "refused"
    try:
        src = tuple(h.strip() for h in os.environ.get("VMS_REPLAY_SOURCE_HOSTS", "").split(",") if h.strip()) or DEFAULT_REPLAY_SOURCE_HOSTS
        obs = (greenbone_replay(report, targets[0], src) if engine == "greenbone_report" and report else tcp_connect(targets, ports))
        api.call(f"/jobs/{job['job_id']}/results", {"batch_id": f"res-{job['job_id']}-{uuid.uuid4().hex[:8]}", "job_id": job["job_id"],
                                                    "observations": obs, "per_target_outcome": {t: "completed" for t in targets}})
        api.call(f"/jobs/{job['job_id']}/finish", {"outcome": "completed", "detail": f"{engine}: {len(obs)} observation(s)"})
        return "completed"
    except Exception as e:  # report the failure, never retry blindly
        api.call(f"/jobs/{job['job_id']}/finish", {"outcome": "failed", "detail": f"{type(e).__name__}"[:200]})
        return "failed"


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    with open(os.environ["NOVRSOC_VMS_TOKEN_FILE"], encoding="utf-8") as f:
        token = f.read().strip()
    api = Api(os.environ["NOVRSOC_API_URL"], token, os.environ.get("NOVRSOC_API_CA_CERT"))
    engine = os.environ.get("VMS_ENGINE", "tcp_connect")
    report = os.environ.get("VMS_GREENBONE_REPORT")
    ports = tuple(int(p) for p in os.environ.get("VMS_TCP_PORTS", "").split(",") if p.strip()) or DEFAULT_PORTS
    if "--once" in argv:
        print(json.dumps({"event": "run_once", "result": run_once(api, engine, report, ports)}))
        return 0
    while True:
        print(json.dumps({"event": "cycle", "result": run_once(api, engine, report, ports)}), flush=True)
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
