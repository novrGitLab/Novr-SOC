"""NovrSOC V2 adapter for the VMS worker. Production location: Server 2, as the compose service `vms-worker` (profile
`vms`), on an internal network that reaches only the API. Development: any local host.

Speaks the V2 worker protocol (/api/v1/vms/worker/, contracts in novrsoc_contracts.v1.vms): heartbeat, claim, results, finish, with an
organization-bound `nsk_` vms_worker credential read from a file (or one file per organization from a directory).
Engines:
  disabled          (production default) heartbeat only: no job is ever claimed, nothing is touched.
Two development engines are restricted to LOCAL TEST TARGETS (loopback addresses, *.test and *.localhost names),
checked again here before anything is touched:
  tcp_connect       a real TCP connect check of a fixed port list on loopback targets (no payloads, no exploits);
  greenbone_report  replays a Greenbone GMP report FILE through the worker's tested parser (worker.openvas_results),
                    attributing its results to the claimed target. Nothing is scanned; the report is labelled as such.
One production engine (needs the API in authorized_scopes mode, the organization's enabled scan policy, and nmap on
this host - the default image has none):
  nmap_service      `nmap -sT -sV` (TCP connect and service/version detection: no raw packets, no scripts, no exploits)
                    of the `ports` activity, parsed by the worker's tested 1.8.x parsers (worker.parse_nmap_xml /
                    parse_nmap_hosts / classify_nmap). Before anything is sent, each target - and every address a name
                    resolves to - must lie inside VMS_ALLOWED_NETWORKS (the networks THIS worker has a route to: its own
                    declaration, required) and outside the job's protected networks; otherwise it is reported `no_route`
                    or `refused_out_of_scope` and never probed. A name is scanned at the address it resolved to (pinned:
                    no second lookup). The packet rate is the lower of the job's policy ceiling and VMS_NMAP_MAX_RATE.
                    It reports exposed services and versions; it does not claim vulnerabilities.
  greenbone_gmp     a live Greenbone/OpenVAS scan of the `vuln_openvas` activity through gvmd's GMP (gmp.py: standard library,
                    a dedicated Greenbone user, gvmd's Unix socket shared from the isolated Greenbone stack or verified TLS).
                    Targets pass the same checks as nmap_service and are handed over as the addresses checked; the tested
                    worker.GreenboneScan flow refuses an unsafe scan configuration (safe checks off, vhost expansion on),
                    resumes rather than duplicates a task after a crash, bounds the scan time and deletes its task and target;
                    results are attributed only to the submitted addresses (worker.openvas_results). One task at a time per
                    worker, at most VMS_GREENBONE_MAX_TARGETS targets; results are delivered in batches of 1000.

  python v2_adapter.py --once      claim at most one job, run it, finish it
  python v2_adapter.py             loop (heartbeat every 60 s)
Environment: NOVRSOC_API_URL, NOVRSOC_VMS_TOKEN_FILE or NOVRSOC_VMS_TOKEN_DIR (every *.token file in it is one
organization's credential), NOVRSOC_API_CA_CERT (optional), NOVRSOC_API_TRANSPORT (`compose-internal` permits plain
http to a single-label compose service name such as `api`), VMS_ENGINE (default `disabled`), VMS_GREENBONE_REPORT,
VMS_TCP_PORTS (comma list); for nmap_service: VMS_ALLOWED_NETWORKS (comma CIDRs, required), VMS_NMAP_MAX_RATE (packets/s,
default 100), VMS_NMAP_PORTS (top-N as `top-1000`, or an nmap port list; default top-1000), VMS_NMAP_PATH, VMS_NMAP_HOST_TIMEOUT
(default 30m).
"""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone

VERSION = "2.0.0"
DEFAULT_PORTS = (22, 80, 443, 3210, 5432, 8000, 8080, 55432)
ENGINES = ("disabled", "tcp_connect", "greenbone_report", "nmap_service", "greenbone_gmp")
NMAP_ACTIVITIES = ("ports",)


def api_url_allowed(url: str, transport: str | None = None) -> bool:
    """https anywhere; plain http only to a loopback API, or (explicit `compose-internal` transport) to a single-label
    compose service name, which resolves only on the container network and never through public DNS."""
    if url.startswith("https://"):
        return True
    if not url.startswith("http://"):
        return False
    host = (urllib.parse.urlsplit(url).hostname or "").lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        return True
    return transport == "compose-internal" and bool(host) and "." not in host and ":" not in host


def is_local_test_target(value: str) -> bool:
    v = value.strip().lower()
    try:
        ip = ipaddress.ip_address(v)
        return ip.is_loopback
    except ValueError:
        return v == "localhost" or v.endswith(".test") or v.endswith(".localhost")


class Api:
    def __init__(self, url: str, token: str, ca: str | None = None, opener=None, transport: str | None = None):
        if not api_url_allowed(url, transport):
            raise SystemExit("NOVRSOC_API_URL must use https (plain http only for a loopback API, or a compose service "
                             "name with NOVRSOC_API_TRANSPORT=compose-internal)")
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


class NmapConfig:
    """The nmap_service engine's own limits (this host's declaration; the API's policy can only narrow them)."""

    def __init__(self, allowed: str, max_rate: int = 100, ports: str = "top-1000", path: str = "nmap", host_timeout: str = "30m",
                 runner=None, resolver=None):
        self.allowed = [ipaddress.ip_network(n.strip(), strict=False) for n in (allowed or "").split(",") if n.strip()]
        if not self.allowed:
            raise SystemExit("nmap_service needs VMS_ALLOWED_NETWORKS: the networks this worker has a route to (comma CIDRs)")
        if any(n.prefixlen < (8 if n.version == 4 else 32) for n in self.allowed):
            raise SystemExit("VMS_ALLOWED_NETWORKS: a network wider than /8 (IPv6 /32) is not a declaration, it is the Internet")
        if not 1 <= int(max_rate) <= 1000:
            raise SystemExit("VMS_NMAP_MAX_RATE must be 1..1000 packets per second")
        if not (ports.startswith("top-") and ports[4:].isdigit()) and not all(c.isdigit() or c in ",-" for c in ports):
            raise SystemExit("VMS_NMAP_PORTS must be top-N or an nmap port list such as 22,80,443,8000-8100")
        self.max_rate, self.ports, self.path, self.host_timeout = int(max_rate), ports, path, host_timeout
        self.runner = runner or _run_nmap
        self.resolver = resolver or (lambda name: sorted({ai[4][0] for ai in socket.getaddrinfo(name, None, proto=socket.IPPROTO_TCP)}))

    @classmethod
    def from_env(cls, env=os.environ) -> "NmapConfig":
        return cls(env.get("VMS_ALLOWED_NETWORKS", ""), int(env.get("VMS_NMAP_MAX_RATE", "100")), env.get("VMS_NMAP_PORTS", "top-1000"),
                   env.get("VMS_NMAP_PATH", "nmap"), env.get("VMS_NMAP_HOST_TIMEOUT", "30m"))

    def routable(self, address: str) -> bool:
        ip = ipaddress.ip_address(address)
        return any(ip.version == n.version and ip in n for n in self.allowed)

    def args(self, address: str, rate: int) -> list[str]:
        port_args = ["--top-ports", self.ports[4:]] if self.ports.startswith("top-") else ["-p", self.ports]
        return [self.path, "-sT", "-sV", "-Pn", "-T3", "-n", "--max-retries", "2", "--max-rate", str(rate),
                "--host-timeout", self.host_timeout, *port_args, "-oX", "-", "--", address]


def _run_nmap(args: list[str]) -> str:
    exe = shutil.which(args[0])
    if not exe:
        raise RuntimeError(f"{args[0]} is not installed on this worker")
    r = subprocess.run([exe, *args[1:]], capture_output=True, text=True, timeout=4 * 3600, stdin=subprocess.DEVNULL)
    if r.returncode != 0:   # a failed tool fails the target with its reason; it never passes as "found nothing"
        raise RuntimeError(f"nmap exited {r.returncode}: {((r.stderr or '').strip().splitlines() or ['no error output'])[-1][:200]}")
    return r.stdout or ""


def _in_any(address: str, networks: list[str]) -> bool:
    ip = ipaddress.ip_address(address)
    for n in networks:
        try:
            net = ipaddress.ip_network(n, strict=False)
        except ValueError:
            continue
        if ip.version == net.version and ip in net:
            return True
    return False


def nmap_service(job: dict, cfg: NmapConfig) -> tuple[list[dict], dict[str, str], dict[str, str]]:
    """(observations, per-target outcome, per-target reason). Nothing outside the worker's declared networks or inside the
    job's protected networks is ever handed to nmap."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import worker  # noqa: PLC0415  (the tested 1.8.x nmap parsers)
    rate = min(cfg.max_rate, int(job.get("max_rate_pps") or cfg.max_rate))
    protected = list(job.get("protected_networks") or [])
    obs, outcome, why = [], {}, {}
    for t in job["targets"]:
        value, kind = t["value"], t["kind"]
        try:
            addresses = [str(ipaddress.ip_address(value))] if kind == "ip" else cfg.resolver(value)
        except (OSError, ValueError):
            outcome[value], why[value] = "failed", "the name does not resolve from this worker"
            continue
        if not addresses:
            outcome[value], why[value] = "failed", "the name does not resolve from this worker"
            continue
        if any(_in_any(a, protected) for a in addresses):
            outcome[value], why[value] = "refused_out_of_scope", "inside a protected network of the organization's scan policy"
            continue
        if not all(cfg.routable(a) for a in addresses):
            outcome[value], why[value] = "no_route", "outside VMS_ALLOWED_NETWORKS: this worker declares no route to it; not attempted"
            continue
        address = addresses[0]   # pinned: nmap receives the address checked above, never the name
        try:
            xml = cfg.runner(cfg.args(address, rate))
            services = worker.parse_nmap_xml(xml)
            hosts = worker.parse_nmap_hosts(xml)
        except Exception as e:  # noqa: BLE001  (tool failure or unreadable output: this target failed, with the reason)
            outcome[value], why[value] = "failed", str(e)[:200] or type(e).__name__
            continue
        verdict, reason = worker.classify_nmap(address, hosts.get(address) or (next(iter(hosts.values())) if len(hosts) == 1 else None))
        outcome[value] = "completed" if verdict.startswith("reachable") else "unreachable" if verdict == "unreachable" else "failed"
        why[value] = reason
        obs.append({"kind": "host", "target": {"kind": kind, "value": value}, "title": f"{verdict}: {reason}"[:200],
                    "evidence_ref": f"nmap:{address}"})
        for svc in services:
            if svc.get("state") != "open":
                continue
            label = " ".join(x for x in (svc.get("product"), svc.get("version")) if x) or f"Open {svc.get('protocol')} port {svc['port']}"
            obs.append({"kind": "service", "target": {"kind": kind, "value": value}, "port": svc["port"],
                        "protocol": svc.get("protocol") if svc.get("protocol") in ("tcp", "udp") else "tcp",
                        "check_id": (svc.get("service") or "")[:200] or None, "title": label[:200], "evidence_ref": f"nmap:{address}"})
    return obs, outcome, why


GREENBONE_ACTIVITIES = ("vuln_openvas",)


class GreenboneConfig:
    """The greenbone_gmp engine's own limits: the networks the Greenbone scanner has a route to (VMS_ALLOWED_NETWORKS,
    required, the same declaration as nmap_service), the most targets one task may hold, and how the scanner is reached
    (gmp.session_from_env: gvmd's socket shared from the isolated Greenbone stack, or verified TLS)."""

    def __init__(self, allowed: str, max_targets: int = 16, factory=None, resolver=None):
        self.net = NmapConfig(allowed, resolver=resolver)   # same declaration rules (required, nothing wider than /8)
        if not 1 <= int(max_targets) <= 256:
            raise SystemExit("VMS_GREENBONE_MAX_TARGETS must be 1..256")
        self.max_targets = int(max_targets)
        if factory is None:
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import gmp  # noqa: PLC0415
            factory = gmp.session_from_env
        self.factory = factory

    @classmethod
    def from_env(cls, env=os.environ) -> "GreenboneConfig":
        return cls(env.get("VMS_ALLOWED_NETWORKS", ""), int(env.get("VMS_GREENBONE_MAX_TARGETS", "16")))


def greenbone_gmp(job: dict, cfg: GreenboneConfig, cancel=None) -> tuple[list[dict], dict[str, str], dict[str, str]]:
    """(observations, per-target outcome, per-target reason). Targets are checked exactly as for nmap_service (inside the
    declared networks, outside the job's protected networks) and handed to Greenbone as the ADDRESSES checked (pinned).
    Results are attributed only to those addresses (worker.openvas_results' attribution contract); anything OpenVAS
    discovers by itself is dropped. The scan configuration must be safe (safe checks on, vhost expansion off) or the job
    is refused before a task exists (worker.GreenboneScan.prepare)."""
    import threading
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import worker  # noqa: PLC0415  (the tested Greenbone flow and report parser)
    protected = list(job.get("protected_networks") or [])
    outcome, why, pinned = {}, {}, {}
    for t in job["targets"]:
        value, kind = t["value"], t["kind"]
        try:
            addresses = [str(ipaddress.ip_address(value))] if kind == "ip" else cfg.net.resolver(value)
        except (OSError, ValueError):
            outcome[value], why[value] = "failed", "the name does not resolve from this worker"
            continue
        if not addresses:
            outcome[value], why[value] = "failed", "the name does not resolve from this worker"
        elif any(_in_any(a, protected) for a in addresses):
            outcome[value], why[value] = "refused_out_of_scope", "inside a protected network of the organization's scan policy"
        elif not all(cfg.net.routable(a) for a in addresses):
            outcome[value], why[value] = "no_route", "outside VMS_ALLOWED_NETWORKS: the scanner declares no route to it; not attempted"
        else:
            pinned[addresses[0]] = (value, kind)
    if len(pinned) > cfg.max_targets:
        for a in list(pinned)[cfg.max_targets:]:
            v, _ = pinned.pop(a)
            outcome[v], why[v] = "failed", f"more than {cfg.max_targets} targets in one Greenbone task (VMS_GREENBONE_MAX_TARGETS); not attempted"
    if not pinned:
        return [], outcome, why
    sub = worker.OpenvasSubmission()
    sub.ips.update(pinned)
    scan = worker.GreenboneScan(str(job["job_id"]), sub, cancel or threading.Event(), factory=cfg.factory)
    try:
        scan.prepare()
        scan.wait()
        xml = scan.report()
    except worker.GreenboneError as e:
        for v, _ in pinned.values():
            outcome[v], why[v] = "failed", str(e)[:200]
        return [], outcome, why
    finally:
        scan.cleanup()
    findings, _ = worker.openvas_results(xml, attribute=lambda ip, name: (ip or "") if (ip or "") in pinned else None)
    obs = []
    for f_ in findings:
        if f_.get("host") not in pinned:   # attribution guarantees this; checked again, never guessed
            continue
        value, kind = pinned[f_["host"]]
        obs.append({"kind": "finding", "target": {"kind": kind, "value": value}, "port": f_.get("port"),
                    "protocol": f_.get("protocol") or "tcp", "check_id": f_.get("rule_id"), "title": (f_.get("title") or "")[:200],
                    "severity": f_.get("severity"), "cvss_v3": f_.get("cvss"),
                    "cves": [c for c in (f_.get("cve_ids") or []) if c.startswith("CVE-")][:50],
                    "evidence_ref": f"greenbone:{scan.report_id or 'report'}"})
    for v, _ in pinned.values():
        outcome[v], why[v] = "completed", f"Greenbone task {scan.name}: {scan.safety}"[:200]
    return obs, outcome, why


def _run_greenbone_job(api: Api, job: dict, cfg: GreenboneConfig | None) -> str:
    jid = job["job_id"]
    if cfg is None:
        api.call(f"/jobs/{jid}/finish", {"outcome": "failed", "detail": "greenbone_gmp is not configured on this worker"})
        return "failed"
    if job.get("activity") not in GREENBONE_ACTIVITIES:
        api.call(f"/jobs/{jid}/finish", {"outcome": "failed", "detail": f"engine greenbone_gmp runs vuln_openvas only, not {job.get('activity')}"})
        return "refused"
    obs, outcome, why = greenbone_gmp(job, cfg)
    for i in range(0, max(1, len(obs)), 1000):   # bounded batches: the API and PostgreSQL ingest a large report in steps
        api.call(f"/jobs/{jid}/results", {"batch_id": f"res-{jid}-{i // 1000}-{uuid.uuid4().hex[:6]}", "job_id": jid,
                                          "observations": obs[i:i + 1000], "per_target_outcome": outcome})
    done = sum(1 for o in outcome.values() if o == "completed")
    summary = ", ".join(f"{n} {k}" for k, n in sorted({o: list(outcome.values()).count(o) for o in set(outcome.values())}.items()))
    failed_all = done == 0 and any(o == "failed" for o in outcome.values())   # nothing scanned and Greenbone failed
    api.call(f"/jobs/{jid}/finish", {"outcome": "failed" if failed_all else "completed",
                                     "detail": (f"greenbone_gmp: {len(obs)} finding(s); {summary or 'no target'}; "
                                                + "; ".join(f"{t}: {r}" for t, r in why.items()))[:500]})
    return "failed" if failed_all else "completed"


def run_once(api: Api, engine: str, report: str | None, ports=DEFAULT_PORTS, nmap: NmapConfig | None = None,
             greenbone: "GreenboneConfig | None" = None) -> str:
    if engine == "disabled":   # heartbeat only: the worker reports that it is present and never claims a job
        api.call("/heartbeat", {"sent_at": datetime.now(timezone.utc).isoformat(), "component_version": VERSION, "state": "ok",
                                "dependencies": [{"name": "engine.disabled", "state": "unconfigured",
                                                  "detail": "scanning disabled on this worker; no job is claimed"}]})
        return "disabled"
    detail = (f"declared networks: {', '.join(str(n) for n in nmap.allowed)}; max {nmap.max_rate} pps" if engine == "nmap_service" and nmap
              else f"Greenbone GMP; declared networks: {', '.join(str(n) for n in greenbone.net.allowed)}; max {greenbone.max_targets} targets per task"
              if engine == "greenbone_gmp" and greenbone else "local test targets only")
    api.call("/heartbeat", {"sent_at": datetime.now(timezone.utc).isoformat(), "component_version": VERSION, "state": "ok",
                            "dependencies": [{"name": f"engine.{engine}", "state": "ok", "detail": detail[:300]}]})
    status, claim = api.call("/claim")
    if status != 200 or not claim.get("job"):
        return claim.get("reason", f"claim_http_{status}")
    job = claim["job"]
    targets = [t["value"] for t in job["targets"]]
    if engine == "nmap_service":
        return _run_nmap_job(api, job, nmap)
    if engine == "greenbone_gmp":
        return _run_greenbone_job(api, job, greenbone)
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


def _run_nmap_job(api: Api, job: dict, cfg: NmapConfig | None) -> str:
    jid = job["job_id"]
    if cfg is None:
        api.call(f"/jobs/{jid}/finish", {"outcome": "failed", "detail": "nmap_service is not configured on this worker"})
        return "failed"
    if job.get("activity") not in NMAP_ACTIVITIES:
        api.call(f"/jobs/{jid}/finish", {"outcome": "failed", "detail": f"engine nmap_service runs the ports activity only, not {job.get('activity')}"})
        return "refused"
    obs, outcome, why = nmap_service(job, cfg)
    api.call(f"/jobs/{jid}/results", {"batch_id": f"res-{jid}-{uuid.uuid4().hex[:8]}", "job_id": jid, "observations": obs[:5000],
                                      "per_target_outcome": outcome})
    done = sum(1 for o in outcome.values() if o == "completed")
    summary = ", ".join(f"{n} {k}" for k, n in sorted({o: list(outcome.values()).count(o) for o in set(outcome.values())}.items()))
    failed_all = done == 0 and all(o == "failed" for o in outcome.values())
    api.call(f"/jobs/{jid}/finish", {"outcome": "failed" if failed_all else "completed",
                                     "detail": (f"nmap_service: {summary or 'no target'}; " + "; ".join(f"{t}: {r}" for t, r in why.items()))[:500]})
    return "failed" if failed_all else "completed"


def token_files(env=os.environ) -> list[str]:
    """One credential per organization: every *.token file in NOVRSOC_VMS_TOKEN_DIR, or the single NOVRSOC_VMS_TOKEN_FILE."""
    d = env.get("NOVRSOC_VMS_TOKEN_DIR")
    if d:
        files = sorted(os.path.join(d, n) for n in os.listdir(d) if n.endswith(".token"))
        if not files:
            raise SystemExit("NOVRSOC_VMS_TOKEN_DIR has no *.token file: issue a vms_worker identity per organization")
        return files
    if env.get("NOVRSOC_VMS_TOKEN_FILE"):
        return [env["NOVRSOC_VMS_TOKEN_FILE"]]
    raise SystemExit("set NOVRSOC_VMS_TOKEN_DIR or NOVRSOC_VMS_TOKEN_FILE")


def greenbone_check(factory=None) -> dict:
    """Read-only verification of the Greenbone connection (deployment step; nothing is created or scanned): the socket
    or TLS session, the dedicated user's authentication, gvmd's version, the feeds' age, and whether the scan
    configuration NovrVMS will use is safe (safe checks on, vhost expansion confirmed off)."""
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    import worker  # noqa: PLC0415
    if factory is None:
        import gmp  # noqa: PLC0415
        factory = gmp.session_from_env
    out: dict = {"ok": False}
    try:
        with factory() as g:
            g.authenticate(worker.GVM_USER, worker.GVM_PASSWORD)
            out["authenticated"] = True
            out["gvmd_version"] = g.get_version().findtext("version")
            out["feeds"] = worker.gvm_feed_rows(g.get_feeds())
            safe, why = worker.gvm_config_safety(g.get_scan_config(worker.GVM_CONFIG_ID), worker.read_openvas_conf())
            out["scan_config_safe"], out["scan_config_detail"] = safe, why
        out["ok"] = bool(out["scan_config_safe"])
    except Exception as e:  # noqa: BLE001  (every failure is reported with its plain reason, never a credential)
        out["error"] = str(worker.gvm_problem(e))
    return out


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if "--greenbone-check" in argv:
        r = greenbone_check()
        print(json.dumps(r, default=str, indent=2))
        return 0 if r["ok"] else 1
    engine = os.environ.get("VMS_ENGINE", "disabled")
    if engine not in ENGINES:
        raise SystemExit(f"VMS_ENGINE must be one of {', '.join(ENGINES)}")
    apis = []
    for path in token_files():
        with open(path, encoding="utf-8") as f:
            apis.append(Api(os.environ["NOVRSOC_API_URL"], f.read().strip(), os.environ.get("NOVRSOC_API_CA_CERT"),
                            transport=os.environ.get("NOVRSOC_API_TRANSPORT")))
    report = os.environ.get("VMS_GREENBONE_REPORT")
    ports = tuple(int(p) for p in os.environ.get("VMS_TCP_PORTS", "").split(",") if p.strip()) or DEFAULT_PORTS
    nmap = NmapConfig.from_env() if engine == "nmap_service" else None
    greenbone = GreenboneConfig.from_env() if engine == "greenbone_gmp" else None
    if "--once" in argv:
        for api in apis:
            print(json.dumps({"event": "run_once", "result": run_once(api, engine, report, ports, nmap, greenbone)}), flush=True)
        return 0
    while True:
        for api in apis:   # each organization's credential is used only for its own heartbeat, claims and results
            print(json.dumps({"event": "cycle", "result": run_once(api, engine, report, ports, nmap, greenbone)}), flush=True)
        time.sleep(60)


if __name__ == "__main__":
    raise SystemExit(main())
