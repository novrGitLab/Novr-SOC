"""Production scanning model (NOVRSOC_VMS_SCANNING=authorized_scopes): the organization's scan policy is the standing
authorization (no per-endpoint approval), and every control holds at queue time and again at claim: approved scope,
protected networks, target cap, weekly windows, concurrency, rate ceiling. Imported assets enroll automatically only when
private, fresh, unique, owned and inside an approved scope; public, shared, stale and scan-only addresses never do.
Nothing here touches a network: the worker is the HTTP protocol driven by the test."""
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed
from app.assets import reconcile
from app.main import create_app
from app.vms import policy as vpolicy
from tests.conftest import PASSWORD, audit_actions
from tests.modules.conftest import Client

ALL_WEEK = [{"weekday": d, "start_minute": 0, "end_minute": 1440} for d in range(7)]


@pytest.fixture(scope="module")
def prod_app(settings):
    return create_app(settings.model_copy(update={"vms_scanning": "authorized_scopes"}))


@pytest.fixture
def tenant(owner):
    """A fresh client organization with its own manager and analyst, so counts are exact."""
    tag = uuid.uuid4().hex[:6]
    with owner.begin() as c:
        org = devseed.create_org(c, f"vp-{tag}", f"VMS policy {tag}")
        devseed.create_user(c, f"vpm-{tag}@test.novrsoc.invalid", PASSWORD, "soc_manager", org)
        devseed.create_user(c, f"vpa-{tag}@test.novrsoc.invalid", PASSWORD, "analyst", org)
        _, token = devseed.create_service_identity(c, org, "vms_worker", f"vp-{tag}", scopes=["vms:worker"])
    return {"org": org, "m": f"vpm-{tag}", "a": f"vpa-{tag}", "token": token}


def _w(app, token):
    c = TestClient(app)
    return lambda path, body=None: c.post(f"/api/v1/vms/worker{path}", json=body or {}, headers={"Authorization": f"Bearer {token}"})


def _policy(**kw):
    return {"enabled": True, "auto_enroll": False, "windows": ALL_WEEK, "timezone": "Africa/Lagos", "max_targets_per_scan": 2,
            "max_rate_pps": 50, "max_concurrent_scans": 1, "protected_networks": ["10.40.0.128/25"],
            "authorization_reference": "MSA-2026-014 schedule B", **kw}


def _scan(c, scope, targets, activity="ports"):
    return c.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope, "activity": activity,
                                        "targets": targets})


def test_policy_holds_every_scan_at_queue_and_at_claim(prod_app, tenant, owner, world):
    m, a = Client(prod_app, tenant["m"]), Client(prod_app, tenant["a"])
    claim = _w(prod_app, tenant["token"])
    scope = lambda v: m.post("/api/v1/vms/scopes", {"entry": {"kind": "cidr", "value": v}, "allowed_activities": ["ports"],  # noqa: E731
                                                   "authorization_reference": "MSA-2026-014"})
    assert scope("127.0.0.0/8").json()["error"]["code"] == "scope_not_allowed"          # never loopback in production
    assert scope("10.0.0.0/8").json()["error"]["code"] == "scope_not_allowed"           # ranges are bounded
    assert scope("198.51.100.0/22").json()["error"]["code"] == "scope_not_allowed"      # public ranges even narrower
    sc = scope("10.40.0.0/24")
    assert sc.status_code == 201, sc.text
    sid = sc.json()["id"]
    # no enabled policy: nothing can be queued, and a worker gets nothing
    assert _scan(a, sid, ["10.40.0.10"]).json()["error"]["code"] == "policy_disabled"
    assert claim("/claim").json()["reason"] == "policy_disabled"
    assert m.put("/api/v1/vms/policy", _policy(windows=[])).json()["error"]["code"] == "policy_incomplete"
    assert m.put("/api/v1/vms/policy", _policy(authorization_reference="")).json()["error"]["code"] == "policy_incomplete"
    assert a.put("/api/v1/vms/policy", _policy()).status_code == 403                    # vms:scope only
    pol = m.put("/api/v1/vms/policy", _policy())
    assert pol.status_code == 200, pol.text
    assert pol.json()["configured"] and pol.json()["in_window_now"] and pol.json()["installation_mode"] == "authorized_scopes"
    # queue-time controls
    assert _scan(a, sid, ["10.40.0.130"]).json()["error"]["code"] == "target_protected"
    assert _scan(a, sid, ["10.40.0.10", "10.40.0.11", "10.40.0.12"]).json()["error"]["code"] == "too_many_targets"
    first = _scan(a, sid, ["10.40.0.10", "10.40.0.11"]).json()
    second = _scan(a, sid, ["10.40.0.12"]).json()
    assert first["origin"] == "manual" and first["progress"]["targets_total"] == 2
    # claim: the policy's ceiling and protected networks travel with the job; the concurrency cap holds
    job = claim("/claim").json()
    assert job["reason"] == "job" and job["job"]["job_id"] == first["id"]
    assert job["job"]["max_rate_pps"] == 50 and job["job"]["protected_networks"] == ["10.40.0.128/25"]
    assert claim("/claim").json()["reason"] == "concurrency_limit"
    jid = first["id"]
    claim(f"/jobs/{jid}/results", {"batch_id": f"r-{uuid.uuid4().hex}", "job_id": jid, "observations": [],
                                    "per_target_outcome": {"10.40.0.10": "completed", "10.40.0.11": "no_route"}})
    done = claim(f"/jobs/{jid}/finish", {"outcome": "completed", "detail": "1 scanned, 1 no route"}).json()
    assert done["progress"]["targets_reported"] == 2 and done["progress"]["outcomes"]["10.40.0.11"] == "no_route"
    assert (done["outcome"]["targets_scanned"], done["outcome"]["targets_not_scanned"]) == (1, 1)
    # outside the window: queued work waits
    today = datetime.now(timezone.utc).astimezone(vpolicy.tz("Africa/Lagos")).weekday()
    other = [{"weekday": (today + 3) % 7, "start_minute": 60, "end_minute": 120}]
    assert m.put("/api/v1/vms/policy", _policy(windows=other)).json()["in_window_now"] is False
    assert claim("/claim").json()["reason"] == "outside_scan_window"
    # a protected network added after queueing is enforced at claim: the job fails its re-check, nothing is handed out
    m.put("/api/v1/vms/policy", _policy(protected_networks=["10.40.0.0/28"]))
    assert claim("/claim").json()["reason"] == "no_job"
    assert next(s for s in a.get("/api/v1/vms/scans").json()["items"] if s["id"] == second["id"])["state"] == "failed"
    assert m.put("/api/v1/vms/policy", _policy(enabled=False)).json()["enabled"] is False
    assert claim("/claim").json()["reason"] == "policy_disabled"
    actions = {e["action"] for e in audit_actions(owner, org=tenant["org"])}
    assert {"VMS_POLICY_ENABLED", "VMS_POLICY_UPDATED", "VMS_POLICY_DISABLED", "VMS_SCOPE_APPROVED"} <= actions
    # another organization sees none of it
    b = Client(prod_app, "analyst_b")
    assert all(s["id"] != jid for s in b.get("/api/v1/vms/scans").json()["items"])
    assert b.get("/api/v1/vms/policy").json()["configured"] is False


def test_unreachable_targets_never_verify_a_fix(prod_app, tenant, owner):
    m, a = Client(prod_app, tenant["m"]), Client(prod_app, tenant["a"])
    claim = _w(prod_app, tenant["token"])
    sid = m.post("/api/v1/vms/scopes", {"entry": {"kind": "cidr", "value": "10.41.0.0/24"}, "allowed_activities": ["ports"],
                                        "authorization_reference": "MSA-2026-015"}).json()["id"]
    m.put("/api/v1/vms/policy", _policy(protected_networks=[]))
    host = "10.41.0.7"
    j1 = _scan(a, sid, [host]).json()["id"]
    assert claim("/claim").json()["job"]["job_id"] == j1
    obs = [{"kind": "finding", "target": {"kind": "ip", "value": host}, "port": 22, "protocol": "tcp", "check_id": "ssh-old",
            "title": "Outdated SSH server", "severity": "medium", "cves": []}]
    claim(f"/jobs/{j1}/results", {"batch_id": f"r-{uuid.uuid4().hex}", "job_id": j1, "observations": obs, "per_target_outcome": {host: "completed"}})
    claim(f"/jobs/{j1}/finish", {"outcome": "completed"})
    fid = next(f for f in a.get("/api/v1/vms/findings").json()["items"] if f["host"] == host)["id"]
    for to in ("in_progress", "fixed_pending_verification"):
        assert a.post(f"/api/v1/vms/findings/{fid}/transition", {"finding_id": fid, "to_status": to, "reason": "patched"}).status_code == 200
    j2 = _scan(a, sid, [host]).json()["id"]
    assert claim("/claim").json()["job"]["job_id"] == j2
    claim(f"/jobs/{j2}/results", {"batch_id": f"r-{uuid.uuid4().hex}", "job_id": j2, "observations": [], "per_target_outcome": {host: "unreachable"}})
    assert claim(f"/jobs/{j2}/finish", {"outcome": "completed"}).json()["outcome"]["verified"] == 0
    assert a.get(f"/api/v1/vms/findings/{fid}").json()["finding"]["status"] == "fixed_pending_verification"   # silence is not a fix


def _asset(owner, org, source, ids, ip=None, name=None) -> str:
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :o, true)"), {"o": str(org)})
        return str(reconcile.upsert(c, reconcile.Observation(source=source, kind="host", display_name=name or ids[0][1], identifiers=ids,
                                                             attributes={"primary_ip": ip}), "test").asset_id)


def test_imported_assets_enroll_only_when_private_fresh_unique_owned_and_in_scope(prod_app, tenant, owner, world):
    org, m = tenant["org"], Client(prod_app, tenant["m"])
    sid = m.post("/api/v1/vms/scopes", {"entry": {"kind": "cidr", "value": "10.42.0.0/24"}, "allowed_activities": ["ports"],
                                        "authorization_reference": "MSA-2026-016"}).json()["id"]
    ok = _asset(owner, org, "wazuh", [("wazuh_agent", "1101"), ("ip", "10.42.0.10")], "10.42.0.10", "web01")
    public = _asset(owner, org, "wazuh", [("wazuh_agent", "1102"), ("ip", "203.0.113.9")], "203.0.113.9", "laptop-home")
    cgnat = _asset(owner, org, "wazuh", [("wazuh_agent", "1103"), ("ip", "100.64.1.1")], "100.64.1.1", "lte-router")
    s1 = _asset(owner, org, "wazuh", [("wazuh_agent", "1104"), ("ip", "10.42.0.20")], "10.42.0.20", "dhcp-a")
    s2 = _asset(owner, org, "wazuh", [("wazuh_agent", "1105"), ("ip", "10.42.0.20")], "10.42.0.20", "dhcp-b")
    prot = _asset(owner, org, "wazuh", [("wazuh_agent", "1106"), ("ip", "10.42.0.200")], "10.42.0.200", "ot-plc")
    scan_only = _asset(owner, org, "vms", [("ip", "10.42.0.30")], "10.42.0.30")
    outside = _asset(owner, org, "wazuh", [("wazuh_agent", "1107"), ("ip", "10.99.0.5")], "10.99.0.5", "branch")
    stale = _asset(owner, org, "wazuh", [("wazuh_agent", "1108"), ("ip", "10.42.0.40")], "10.42.0.40", "old-vm")
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.asset_identifiers SET last_seen_at = now() - interval '10 days' WHERE asset_id = :a AND kind = 'ip'"),
                  {"a": stale})
    assert s1 != s2                                                          # same address, different agents: never merged
    m.put("/api/v1/vms/policy", _policy(auto_enroll=False, protected_networks=["10.42.0.128/25"]))
    view = {e["asset_id"]: e for e in m.get("/api/v1/vms/enrollments").json()["items"]}
    assert view[ok]["status"] == "eligible"                                   # in scope, but automatic enrollment is off
    m.put("/api/v1/vms/policy", _policy(auto_enroll=True, protected_networks=["10.42.0.128/25"], max_targets_per_scan=8))
    view = {e["asset_id"]: e for e in m.get("/api/v1/vms/enrollments").json()["items"]}
    expected = {ok: "enrolled", public: "public_address", cgnat: "public_address", s1: "shared_address", s2: "shared_address",
                prot: "excluded_protected", scan_only: "unverified_source", outside: "outside_scope", stale: "stale_address"}
    assert {k: view[k]["status"] for k in expected} == expected
    assert view[ok]["scope_id"] == sid and view[ok]["address"] == "10.42.0.10" and "wazuh" in view[ok]["sources"]
    # enrollment queues ONE scan with exactly the enrolled address, linked to the canonical asset
    ev = m.post("/api/v1/vms/enrollments/evaluate").json()
    assert ev["scans_queued"] == 1 and ev["by_status"]["enrolled"] == 1
    jobs = [j for j in m.get("/api/v1/vms/scans").json()["items"] if j["origin"] == "enrollment"]
    assert len(jobs) == 1 and jobs[0]["targets"] == ["10.42.0.10"] and jobs[0]["asset_ids"] == [ok]
    assert m.post("/api/v1/vms/enrollments/evaluate").json()["scans_queued"] == 0     # never queued twice
    claim = _w(prod_app, tenant["token"])
    jid = claim("/claim").json()["job"]["job_id"]
    assert jid == jobs[0]["id"]
    claim(f"/jobs/{jid}/results", {"batch_id": f"r-{uuid.uuid4().hex}", "job_id": jid, "observations": [
        {"kind": "finding", "target": {"kind": "ip", "value": "10.42.0.10"}, "port": 443, "protocol": "tcp", "check_id": "tls-old",
         "title": "TLS 1.0 enabled", "severity": "medium", "cves": []}], "per_target_outcome": {"10.42.0.10": "completed"}})
    claim(f"/jobs/{jid}/finish", {"outcome": "completed"})
    after = next(e for e in m.get("/api/v1/vms/enrollments").json()["items"] if e["asset_id"] == ok)
    assert after["last_job_id"] == jid and after["last_scanned_at"] and after["open_findings"] == 1
    finding = next(f for f in m.get("/api/v1/vms/findings").json()["items"] if f["host"] == "10.42.0.10")
    assert finding["asset_id"] == ok                                           # the finding sits on the canonical asset
    assert m.post("/api/v1/vms/enrollments/evaluate").json()["scans_queued"] == 0     # not due again yet
    # a finding on a shared address is never attached to either device
    sid2 = _scan(Client(prod_app, tenant["a"]), sid, ["10.42.0.20"]).json()["id"]
    assert claim("/claim").json()["job"]["job_id"] == sid2
    claim(f"/jobs/{sid2}/results", {"batch_id": f"r-{uuid.uuid4().hex}", "job_id": sid2, "observations": [
        {"kind": "finding", "target": {"kind": "ip", "value": "10.42.0.20"}, "port": 21, "protocol": "tcp", "check_id": "ftp-anon",
         "title": "Anonymous FTP", "severity": "high", "cves": []}], "per_target_outcome": {"10.42.0.20": "completed"}})
    claim(f"/jobs/{sid2}/finish", {"outcome": "completed"})
    assert next(f for f in m.get("/api/v1/vms/findings").json()["items"] if f["host"] == "10.42.0.20")["asset_id"] is None
    # manual exclusion sticks through re-evaluation; lifting it restores the computed decision
    assert m.post(f"/api/v1/vms/enrollments/{ok}/exclusion", {"excluded": True, "reason": "fragile legacy server"}).json()["status"] == "manual_exclusion"
    m.post("/api/v1/vms/enrollments/evaluate")
    assert next(e for e in m.get("/api/v1/vms/enrollments").json()["items"] if e["asset_id"] == ok)["status"] == "manual_exclusion"
    assert m.post(f"/api/v1/vms/enrollments/{ok}/exclusion", {"excluded": False, "reason": "owner approved"}).json()["status"] == "enrolled"
    assert {"VMS_ASSET_EXCLUDED", "VMS_ASSET_EXCLUSION_LIFTED", "VMS_ENROLLMENT_EVALUATED"} <= \
        {e["action"] for e in audit_actions(owner, org=org)}
    # tenant isolation: another organization neither sees nor can exclude these assets
    b = Client(prod_app, "manager_b")
    assert all(e["asset_id"] != ok for e in b.get("/api/v1/vms/enrollments").json()["items"])
    assert b.post(f"/api/v1/vms/enrollments/{ok}/exclusion", {"excluded": True, "reason": "cross-tenant attempt"}).status_code == 404


def test_enrollment_decision_is_pure_and_conservative():
    now = datetime.now(timezone.utc)
    pol = {**vpolicy.DEFAULTS, "enabled": True, "auto_enroll": True}

    class A:
        sources = ["wazuh"]
    net = __import__("ipaddress").ip_network("10.0.0.0/24")

    class S:
        id, value = uuid.uuid4(), "10.0.0.0/24"
    scopes = [(net, S)]
    d = lambda addrs, shared=frozenset(), a=A: vpolicy.decide(a, addrs, set(shared), scopes, pol, now, False)[0]  # noqa: E731
    assert d([("10.0.0.5", now)]) == "enrolled"
    assert d([("10.0.0.5", now - timedelta(hours=1)), ("203.0.113.1", now)]) == "public_address"    # the newest address counts
    assert d([("127.0.0.1", now)]) == "outside_scope" and d([("169.254.1.1", now)]) == "outside_scope"
    assert d([("10.0.0.5", now)], shared={"10.0.0.5"}) == "shared_address"
    assert d([]) == "no_address"

    class Scanned:
        sources = ["vms"]
    assert d([("10.0.0.5", now)], a=Scanned) == "unverified_source"
    assert vpolicy.production_scope_problem("domain", "intranet") is not None
    assert vpolicy.production_scope_problem("cidr", "192.168.10.0/24") is None
    assert vpolicy.production_scope_problem("ip", "224.0.0.1") is not None


def test_platform_caps_hold_across_organizations_and_greenbone_runs_one_at_a_time(settings, owner, world):
    """NOVRSOC_VMS_MAX_RUNNING_SCANS and _GREENBONE hold across EVERY organization (a count only, migration 0023), on top
    of each organization's own cap: result ingestion and the single Greenbone stack are protected."""
    with owner.connect() as c:
        base = c.execute(text("SELECT novrsoc.vms_running_scans()")).scalar()
        base_gb = c.execute(text("SELECT novrsoc.vms_running_scans('vuln_openvas')")).scalar()
    app = create_app(settings.model_copy(update={"vms_scanning": "authorized_scopes", "vms_max_running_scans": base + 2,
                                                 "vms_max_running_greenbone": base_gb + 1}))
    tenants = []
    for _ in range(2):
        tag = uuid.uuid4().hex[:6]
        with owner.begin() as c:
            org = devseed.create_org(c, f"vc-{tag}", f"VMS caps {tag}")
            devseed.create_user(c, f"vcm-{tag}@test.novrsoc.invalid", PASSWORD, "soc_manager", org)
            devseed.create_user(c, f"vca-{tag}@test.novrsoc.invalid", PASSWORD, "analyst", org)
            _, token = devseed.create_service_identity(c, org, "vms_worker", f"vc-{tag}", scopes=["vms:worker"])
        m, a = Client(app, f"vcm-{tag}"), Client(app, f"vca-{tag}")
        sid = m.post("/api/v1/vms/scopes", {"entry": {"kind": "cidr", "value": "10.41.0.0/24"}, "allowed_activities": ["ports", "vuln_openvas"],
                                            "authorization_reference": "MSA-2026-020"}).json()["id"]
        assert m.put("/api/v1/vms/policy", _policy(max_concurrent_scans=3, protected_networks=[])).status_code == 200
        tenants.append({"a": a, "sid": sid, "claim": _w(app, token)})
    one, two = tenants
    assert _scan(one["a"], one["sid"], ["10.41.0.10"], activity="vuln_openvas").status_code == 201
    assert _scan(two["a"], two["sid"], ["10.41.0.20"], activity="vuln_openvas").status_code == 201
    assert _scan(two["a"], two["sid"], ["10.41.0.21"], activity="ports").status_code == 201
    first = one["claim"]("/claim").json()
    assert first["reason"] == "job" and first["job"]["activity"] == "vuln_openvas"
    # Greenbone is busy (platform cap 1): the other organization gets its ports job, never a second Greenbone task
    nxt = two["claim"]("/claim").json()
    assert nxt["reason"] == "job" and nxt["job"]["activity"] == "ports"
    # the platform total is reached: nobody gets more, although each organization is under its own cap of 3
    assert two["claim"]("/claim").json()["reason"] == "concurrency_limit"
    assert one["claim"]("/claim").json()["reason"] == "concurrency_limit"
    for t, j in ((one, first), (two, nxt)):
        jid = j["job"]["job_id"]
        t["claim"](f"/jobs/{jid}/finish", {"outcome": "completed", "detail": "test"})
    again = two["claim"]("/claim").json()
    assert again["reason"] == "job" and again["job"]["activity"] == "vuln_openvas"     # the Greenbone slot is free again
    two["claim"](f"/jobs/{again['job']['job_id']}/finish", {"outcome": "completed", "detail": "test"})
