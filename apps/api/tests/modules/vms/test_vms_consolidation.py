"""VMS consolidation on LOCAL TEST TARGETS: findings and services link to the ONE shared asset inventory, CVE
intelligence marks KEV findings, retests are resolved by scan evidence, schedules create jobs only where scanning is
enabled, remediation tasks are assigned and annotated, risk prioritization and the services inventory read real records."""
import uuid

import pytest
from sqlalchemy import text

from app.main import create_app
from tests.modules.conftest import Client
from tests.modules.vms.test_vms_flow import _worker

CVE = "CVE-2024-3400"


@pytest.fixture(scope="module")
def vms_app(settings):
    return create_app(settings.model_copy(update={"vms_scanning": "local_test_targets"}))


def _scan_and_ingest(vms_app, owner, world, target, observations):
    m, a = Client(vms_app, "manager"), Client(vms_app, "analyst_a")
    scope = m.post("/api/v1/vms/scopes", {"entry": {"kind": "domain", "value": "consol.test"}, "allowed_activities": ["vuln_openvas"],
                                          "authorization_reference": "LAB-002 local test targets"}, org=world.alpha).json()
    scan = a.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope["id"], "activity": "vuln_openvas",
                                        "targets": [target]}).json()
    W = _worker(owner, world.alpha)(vms_app)
    job = W.post("/claim").json()["job"]["job_id"]
    assert job == scan["id"]
    W.post(f"/jobs/{job}/results", {"batch_id": f"res-{uuid.uuid4().hex}", "job_id": job, "observations": observations})
    W.post(f"/jobs/{job}/finish", {"outcome": "completed"})
    return scope, W


def test_findings_and_services_reconcile_into_the_shared_inventory(vms_app, owner, world):
    a = Client(vms_app, "analyst_a")
    target = f"web-{uuid.uuid4().hex[:4]}.consol.test"
    obs = [{"kind": "service", "target": {"kind": "domain", "value": target}, "port": 443, "protocol": "tcp", "check_id": "https",
            "title": "nginx 1.24"},
           {"kind": "finding", "target": {"kind": "domain", "value": target}, "port": 443, "protocol": "tcp", "check_id": "1.3.6.1.4.1.25623.1.0.9",
            "title": "PAN-OS command injection", "severity": "critical", "cvss_v3": 10.0, "cves": [CVE]}]
    _scan_and_ingest(vms_app, owner, world, target, obs)
    finding = next(f for f in a.get("/api/v1/vms/findings").json()["items"] if f["host"] == target)
    assert finding["asset_id"] and finding["asset_name"] == target and finding["kev"] is False
    assets = a.get(f"/api/v1/assets?q={target}").json()["items"]
    assert len(assets) == 1 and assets[0]["id"] == finding["asset_id"] and "vms" in assets[0]["sources"]
    detail = a.get(f"/api/v1/assets/{finding['asset_id']}").json()
    assert any(s["port"] == 443 and s["product"] == "nginx 1.24" for s in detail["services"])
    assert [f["id"] for f in detail["findings"]] == [finding["id"]] and "never merged" in detail["detection_note"]
    assert any(s["asset_name"] == target for s in a.get("/api/v1/vms/services").json()["items"])
    # CVE intelligence (KEV) changes prioritization context, not the scanner's evidence
    assert a.post("/api/v1/insights/cves/import", {"source": "cisa-kev-file",
                                                   "kev_catalog": {"vulnerabilities": [{"cveID": CVE, "dateAdded": "2024-04-12",
                                                                                        "vulnerabilityName": "PAN-OS GlobalProtect"}]}}).json()["imported"] == 1
    d = a.get(f"/api/v1/vms/findings/{finding['id']}").json()
    assert d["finding"]["kev"] is True and d["cve_intel"][0]["kev"] is True and d["cves_without_intel"] == []
    risk = a.get("/api/v1/vms/risk").json()
    assert risk["kev_findings"] >= 1 and any(r["asset_id"] == finding["asset_id"] for r in risk["assets"])


def test_retest_is_resolved_by_scan_evidence_and_blocked_where_scanning_is_off(vms_app, app, owner, world):
    a = Client(vms_app, "analyst_a")
    target = f"db-{uuid.uuid4().hex[:4]}.consol.test"
    obs = [{"kind": "finding", "target": {"kind": "domain", "value": target}, "port": 5432, "protocol": "tcp", "check_id": "pg-weak",
            "title": "Weak database configuration", "severity": "high", "cvss_v3": 7.5, "cves": []}]
    scope, W = _scan_and_ingest(vms_app, owner, world, target, obs)
    fid = next(f for f in a.get("/api/v1/vms/findings").json()["items"] if f["host"] == target)["id"]
    off = Client(app, "analyst_a").post(f"/api/v1/vms/findings/{fid}/retest", {"note": "patched"})
    assert off.status_code == 201 and off.json()["status"] == "blocked_scanning_disabled" and off.json()["scan_job_id"] is None
    for to in ("in_progress", "fixed_pending_verification"):
        a.post(f"/api/v1/vms/findings/{fid}/transition", {"finding_id": fid, "to_status": to, "reason": "patched"})
    rt = a.post(f"/api/v1/vms/findings/{fid}/retest", {"note": "verify the fix"}).json()
    assert rt["status"] == "scan_requested" and rt["scan_job_id"]
    job = W.post("/claim").json()["job"]["job_id"]
    assert job == rt["scan_job_id"]
    W.post(f"/jobs/{job}/results", {"batch_id": f"res-{uuid.uuid4().hex}", "job_id": job, "observations": []})
    W.post(f"/jobs/{job}/finish", {"outcome": "completed"})
    d = a.get(f"/api/v1/vms/findings/{fid}").json()
    assert d["finding"]["status"] == "verified" and d["verifications"][0]["status"] == "verified"
    assert d["remediation"]["status"] == "done" and any(h["action"] == "VMS_RETEST_REQUESTED" for h in d["history"])


def test_schedules_remediation_and_permissions(vms_app, app, owner, world):
    m, a = Client(vms_app, "manager"), Client(vms_app, "analyst_a")
    scope = m.post("/api/v1/vms/scopes", {"entry": {"kind": "domain", "value": "sched.test"}, "allowed_activities": ["ports"],
                                          "authorization_reference": "LAB-003"}, org=world.alpha).json()
    bad = m.post("/api/v1/vms/schedules", {"scope_id": scope["id"], "name": "weekly ports", "activity": "ports",
                                           "targets": ["other.example.com"], "cadence": "weekly"}, org=world.alpha)
    assert bad.status_code == 422 and bad.json()["error"]["code"] == "target_out_of_scope"
    assert a.post("/api/v1/vms/schedules", {"scope_id": scope["id"], "name": "x", "activity": "ports", "targets": ["a.sched.test"],
                                            "cadence": "weekly"}).status_code == 403                          # analysts cannot schedule
    sch = m.post("/api/v1/vms/schedules", {"scope_id": scope["id"], "name": f"weekly-{uuid.uuid4().hex[:4]}", "activity": "ports",
                                           "targets": ["a.sched.test"], "cadence": "weekly", "enabled": True}, org=world.alpha).json()
    assert sch["enabled"] is True and "Creates a scan job" in sch["execution"]
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.vms_scan_schedules SET next_run_at = now() - interval '1 minute' WHERE id = :i"), {"i": sch["id"]})
    W = _worker(owner, world.alpha)(vms_app)
    claim = W.post("/claim").json()                                                    # due schedules materialize at claim
    assert claim["reason"] == "job" and claim["job"]["targets"][0]["value"] == "a.sched.test"
    W.post(f"/jobs/{claim['job']['job_id']}/finish", {"outcome": "completed"})
    assert Client(app, "manager").get("/api/v1/vms/schedules", org=world.alpha).json()["items"][0]["execution"].startswith("Scanning is disabled")
    tasks = a.get("/api/v1/vms/remediation").json()
    task = next(t for t in tasks["items"] if t["status"] in ("open", "in_progress"))
    me = a.get("/api/v1/auth/me").json()["user"]["id"]
    upd = a.patch(f"/api/v1/vms/remediation/{task['id']}", {"assignee_id": me, "note": "Patch window Friday", "status": "in_progress"}).json()
    assert upd["assignee_id"] == me and upd["note"] == "Patch window Friday" and upd["status"] == "in_progress"
    outsider = Client(vms_app, "analyst_b").get("/api/v1/auth/me").json()["user"]["id"]
    assert a.patch(f"/api/v1/vms/remediation/{task['id']}", {"assignee_id": outsider}).status_code == 422   # not a member of alpha
    assert Client(vms_app, "exec_a").patch(f"/api/v1/vms/remediation/{task['id']}", {"note": "x"}).status_code == 403
    assert Client(vms_app, "manager_b").get(f"/api/v1/vms/findings/{task['finding_id']}").status_code == 404
    assert any(e["action"] == "VMS_REMEDIATION_UPDATED" for e in a.get("/api/v1/vms/audit").json()["items"])
