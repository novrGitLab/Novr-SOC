"""VMS end to end on LOCAL TEST TARGETS only: scope -> scan -> worker claim -> results -> dedupe -> priority and
remediation -> report -> verification by scan evidence. The worker side posts the shared fixture produced by the
worker's tested Greenbone parser (packages/contracts/fixtures/vms/openvas-observations.json)."""
import json
import uuid
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app import devseed
from app.main import create_app
from tests.modules.conftest import Client

FIXTURE = json.loads((Path(__file__).resolve().parents[5] / "packages/contracts/fixtures/vms/openvas-observations.json").read_text())


@pytest.fixture(scope="module")
def vms_app(settings):
    return create_app(settings.model_copy(update={"vms_scanning": "local_test_targets"}))


def _obs(target, items):
    return [{"kind": "finding", "target": {"kind": "domain", "value": target}, "port": f["port"], "protocol": f.get("protocol", "tcp"),
             "check_id": f["rule_id"], "title": f["title"][:200], "severity": f["severity"], "cvss_v3": f.get("cvss"),
             "cves": [c for c in f.get("cve_ids", []) if c.startswith("CVE-")]} for f in items]


def _worker(owner, org):
    with owner.begin() as c:
        _, token = devseed.create_service_identity(c, org, "vms_worker", f"local-{uuid.uuid4().hex[:4]}", scopes=["vms:worker"])
    w = TestClient

    class W:
        def __init__(self, app):
            self.c = w(app)

        def post(self, path, body=None):
            return self.c.post(f"/api/v1/vms/worker{path}", json=body or {}, headers={"Authorization": f"Bearer {token}"})
    return W


def test_local_scan_to_findings_remediation_report_and_verification(vms_app, owner, world):
    a = Client(vms_app, "analyst_a")
    m = Client(vms_app, "manager")
    target = f"app-{uuid.uuid4().hex[:4]}.alpha.test"
    assert m.post("/api/v1/vms/scopes", {"entry": {"kind": "domain", "value": "10.0.0.0"}, "allowed_activities": ["vuln_openvas"],
                                         "authorization_reference": "x"}, org=world.alpha).status_code == 422
    assert m.post("/api/v1/vms/scopes", {"entry": {"kind": "ip", "value": "203.0.113.5"}, "allowed_activities": ["vuln_openvas"],
                                         "authorization_reference": "lab test"}, org=world.alpha).json()["error"]["code"] == "scope_not_allowed"
    scope = m.post("/api/v1/vms/scopes", {"entry": {"kind": "domain", "value": "alpha.test"}, "allowed_activities": ["vuln_openvas", "ports"],
                                          "authorization_reference": "LAB-001 local test targets"}, org=world.alpha).json()
    out = a.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope["id"], "activity": "vuln_openvas",
                                       "targets": ["evil.example.com"]})
    assert out.status_code == 422 and out.json()["error"]["code"] == "target_out_of_scope"
    scan = a.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope["id"], "activity": "vuln_openvas",
                                        "targets": [target]}).json()
    assert scan["state"] == "queued"
    W = _worker(owner, world.alpha)(vms_app)
    claim = W.post("/claim").json()
    assert claim["reason"] == "job" and claim["job"]["targets"] == [{"kind": "domain", "value": target, "site_id": None}]
    job = claim["job"]["job_id"]
    obs = _obs(target, FIXTURE) + _obs("intruder.alpha.test", FIXTURE[:1])           # one observation for an unsubmitted host
    batch = {"batch_id": f"res-{uuid.uuid4().hex}", "job_id": job, "observations": obs}
    ack = W.post(f"/jobs/{job}/results", batch).json()
    assert ack["new_findings"] == len(FIXTURE) and ack["refused_out_of_scope"] == 1
    assert W.post(f"/jobs/{job}/results", batch).json()["replayed"] is True        # idempotent per batch
    assert W.post(f"/jobs/{job}/finish", {"outcome": "completed", "detail": "fixture replay"}).json()["state"] == "completed"
    findings = a.get("/api/v1/vms/findings").json()
    mine = [f for f in findings["items"] if f["host"] == target]
    assert len(mine) == len(FIXTURE) and all(f["remediation_due_at"] for f in mine)
    top = max(mine, key=lambda f: f["risk"]["score"])
    assert top["priority"] in ("P1", "P2") and top["risk"]["formula_version"] == "1.0"
    report = a.get("/api/v1/vms/report").json()
    assert report["scanning"] == "enabled" and sum(report["by_priority"].values()) >= len(FIXTURE)
    # Remediate one finding, then a second scan that no longer reports it verifies it; one that does reopens it.
    fid = top["id"]
    for to in ("in_progress", "fixed_pending_verification"):
        assert a.post(f"/api/v1/vms/findings/{fid}/transition", {"finding_id": fid, "to_status": to, "reason": "patching"}).status_code == 200
    assert a.post(f"/api/v1/vms/findings/{fid}/transition", {"finding_id": fid, "to_status": "open", "reason": "reopen it by hand"}).status_code == 409
    scan2 = a.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope["id"], "activity": "vuln_openvas",
                                         "targets": [target]}).json()
    job2 = W.post("/claim").json()["job"]["job_id"]
    assert job2 == scan2["id"]
    rest = [f for f in FIXTURE if f["rule_id"] != top["check_id"]]
    W.post(f"/jobs/{job2}/results", {"batch_id": f"res-{uuid.uuid4().hex}", "job_id": job2, "observations": _obs(target, rest)})
    W.post(f"/jobs/{job2}/finish", {"outcome": "completed"})
    assert next(f for f in a.get("/api/v1/vms/findings").json()["items"] if f["id"] == fid)["status"] == "verified"
    # isolation: beta sees none of alpha's findings, scopes or scans, and beta's worker gets no alpha job
    b = Client(vms_app, "manager_b")
    assert all(f["host"] != target for f in b.get("/api/v1/vms/findings").json()["items"])
    assert b.get("/api/v1/vms/scopes").json()["items"] == [] or all(s["id"] != scope["id"] for s in b.get("/api/v1/vms/scopes").json()["items"])
    a.post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": scope["id"], "activity": "ports", "targets": [target]})
    assert _worker(owner, world.beta)(vms_app).post("/claim").json()["reason"] == "no_job"
    assert W.post(f"/jobs/{job}/results", {"batch_id": f"res-{uuid.uuid4().hex}", "job_id": job, "observations": []}).status_code == 409


def test_disabled_scanning_refuses_scans(app, world, as_user):
    r = as_user("analyst_a", app).post("/api/v1/vms/scans", {"idempotency_key": f"scan-{uuid.uuid4().hex}", "scope_id": str(uuid.uuid4()),
                                                              "activity": "ports", "targets": ["x.test"]})
    assert r.status_code == 409 and r.json()["error"]["code"] == "scanning_disabled"
