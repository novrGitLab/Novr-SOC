"""NHAI inside VMS and the asset inventory: finding explanations and asset summaries go through the SAME worker, gateway
and deterministic validator as alert explanations; bundles stay in one organization; nothing executes."""
import uuid

import pytest
from sqlalchemy import text

from app.connectors.inference import TestInferenceAdapter
from app.main import create_app
from tests.modules.conftest import Client
from tests.modules.nhai.test_nhai import drain


@pytest.fixture(scope="module")
def nhai_app(fixture_settings):
    return create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))


@pytest.fixture(scope="module")
def alpha_finding(owner, world):
    """One VMS finding of alpha, linked to an asset (inserted directly: this test is about NHAI, not ingest)."""
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        asset = c.execute(text("""INSERT INTO novrsoc.assets (org_id, kind, display_name, criticality, exposure)
                                  VALUES (:o, 'host', 'nhai-app-01', 'high', 'internet_facing') RETURNING id"""), {"o": world.alpha}).scalar()
        c.execute(text("""INSERT INTO novrsoc.asset_identifiers (org_id, asset_id, kind, value, sources)
                          VALUES (:o, :a, 'hostname', :h, ARRAY['manual'])"""), {"o": world.alpha, "a": asset, "h": f"nhai-{uuid.uuid4().hex[:6]}"})
        fid = c.execute(text("""INSERT INTO novrsoc.vms_findings (org_id, dedupe_key, host, port, protocol, title, severity, cvss, cves, priority,
                                                                  risk_score, source, asset_id)
                                VALUES (:o, :k, 'nhai-app-01', 443, 'tcp', 'OpenSSL heap overflow', 'high', 8.1, ARRAY['CVE-2022-3602'], 'P2', 81,
                                        'vuln_openvas', :a) RETURNING id"""), {"o": world.alpha, "k": uuid.uuid4().hex, "a": asset}).scalar()
        c.execute(text("""INSERT INTO novrsoc.ti_cve_records (org_id, cve_id, cvss_v3, kev, description, source)
                          VALUES (:o, 'CVE-2022-3602', 7.5, false, 'X.509 email address buffer overflow', 'test-file')"""), {"o": world.alpha})
    return fid, asset


def test_finding_explanation_and_asset_summary_are_validated_drafts(nhai_app, alpha_finding, fixture_settings, app_engine, owner, world):
    fid, asset = alpha_finding
    a = Client(nhai_app, "analyst_a")
    j1 = a.post("/api/v1/nhai/finding-explanations", {"finding_id": str(fid)})
    assert j1.status_code == 202 and j1.json()["task"] == "finding_explanation" and j1.json()["subject"]["type"] == "vms_finding"
    j2 = a.post("/api/v1/nhai/asset-summaries", {"asset_id": str(asset)})
    assert j2.status_code == 202 and j2.json()["task"] == "asset_summary"
    with owner.begin() as c:
        b1 = c.execute(text("SELECT bundle FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": j1.json()["id"]}).scalar()
    kinds = [e["ref"]["type"] for e in b1["evidence"]]
    assert kinds[0] == "vms_finding" and "cve_intel" in kinds and "asset" in kinds and b1["org_id"] == str(world.alpha)
    assert drain(app_engine, fixture_settings, TestInferenceAdapter()).count("succeeded") >= 2
    r1 = a.get(f"/api/v1/nhai/jobs/{j1.json()['id']}").json()["result"]
    assert r1["status"] == "draft" and r1["confidence"] == "low" and all(rec["requires_human_approval"] for rec in r1["recommendations"])
    assert any("Exploitability" in g for g in r1["missing_evidence"])
    r2 = a.get(f"/api/v1/nhai/jobs/{j2.json()['id']}").json()["result"]
    assert r2["severity_assessment"] is None and r2["citations"][0]["citation_id"] == "E1"   # no authoritative severity for an asset
    detail = a.get(f"/api/v1/assets/{asset}").json()
    assert detail["nhai_jobs"] and detail["nhai_jobs"][0]["task"] == "asset_summary"


def test_bundles_never_cross_organizations(nhai_app, alpha_finding):
    fid, asset = alpha_finding
    b = Client(nhai_app, "analyst_b")
    assert b.post("/api/v1/nhai/finding-explanations", {"finding_id": str(fid)}).status_code == 404
    assert b.post("/api/v1/nhai/asset-summaries", {"asset_id": str(asset)}).status_code == 404
    assert Client(nhai_app, "exec_a").post("/api/v1/nhai/asset-summaries", {"asset_id": str(asset)}).status_code == 403


def test_unconfigured_backend_refuses(app, alpha_finding):
    r = Client(app, "analyst_a").post("/api/v1/nhai/finding-explanations", {"finding_id": str(alpha_finding[0])})
    assert r.status_code == 503 and r.json()["error"]["code"] == "integration_unconfigured"
