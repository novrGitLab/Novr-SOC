"""Cases correlate SIEM alerts with VMS findings through the canonical asset inventory: the case's alerts name their asset,
the asset's OPEN findings are joined (closed ones are not), nothing crosses organizations, and VMS data is shown only to
callers allowed to read it. NHAI's case and alert evidence carry the same combined view."""
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import text

from app.main import create_app
from app.modules.soc import get_case_correlation
from tests.modules.conftest import Client


def _asset(c, org, name):
    return c.execute(text("""INSERT INTO novrsoc.assets (org_id, kind, display_name, criticality, exposure)
                             VALUES (:o, 'host', :n, 'high', 'internal') RETURNING id"""), {"o": org, "n": name}).scalar()


def _finding(c, org, asset, title, status="open", risk=70):
    return c.execute(text("""INSERT INTO novrsoc.vms_findings (org_id, dedupe_key, host, port, protocol, title, severity, cves, priority,
                                                              risk_score, source, asset_id, status)
                             VALUES (:o, :k, 'h', 445, 'tcp', :t, 'high', ARRAY['CVE-2017-0144'], 'P2', :r, 'vuln_openvas', :a, :s)
                             RETURNING id"""), {"o": org, "k": uuid.uuid4().hex, "t": title, "r": risk, "a": asset, "s": status}).scalar()


def _alert(c, org, asset):
    return c.execute(text("""INSERT INTO novrsoc.alerts (org_id, source, external_id, rule_id, rule_level, rule_description, severity,
                                                        agent_id, agent_name, agent_groups, observed_at, raw, asset_id)
                             VALUES (:o, 'wazuh', :x, '60106', 10, 'Windows logon failure burst', 'high', '001', 'corr-host', '{}',
                                     :t, '{}'::jsonb, :a) RETURNING id"""),
                     {"o": org, "x": uuid.uuid4().hex, "t": datetime.now(timezone.utc), "a": asset}).scalar()


@pytest.fixture(scope="module")
def corr(owner, world):
    with owner.begin() as c:
        asset = _asset(c, world.alpha, "corr-fileserver-01")
        open_f = _finding(c, world.alpha, asset, "SMBv1 remote code execution", risk=90)
        _finding(c, world.alpha, asset, "Old TLS cipher (fixed)", status="verified")
        _finding(c, world.alpha, asset, "Accepted legacy service", status="risk_accepted")
        beta_asset = _asset(c, world.beta, "corr-beta-01")
        _finding(c, world.beta, beta_asset, "Beta-only finding")
        a1, a2, loose = _alert(c, world.alpha, asset), _alert(c, world.alpha, asset), _alert(c, world.alpha, None)
        case = c.execute(text("""INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id)
                                 VALUES (:o, 'Correlated case', 'high', 'manual', :s) RETURNING id"""),
                         {"o": world.alpha, "s": uuid.uuid4().hex}).scalar()
        for a in (a1, a2, loose):
            c.execute(text("INSERT INTO novrsoc.case_alerts (case_id, alert_id, org_id) VALUES (:c, :a, :o)"),
                      {"c": case, "a": a, "o": world.alpha})
    return {"case": case, "asset": asset, "open": open_f, "alerts": {a1, a2}, "first_alert": a1}


def test_case_joins_open_findings_of_its_assets(fixture_app, corr):
    r = Client(fixture_app, "analyst_a").get(f"/api/v1/soc/cases/{corr['case']}/correlation")
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["findings_visible"] is True and d["alerts_without_asset"] == 1
    assert len(d["assets"]) == 1
    a = d["assets"][0]
    assert a["asset_id"] == str(corr["asset"]) and {uuid.UUID(x) for x in a["alert_ids"]} == corr["alerts"]
    # verified and risk-accepted findings are not "open"; only the SMBv1 one is joined
    assert [f["title"] for f in a["open_findings"]] == ["SMBv1 remote code execution"] and a["open_findings_total"] == 1


def test_correlation_stays_in_the_organization(fixture_app, corr):
    assert Client(fixture_app, "analyst_b").get(f"/api/v1/soc/cases/{corr['case']}/correlation").status_code == 404
    assert Client(fixture_app, "portal_a").get(f"/api/v1/soc/cases/{corr['case']}/correlation").status_code == 403


def test_findings_are_withheld_without_vms_read(app_engine, world, corr):
    class NoVms:
        def has(self, permission):
            return permission != "vms:read"
    with app_engine.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        d = get_case_correlation(corr["case"], p=NoVms(), conn=c)
    assert d.findings_visible is False and d.assets and all(a.open_findings == [] and a.open_findings_total == 0 for a in d.assets)


@pytest.fixture(scope="module")
def nhai_app(fixture_settings):
    return create_app(fixture_settings.model_copy(update={"nhai_backend": "test_adapter"}))


def test_nhai_case_and_alert_evidence_include_the_assets_findings(nhai_app, owner, corr):
    a = Client(nhai_app, "analyst_a")
    jc = a.post("/api/v1/nhai/case-assistance", {"case_id": str(corr["case"])})
    ja = a.post("/api/v1/nhai/alert-explanations", {"alert_id": str(corr["first_alert"])})
    assert jc.status_code in (200, 202) and ja.status_code in (200, 202), (jc.text, ja.text)
    with owner.begin() as c:
        bc = c.execute(text("SELECT bundle FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": jc.json()["id"]}).scalar()
        ba = c.execute(text("SELECT bundle FROM novrsoc.nhai_jobs WHERE id = :i"), {"i": ja.json()["id"]}).scalar()
    for b in (bc, ba):
        vms = [e["excerpt"] for e in b["evidence"] if e["ref"]["type"] == "vms_findings"]
        assert vms and "SMBv1 remote code execution" in vms[0], b["evidence"]
        assert "Old TLS cipher" not in " ".join(vms) and "Beta-only" not in " ".join(e["excerpt"] for e in b["evidence"])
