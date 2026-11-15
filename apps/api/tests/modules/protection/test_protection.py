"""Email Security and Brand Protection (pilot): safe parsing, honest adapter states, isolation."""
import uuid

import pytest

from app.main import create_app
from app.protection import engine
from tests.helpers.rls import assert_tenant_isolation
from tests.modules.conftest import Client


def dmarc(domain, report_id, policy="quarantine"):
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<feedback>
  <report_metadata><org_name>dmarc-reporter.example</org_name><email>noreply-dmarc@dmarc-reporter.example</email>
    <report_id>{report_id}</report_id><date_range><begin>1762905600</begin><end>1762991999</end></date_range></report_metadata>
  <policy_published><domain>{domain}</domain><adkim>r</adkim><aspf>r</aspf><p>{policy}</p><pct>100</pct></policy_published>
  <record><row><source_ip>198.51.100.10</source_ip><count>120</count>
    <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from></identifiers></record>
  <record><row><source_ip>203.0.113.66</source_ip><count>7</count>
    <policy_evaluated><disposition>quarantine</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>{domain}</header_from></identifiers></record>
</feedback>"""


def test_dmarc_parser_refuses_dtds_and_counts_failures():
    rep = engine.parse_dmarc(dmarc("example.test", "r1"))
    assert (rep["total"], rep["failing"], rep["policy"], rep["reporter"]) == (127, 7, "quarantine", "dmarc-reporter.example")
    evil = '<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]><feedback>&e;</feedback>'
    with pytest.raises(engine.DmarcError, match="DTDs"):
        engine.parse_dmarc(evil + " " * 50)
    with pytest.raises(engine.DmarcError, match="feedback"):
        engine.parse_dmarc("<root>" + "x" * 60 + "</root>")


def test_lookalikes_are_deterministic_and_exclude_the_domain():
    a, b = engine.lookalikes("devalpha.com"), engine.lookalikes("devalpha.com")
    assert a == b and "devalpha.com" not in dict(a)
    assert {t for _, t in a} >= {"omission", "repetition", "transposition", "homoglyph", "tld_swap"}


def test_email_domains_and_dmarc_flow(as_user, world):
    m = as_user("manager_b")
    dom = f"b{uuid.uuid4().hex[:6]}.test"
    assert m.post("/api/v1/protection/email/domains", {"domain": dom}).json()["verification"] == "pending"
    assert m.post("/api/v1/protection/email/domains", {"domain": dom}).status_code == 409
    r = m.post("/api/v1/protection/email/dmarc-reports", {"xml": dmarc(dom, f"rep-{uuid.uuid4().hex}")})
    assert r.status_code == 201 and r.json()["messages_failing"] == 7 and len(r.json()["records"]) == 2
    assert m.post("/api/v1/protection/email/dmarc-reports", {"xml": dmarc("unregistered.test", "x" * 8)}).json()["error"]["code"] == "unknown_domain"
    again = m.post("/api/v1/protection/email/dmarc-reports", {"xml": dmarc(dom, r.json()["report_id"])})
    assert again.status_code == 409
    assert {d["domain"]: d["dmarc_policy"] for d in m.get("/api/v1/protection/email/domains").json()["items"]}[dom] == "quarantine"
    assert all(x["domain"] != dom for x in as_user("analyst_a").get("/api/v1/protection/email/dmarc-reports").json()["items"])


@pytest.fixture(scope="module")
def brand_app(settings):
    return create_app(settings.model_copy(update={"brand_resolver": "test_adapter"}))


def test_brand_monitoring_unconfigured_then_test_adapter(app, brand_app, world):
    m = Client(app, "manager")
    s = m.post("/api/v1/protection/brand/subjects", {"type": "domain", "value": "devalpha.com"}, org=world.alpha)
    sid = s.json()["id"] if s.status_code == 201 else next(x["id"] for x in m.get("/api/v1/protection/brand/subjects", org=world.alpha).json()["items"] if x["value"] == "devalpha.com")
    run = m.post(f"/api/v1/protection/brand/subjects/{sid}/runs", {}, org=world.alpha).json()
    assert run["outcome"] == "source_unconfigured" and run["new_findings"] == 0
    mb = Client(brand_app, "manager")
    run2 = mb.post(f"/api/v1/protection/brand/subjects/{sid}/runs", {}, org=world.alpha).json()
    assert run2["outcome"] == "completed" and run2["new_findings"] == 3
    assert mb.post(f"/api/v1/protection/brand/subjects/{sid}/runs", {}, org=world.alpha).json()["new_findings"] == 0  # deduplicated
    found = mb.get("/api/v1/protection/brand/findings", org=world.alpha).json()["items"]
    values = {f["value"]: f for f in found}
    assert set(values) >= {"devalpha.net", "dev-alpha.com", "devalpah.com"}
    assert values["devalpah.com"]["severity"] == "high" and "not live DNS" in values["devalpah.com"]["evidence"]["adapter"]
    fid = values["devalpha.net"]["id"]
    assert mb.post(f"/api/v1/protection/brand/findings/{fid}/triage", {"status": "actioned", "note": "takedown requested"}, org=world.alpha).json()["status"] == "actioned"
    b = Client(brand_app, "manager_b")
    assert b.post(f"/api/v1/protection/brand/findings/{fid}/triage", {"status": "dismissed"}).status_code == 404
    assert b.post(f"/api/v1/protection/brand/subjects/{sid}/runs", {}).status_code == 404
    assert b.post("/api/v1/protection/brand/subjects", {"type": "executive", "value": "Jane Doe"}).status_code == 422


def test_permissions_and_isolation(as_user, owner, app_engine, world):
    assert as_user("portal_a").get("/api/v1/protection/email/domains").status_code == 403
    assert as_user("exec_a").post("/api/v1/protection/email/domains", {"domain": "exec.test"}).status_code == 403
    assert_tenant_isolation(owner, app_engine, table="novrsoc.email_domains", org_a=world.alpha, org_b=world.beta,
                            make_row=lambda org: {"org_id": org, "domain": f"iso{uuid.uuid4().hex[:6]}.test", "verification_token": "t"},
                            update_set="verification = 'failed'")
