"""Machine identity kinds and scopes are ONE definition (novrsoc_contracts.v1.platform.SERVICE_KIND_SCOPES) shared by the
operator CLI, the admin API, the contracts and the database. Regression: the CLI could not issue the organization-bound
`ti_feeder` credential (intel:ingest) that the admin API, the contracts and the Threat Insights ingest endpoint support,
and it accepted any scope."""
import re
import typing
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from app import cli
from app.modules import admin
from novrsoc_contracts.v1 import platform
from tests.modules.conftest import Client

def _bundle(source: str) -> dict:
    """One synthetic STIX 2.1 indicator with a fresh id (a documentation address): nothing shared with other tests."""
    now = "2026-11-10T08:00:00.000Z"
    indicator = {"type": "indicator", "spec_version": "2.1", "id": f"indicator--{uuid.uuid4()}", "created": now, "modified": now,
                 "name": "identity regression indicator", "pattern": "[ipv4-addr:value = '198.51.100.77']", "pattern_type": "stix",
                 "valid_from": now}
    return {"source": source, "collection": "regression",
            "bundle": {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": [indicator]}}


def test_kinds_and_scopes_agree_across_contracts_api_cli_and_database(owner):
    kinds = set(platform.SERVICE_KIND_SCOPES)
    assert "ti_feeder" in kinds and platform.SERVICE_KIND_SCOPES["ti_feeder"] == {"intel:ingest"}
    assert set(typing.get_args(platform.ServiceKind)) == kinds
    assert set(typing.get_args(platform.ServiceWhoAmI.model_fields["kind"].annotation)) == kinds
    assert set(cli.KINDS) == kinds and admin.KIND_SCOPES is platform.SERVICE_KIND_SCOPES
    with owner.connect() as c:
        definition = c.execute(text("""SELECT pg_get_constraintdef(oid) FROM pg_constraint
                                       WHERE conname = 'service_identities_kind_check'""")).scalar()
    assert set(re.findall(r"'([a-z_]+)'", definition)) == kinds


def test_cli_issues_an_organization_bound_ti_feeder(db, owner, world, fixture_app, monkeypatch, tmp_path, as_user):
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    out = tmp_path / "alpha-feeder.token"
    assert cli.create_service_identity("ti_feeder", "alpha-taxii-cli", "t-alpha", [], out) == 0     # default scope: intel:ingest
    token = out.read_text().strip()
    c = TestClient(fixture_app)
    who = c.get("/api/v1/service/whoami", headers={"Authorization": f"Bearer {token}"})
    assert who.status_code == 200 and who.json()["kind"] == "ti_feeder" and who.json()["scopes"] == ["intel:ingest"]
    assert who.json()["org_id"] == str(world.alpha)
    source = f"cli-feed-{uuid.uuid4().hex[:6]}"
    # The organization comes from the identity: an X-Org-Id header for another organization changes nothing.
    r = c.post("/api/v1/insights/ingest/stix", json=_bundle(source),
               headers={"Authorization": f"Bearer {token}", "X-Org-Id": str(world.beta)})
    assert r.status_code == 200, r.text
    alpha_runs = {x["source"] for x in as_user("analyst_a").get("/api/v1/insights/feed-runs").json()["items"]}
    beta_runs = {x["source"] for x in as_user("analyst_b").get("/api/v1/insights/feed-runs").json()["items"]}
    assert source in alpha_runs and source not in beta_runs                              # cross-tenant: never delivered to beta
    # A feeder is not a forwarder: it cannot deliver alerts for any organization.
    alerts = {"batch_id": f"b-{uuid.uuid4().hex}", "alerts": [{"id": f"x-{uuid.uuid4().hex}", "timestamp": "2026-11-10T08:00:00Z",
              "rule": {"id": "1", "level": 3}, "agent": {"id": "004", "name": "b", "groups": ["nv-beta-servers"]}}]}
    assert c.post("/api/v1/soc/ingest/alerts", json=alerts, headers={"Authorization": f"Bearer {token}"}).status_code == 403
    with owner.connect() as conn:
        row = conn.execute(text("SELECT org_id, kind, scopes FROM novrsoc.service_identities WHERE name = 'alpha-taxii-cli'")).one()
    assert (row.org_id, row.kind, list(row.scopes)) == (world.alpha, "ti_feeder", ["intel:ingest"])


def test_invalid_kinds_scopes_and_organizations_are_refused(db, world, monkeypatch, tmp_path, fixture_app):
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    refused = [("ti_feeder", "t-alpha", ["alerts:ingest"]), ("ti_feeder", "t-alpha", ["intel:ingest", "vms:worker"]),
               ("vms_worker", "t-alpha", ["intel:ingest"]), ("forwarder", "t-beta", []), ("ti_feeder", "no-such-org", []),
               ("feeder", "t-alpha", [])]
    for i, (kind, org, scopes) in enumerate(refused):
        out = tmp_path / f"refused-{i}.token"
        assert cli.create_service_identity(kind, f"refused-{i}", org, scopes, out) == 2, (kind, org, scopes)
        assert not out.exists()                                                           # nothing written when refused
    admin_c = Client(fixture_app, "admin")
    for scopes in (["alerts:ingest"], [], ["intel:ingest", "telemetry:ingest"]):
        r = admin_c.post("/api/v1/admin/service-identities", {"kind": "ti_feeder", "name": f"bad-{uuid.uuid4().hex[:6]}",
                                                              "scopes": scopes, "site_id": None}, org=world.alpha)
        assert r.status_code == 422, (scopes, r.text)
    ok = admin_c.post("/api/v1/admin/service-identities", {"kind": "ti_feeder", "name": f"ok-{uuid.uuid4().hex[:6]}",
                                                           "scopes": ["intel:ingest"], "site_id": None}, org=world.alpha)
    assert ok.status_code == 201 and ok.json()["identity"]["kind"] == "ti_feeder"


def test_a_feeder_of_one_organization_never_reaches_another(owner, world, fixture_app, as_user):
    from app import devseed
    with owner.begin() as c:
        _, beta_token = devseed.create_service_identity(c, world.beta, "ti_feeder", f"beta-{uuid.uuid4().hex[:6]}", scopes=["intel:ingest"])
        _, vms_token = devseed.create_service_identity(c, world.alpha, "vms_worker", f"vms-{uuid.uuid4().hex[:6]}", scopes=["vms:worker"])
    c = TestClient(fixture_app)
    source = f"beta-feed-{uuid.uuid4().hex[:6]}"
    assert c.post("/api/v1/insights/ingest/stix", json=_bundle(source),
                  headers={"Authorization": f"Bearer {beta_token}", "X-Org-Id": str(world.alpha)}).status_code == 200
    assert source not in {x["source"] for x in as_user("analyst_a").get("/api/v1/insights/feed-runs").json()["items"]}
    assert source in {x["source"] for x in as_user("analyst_b").get("/api/v1/insights/feed-runs").json()["items"]}
    assert c.post("/api/v1/insights/ingest/stix", json=_bundle("vms-not-a-feeder"),
                  headers={"Authorization": f"Bearer {vms_token}"}).status_code == 403
