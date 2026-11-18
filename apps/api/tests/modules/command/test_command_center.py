"""Command Center: platform-wide views read each organization under ITS OWN row-level security, label every record with
its owner, copy nothing, and are open only to platform staff (administrators: every organization; platform SOC staff:
their assigned organizations). Every view and export is audited; the caller's own context is restored afterwards."""
import csv
import io
import uuid

import pytest
from sqlalchemy import text

from app.modules.command import _cell
from tests.conftest import audit_actions


@pytest.fixture(scope="module")
def data(fixture_alerts, owner, world):
    with owner.connect() as c:
        truth = {str(r.id): r.org_id for r in c.execute(text("SELECT id, org_id FROM novrsoc.alerts"))}
        n = c.execute(text("SELECT count(*) FROM novrsoc.alerts")).scalar()
    assert {world.alpha, world.beta} <= set(truth.values())
    return truth, n


def test_platform_administrators_see_every_organization_with_owner_labels(as_user, world, data, owner):
    truth, before = data
    admin = as_user("admin")
    scope = admin.get("/api/v1/command/scope").json()
    assert scope["scope"] == "platform" and scope["can_export"] is True
    assert {world.platform, world.alpha, world.beta, world.gamma} <= {uuid.UUID(o["id"]) for o in scope["organizations"]}
    assert {"alerts", "vulnerabilities", "cases", "intel", "nhai", "soar_runs", "soar_approvals", "reports", "assets", "scans"} <= set(scope["views"])
    r = admin.get("/api/v1/command/views/alerts?limit=500")
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    owners = {uuid.UUID(i["org"]["id"]) for i in items}
    assert {world.alpha, world.beta} <= owners
    for i in items:                                                   # every label is the real owner
        assert truth[i["id"]] == uuid.UUID(i["org"]["id"])
    beta_only = admin.get(f"/api/v1/command/views/alerts?org={world.beta}&limit=500").json()["items"]
    assert beta_only and {i["org"]["slug"] for i in beta_only} == {"t-beta"}
    crit = admin.get("/api/v1/command/views/alerts?sort=severity&limit=500").json()["items"]
    ranks = [{"critical": 0, "high": 1, "medium": 2, "low": 3}.get(i["severity"], 4) for i in crit]
    assert ranks == sorted(ranks)
    ov = admin.get("/api/v1/command/overview").json()
    rows = {o["org"]["slug"]: o for o in ov["organizations"]}
    with owner.connect() as c:
        alpha_alerts_24h = c.execute(text("SELECT count(*) FROM novrsoc.alerts WHERE org_id = :o AND observed_at > now() - interval '24 hours'"),
                                     {"o": world.alpha}).scalar()
    assert rows["t-alpha"]["alerts_24h"] == alpha_alerts_24h and ov["totals"]["organizations"] == len(rows)
    assert rows["t-alpha"]["posture"] in ("critical", "elevated", "normal", "no_data")
    with owner.connect() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.alerts")).scalar() == before         # nothing copied, nothing written
    acts = [e for e in audit_actions(owner, action="COMMAND_CENTER_VIEW") if e["actor_label"] == "admin@test.novrsoc.invalid"]
    assert {e["resource_id"] for e in acts} >= {"alerts", "overview"}
    assert any(e["details"]["filters"].get("org") == [str(world.beta)] for e in acts)


def test_platform_soc_staff_see_only_their_assigned_organizations(as_user, world, data):
    m = as_user("manager")                                            # home: platform; operations: alpha
    scope = m.get("/api/v1/command/scope").json()
    assert scope["scope"] == "assigned"
    assert {uuid.UUID(o["id"]) for o in scope["organizations"]} == {world.platform, world.alpha}
    items = m.get("/api/v1/command/views/alerts?limit=500").json()["items"]
    assert items and {uuid.UUID(i["org"]["id"]) for i in items} <= {world.platform, world.alpha}
    denied = m.get(f"/api/v1/command/views/alerts?org={world.beta}")
    assert denied.status_code == 403 and str(world.beta) in denied.text
    assert m.get(f"/api/v1/command/views/alerts/export?org={world.beta}").status_code == 403
    a = as_user("analyst_assigned")                                   # home: platform; operations: beta; no exports:manage
    assert {uuid.UUID(o["id"]) for o in a.get("/api/v1/command/scope").json()["organizations"]} == {world.platform, world.beta}
    assert a.get("/api/v1/command/views/cases").status_code == 200
    assert a.get("/api/v1/command/views/alerts/export").status_code == 403
    assert a.get("/api/v1/command/views/assets").status_code == 200


@pytest.mark.parametrize("who", ["analyst_a", "manager_b", "exec_a", "exec_reporting", "portal_a"])
def test_client_organization_accounts_are_refused(as_user, who):
    c = as_user(who)
    for path in ("/api/v1/command/scope", "/api/v1/command/overview", "/api/v1/command/views/alerts"):
        assert c.get(path).status_code == 403, (who, path)


def test_each_view_still_needs_its_own_permission(as_user):
    # an analyst has no soar:manage, but SOAR reads use cases:read like the SOAR pages; none has an unknown view
    a = as_user("analyst_assigned")
    assert a.get("/api/v1/command/views/soar_approvals").status_code == 200
    assert a.get("/api/v1/command/views/not_a_view").status_code == 404


def test_the_callers_own_context_is_restored_after_a_cross_organization_read(as_user, world, owner, data):
    m = as_user("manager")
    m.get("/api/v1/command/views/alerts?limit=500")
    own = m.get("/api/v1/soc/alerts?limit=200").json()["items"]       # no X-Org-Id: the manager's home organization
    with owner.connect() as c:
        home = {str(x) for x in c.execute(text("SELECT id FROM novrsoc.alerts WHERE org_id = :o"), {"o": world.platform}).scalars()}
    assert {i["id"] for i in own} <= home


def test_export_is_owner_labelled_audited_and_formula_safe(as_user, owner, world, data):
    admin = as_user("admin")
    r = admin.get(f"/api/v1/command/views/alerts/export?org={world.alpha}&org={world.beta}")
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/csv")
    assert r.headers["cache-control"] == "no-store" and "attachment" in r.headers["content-disposition"]
    rows = list(csv.DictReader(io.StringIO(r.text)))
    assert rows and {x["organization_slug"] for x in rows} <= {"t-alpha", "t-beta"}
    truth, _ = data
    assert all(str(truth[x["id"]]) in (str(world.alpha), str(world.beta)) for x in rows)
    ex = [e for e in audit_actions(owner, action="COMMAND_CENTER_EXPORT") if e["actor_label"] == "admin@test.novrsoc.invalid"]
    assert ex and ex[-1]["resource_id"] == "alerts" and ex[-1]["details"]["rows"] == len(rows)
    assert _cell("=HYPERLINK(\"http://x\")") == "'=HYPERLINK(\"http://x\")" and _cell("-2+3") == "'-2+3" and _cell("ok") == "ok"
    assert _cell(["CVE-2024-1", "CVE-2024-2"]) == "CVE-2024-1, CVE-2024-2"
