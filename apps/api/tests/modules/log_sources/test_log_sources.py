"""Syslog and agentless sources: events the Wazuh manager receives itself (agent 000) are attributed ONLY through an
explicit, live registration of their sender; unknown, disabled and manager-local events are quarantined; one source can
never be registered to two organizations; reassignment moves only future events; every tenant boundary holds."""
import random
import uuid
from datetime import datetime, timezone

from fastapi.testclient import TestClient
from sqlalchemy import text

from tests.conftest import audit_actions

SRC = "/api/v1/log-sources"


def _ip() -> str:
    return f"10.{random.randint(64, 250)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def _event(location: str, groups=(), agent="000", level=10) -> dict:
    return {"id": f"syslog-{uuid.uuid4().hex}", "timestamp": datetime.now(timezone.utc).isoformat(),
            "rule": {"id": "87701", "level": level, "description": "Firewall: blocked connection"},
            "agent": {"id": agent, "name": "wazuh-manager", "groups": list(groups)},
            "raw": {"location": location, "full_log": "filterlog: block in on igb0"}}


def _ingest(app, token, events) -> dict:
    r = TestClient(app).post("/api/v1/soc/ingest/alerts", json={"batch_id": f"b-{uuid.uuid4().hex}", "alerts": events},
                             headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200, r.text
    return r.json()


def _register(client, org, ip=None, **kw) -> dict:
    body = {"name": kw.pop("name", f"fw-{uuid.uuid4().hex[:8]}"), "kind": "syslog", "source_ip": ip or _ip(), "host": "",
            "device_type": "firewall", "vendor": "OPNsense", "protocol": "udp", "port": 514, "site_id": None, "network": None,
            "authorization_reference": "CHG-1001 log collection", "notes": "", "enabled": True, **kw}
    return client.post(SRC, body, org=org)


def _quarantine_reason(owner, external_id: str) -> str | None:
    with owner.connect() as c:
        return c.execute(text("SELECT reason FROM novrsoc.alert_quarantine WHERE external_id = :x"), {"x": external_id}).scalar()


def test_a_registered_syslog_source_attributes_its_events_to_its_organization_only(fixture_app, as_user, forwarder_token, world, owner):
    mgr, a, b = as_user("manager"), as_user("analyst_a"), as_user("analyst_b")
    r = _register(mgr, world.alpha)
    assert r.status_code == 201, r.text
    src = r.json()
    assert src["status"] == "never_received" and src["match_value"] == src["source_ip"] and src["asset_id"]
    ev = _event(src["source_ip"])
    assert _ingest(fixture_app, forwarder_token, [ev])["accepted"] == 1
    mine = a.get(f"/api/v1/soc/alerts?log_source_id={src['id']}").json()["items"]
    assert [x["external_id"] for x in mine] == [ev["id"]] and mine[0]["log_source_name"] == src["name"]
    assert mine[0]["asset_id"] == src["asset_id"]                                    # the device's asset, not the manager's
    now = a.get(f"{SRC}/{src['id']}").json()
    assert now["event_count"] == 1 and now["status"] == "receiving" and now["last_event_at"]
    # another organization sees nothing of it
    assert b.get(f"/api/v1/soc/alerts/{mine[0]['id']}").status_code == 404
    assert b.get(f"{SRC}/{src['id']}").status_code == 404
    assert not b.get(f"/api/v1/soc/alerts?log_source_id={src['id']}").json()["items"]
    assert b.get(f"/api/v1/assets/{src['asset_id']}").status_code == 404
    assert {"LOG_SOURCE_REGISTERED"} <= {e["action"] for e in audit_actions(owner, org=world.alpha)}


def test_unknown_disabled_and_manager_local_events_are_quarantined_never_assigned(fixture_app, as_user, forwarder_token, world, owner, mapped):
    unknown = _event(_ip())
    local = _event("/var/ossec/logs/active-responses.log")
    grouped = _event(_ip(), groups=["nv-alpha-servers"])           # agent 000's groups are never used, even when mapped
    res = _ingest(fixture_app, forwarder_token, [unknown, local, grouped])
    assert (res["accepted"], res["quarantined"]) == (0, 3)
    assert _quarantine_reason(owner, unknown["id"]) == "unknown_log_source"
    assert _quarantine_reason(owner, local["id"]) == "manager_local_event"
    assert _quarantine_reason(owner, grouped["id"]) == "unknown_log_source"
    mgr = as_user("manager")
    src = _register(mgr, world.alpha).json()
    assert mgr.patch(f"{SRC}/{src['id']}", {"enabled": False}, org=world.alpha).json()["status"] == "disabled"
    off = _event(src["source_ip"])
    assert _ingest(fixture_app, forwarder_token, [off])["quarantined"] == 1
    assert _quarantine_reason(owner, off["id"]) == "log_source_disabled"
    assert mgr.patch(f"{SRC}/{src['id']}", {"enabled": True}, org=world.alpha).json()["status"] == "never_received"
    assert _ingest(fixture_app, forwarder_token, [_event(src["source_ip"])])["accepted"] == 1
    q = as_user("admin").get("/api/v1/admin/wazuh/quarantine").json()
    seen = {(s["kind"], s["value"], s["reason"]) for s in q["unattributed_sources"]}
    assert ("syslog", unknown["raw"]["location"], "unknown_log_source") in seen
    assert ("manager_local", "/var/ossec/logs/active-responses.log", "manager_local_event") in seen
    actions = {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"LOG_SOURCE_DISABLED", "LOG_SOURCE_ENABLED"} <= actions


def test_one_source_one_organization(as_user, world):
    ip = _ip()
    first = _register(as_user("manager"), world.alpha, ip=ip, name="edge-router")
    assert first.status_code == 201
    other_org = _register(as_user("manager_b"), world.beta, ip=ip)
    assert other_org.status_code == 409 and "reassign" in other_org.json()["error"]["message"]
    assert _register(as_user("manager"), world.alpha, ip=_ip(), name="edge-router").status_code == 409   # names unique per org
    agentless = {"kind": "agentless", "source_ip": None, "host": "db01.lab.internal", "protocol": "ssh", "device_type": "linux_server", "port": 22}
    assert _register(as_user("manager"), world.alpha, **agentless).status_code == 201
    assert _register(as_user("manager_b"), world.beta, **{**agentless, "host": "DB01.lab.internal"}).status_code == 409   # case-insensitive


def test_agentless_events_are_attributed_by_their_configured_host(fixture_app, as_user, forwarder_token, world):
    host = f"srv-{uuid.uuid4().hex[:6]}.lab.internal"
    src = _register(as_user("manager_b"), world.beta, kind="agentless", source_ip=None, host=host, protocol="ssh",
                    device_type="linux_server", port=22).json()
    ev = _event(f"(ssh_integrity_check_linux) root@{host}->/etc")
    assert _ingest(fixture_app, forwarder_token, [ev])["accepted"] == 1
    assert [x["external_id"] for x in as_user("analyst_b").get(f"/api/v1/soc/alerts?log_source_id={src['id']}").json()["items"]] == [ev["id"]]


def test_reassignment_moves_future_events_only_and_needs_a_platform_administrator(fixture_app, as_user, forwarder_token, world, owner):
    mgr, admin = as_user("manager"), as_user("admin")
    src = _register(mgr, world.alpha).json()
    before = _event(src["source_ip"])
    assert _ingest(fixture_app, forwarder_token, [before])["accepted"] == 1
    body = {"org_id": str(world.beta), "reason": "Device handed over to Beta"}
    assert mgr.post(f"{SRC}/{src['id']}/reassign", body, org=world.alpha).status_code == 403
    r = admin.post(f"{SRC}/{src['id']}/reassign", body, org=world.alpha)
    assert r.status_code == 201, r.text
    moved = r.json()
    assert moved["org_id"] == str(world.beta) and moved["match_value"] == src["match_value"] and moved["id"] != src["id"]
    old = mgr.get(f"{SRC}/{src['id']}", org=world.alpha).json()
    assert old["status"] == "retired" and "Beta" in old["retired_reason"]
    after = _event(src["source_ip"])
    assert _ingest(fixture_app, forwarder_token, [after])["accepted"] == 1
    a_ids = {x["external_id"] for x in as_user("analyst_a").get("/api/v1/soc/alerts?limit=200").json()["items"]}
    b_ids = {x["external_id"] for x in as_user("analyst_b").get("/api/v1/soc/alerts?limit=200").json()["items"]}
    assert before["id"] in a_ids and before["id"] not in b_ids          # history stays with the organization that had it
    assert after["id"] in b_ids and after["id"] not in a_ids
    assert {"LOG_SOURCE_REASSIGNED_OUT"} <= {e["action"] for e in audit_actions(owner, org=world.alpha)}
    assert {"LOG_SOURCE_REASSIGNED_IN"} <= {e["action"] for e in audit_actions(owner, org=world.beta)}
    assert mgr.patch(f"{SRC}/{src['id']}", {"name": "renamed"}, org=world.alpha).status_code == 409   # retired: history only


def test_downstream_modules_keep_source_events_inside_their_organization(fixture_app, as_user, forwarder_token, world):
    src = _register(as_user("manager"), world.alpha).json()
    ev = _event(src["source_ip"], level=12)
    _ingest(fixture_app, forwarder_token, [ev])
    a, b = as_user("analyst_a"), as_user("analyst_b")
    alert = a.get(f"/api/v1/soc/alerts?log_source_id={src['id']}").json()["items"][0]
    case = a.post("/api/v1/soc/cases", {"alert_ids": [alert["id"]], "title": "Firewall blocks", "severity": "high", "source": "alert",
                                        "source_id": f"src-{alert['id']}"})
    assert case.status_code in (200, 201), case.text
    assert b.get(f"/api/v1/soc/cases/{case.json()['case_id']}").status_code == 404
    assert b.post("/api/v1/soc/cases", {"alert_ids": [alert["id"]], "title": "x", "severity": "high", "source": "alert",
                                        "source_id": f"b-{alert['id']}"}).status_code in (404, 422)
    assert b.post("/api/v1/nhai/alert-explanations", {"alert_id": alert["id"]}).status_code in (404, 409, 503)
    assert b.get(f"/api/v1/soc/alerts/{alert['id']}/evidence").status_code == 404


def test_permissions_and_validation(as_user, world):
    assert _register(as_user("analyst_a"), world.alpha).status_code == 403          # endpoints:manage
    assert _register(as_user("exec_a"), world.alpha).status_code == 403
    assert as_user("analyst_a").get(SRC).status_code == 200                           # endpoints:read
    mgr = as_user("manager")
    assert _register(mgr, world.alpha, source_ip=None).status_code == 422            # syslog needs its sender
    assert _register(mgr, world.alpha, ip="10.9.9.9", network="10.1.0.0/16").status_code == 422
    assert _register(mgr, world.alpha, protocol="ssh").status_code == 422
    beta_site = as_user("manager_b").post("/api/v1/sites", {"name": f"b-{uuid.uuid4().hex[:6]}", "description": "", "network_cidrs": []},
                                          org=world.beta).json()
    assert _register(mgr, world.alpha, site_id=beta_site["id"]).status_code == 422  # another organization's site


def test_broad_wazuh_group_needs_an_acknowledgement_and_groups_stay_unique(as_user, world):
    mgr = as_user("manager")
    r = mgr.post("/api/v1/endpoints/group-mappings", {"group_name": "default", "acknowledge_broad_group": False}, org=world.alpha)
    assert r.status_code == 422 and r.json()["error"]["code"] == "broad_group_requires_acknowledgement"
    ok = mgr.post("/api/v1/endpoints/group-mappings", {"group_name": "default", "acknowledge_broad_group": True}, org=world.alpha)
    try:
        assert ok.status_code == 201 and ok.json()["broad"] is True
        dup = as_user("manager_b").post("/api/v1/endpoints/group-mappings", {"group_name": "default", "acknowledge_broad_group": True},
                                        org=world.beta)
        assert dup.status_code == 409
    finally:
        mgr.delete(f"/api/v1/endpoints/group-mappings/{ok.json()['id']}", org=world.alpha)
