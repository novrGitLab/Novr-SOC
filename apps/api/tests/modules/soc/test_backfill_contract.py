"""The real historical backfill (services/edge/forwarder, novrsoc_forwarder.backfill) against the real classify and
ingest endpoints and database: the dry run stores nothing, ownership is the API's own (agent groups and registered
sources), an import reaches only the planned organization, an alert the live forwarder already delivered is a
duplicate (never a copy), and a mapping change between plan and import stops the import."""
import importlib
import json
import sys
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed

FWD = Path(__file__).resolve().parents[5] / "services" / "edge" / "forwarder"
sys.path.insert(0, str(FWD))
sys.path.insert(0, str(FWD / "tests"))
bf = importlib.import_module("novrsoc_forwarder.backfill")
fake = importlib.import_module("test_forwarder")


class ApiViaTestClient:
    def __init__(self, app, token):
        self.c, self.token = TestClient(app), token

    def request(self, method, url, headers=None, body=None):
        r = self.c.post(url.split("novrsoc-api.test", 1)[1], json=body, headers={"Authorization": f"Bearer {self.token}"})
        return r.status_code, r.content


@pytest.fixture
def env(tmp_path, forwarder_token):
    paths = {}
    for name, value in (("token", forwarder_token), ("idx", "x"), ("mgr", "y")):
        (tmp_path / name).write_text(value)
        paths[name] = str(tmp_path / name)
    return {"NOVRSOC_API_URL": "https://novrsoc-api.test", "WAZUH_INDEXER_URL": "https://idx.test", "WAZUH_API_URL": "https://mgr.test",
            "NOVRSOC_BACKFILL_TOKEN_FILE": paths["token"], "WAZUH_INDEXER_USER": "ro", "WAZUH_INDEXER_PASSWORD_FILE": paths["idx"],
            "WAZUH_API_USER": "ro", "WAZUH_API_PASSWORD_FILE": paths["mgr"], "BACKFILL_STATE_DIR": str(tmp_path / "bkf"),
            "BACKFILL_PAGE_SIZE": "2", "BACKFILL_SETTLE_SECONDS": "0"}


def _backfill(env, app, token, docs, groups, **over):
    cfg = bf.BackfillConfig({**env, **over})
    return bf.Backfill(cfg, api=ApiViaTestClient(app, token), indexer=fake.FakeIndexer(docs), manager=fake.FakeManager(groups),
                       state=bf.BackfillState(cfg.state_dir, None), now=lambda: fake.NOW, sleep=lambda s: None)


def _rows(owner, prefix):
    with owner.begin() as c:
        alerts = c.execute(text("SELECT external_id, org_id FROM novrsoc.alerts WHERE external_id LIKE :p"), {"p": f"{prefix}%"}).all()
        q = c.execute(text("SELECT count(*) FROM novrsoc.alert_quarantine WHERE external_id LIKE :p"), {"p": f"{prefix}%"}).scalar()
    return alerts, q


def test_classify_is_a_forwarder_only_dry_run(fixture_app, forwarder_token, owner, world, mapped):
    c = TestClient(fixture_app)
    a = {"id": f"cls-{uuid.uuid4().hex}", "timestamp": "2026-11-10T08:00:00Z", "rule": {"id": "1", "level": 5},
         "agent": {"id": "004", "name": "b", "groups": ["nv-beta-servers"]}}
    u = {**a, "id": f"cls-{uuid.uuid4().hex}", "agent": {"id": "777", "name": "x", "groups": ["lab-unmapped"]}}
    r = c.post("/api/v1/soc/ingest/classify", json={"alerts": [a, u]}, headers={"Authorization": f"Bearer {forwarder_token}"})
    assert r.status_code == 200, r.text
    items = r.json()["items"]
    assert (items[0]["verdict"], items[0]["org_slug"], items[0]["org_id"]) == ("new", "t-beta", str(world.beta))
    assert (items[1]["verdict"], items[1]["reason"]) == ("quarantine", "no_organization_for_groups")
    assert _rows(owner, "cls-") == ([], 0)                                     # nothing stored, nothing quarantined
    with owner.begin() as conn:
        _, vms = devseed.create_service_identity(conn, world.alpha, "vms_worker", f"v-{uuid.uuid4().hex[:6]}", scopes=["vms:worker"])
        _, feeder = devseed.create_service_identity(conn, world.alpha, "ti_feeder", f"t-{uuid.uuid4().hex[:6]}", scopes=["intel:ingest"])
    for tok in (vms, feeder):
        assert c.post("/api/v1/soc/ingest/classify", json={"alerts": [a]}, headers={"Authorization": f"Bearer {tok}"}).status_code == 403
    assert c.post("/api/v1/soc/ingest/classify", json={"alerts": [a]}).status_code == 401


def test_plan_then_import_reaches_only_the_planned_organization(fixture_app, forwarder_token, owner, world, mapped, env, db, monkeypatch, capsys):
    tag = f"bk{uuid.uuid4().hex[:6]}-"
    sender = f"10.{uuid.uuid4().int % 200 + 30}.0.{uuid.uuid4().int % 250 + 1}"
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        c.execute(text("""INSERT INTO novrsoc.log_sources (org_id, name, kind, source_ip, match_value, device_type, protocol, authorization_reference)
                          VALUES (:o, :n, 'syslog', CAST(:ip AS inet), :mv, 'firewall', 'udp', 'BKF-TEST')"""),
                  {"o": world.alpha, "n": f"fw-{tag}", "ip": sender, "mv": sender})
    docs = [fake.alert(i, fake.T0 + timedelta(seconds=i), agent=a) for i, a in enumerate(["001", "004", "001", "777"])]
    docs.append(fake.alert(4, fake.T0 + timedelta(seconds=4), agent="000", location=sender))
    for d in docs:
        d["id"] = f"{tag}{d['id']}"
    groups = {"001": ["nv-alpha-servers"], "004": ["nv-beta-servers"], "777": ["lab-unmapped"], "000": []}
    # the live forwarder already delivered the first alpha alert
    live = {"batch_id": f"livesim-{uuid.uuid4().hex}", "alerts": [{"id": docs[0]["id"], "timestamp": "2026-11-10T11:00:00+00:00",
            "rule": {"id": "5710", "level": 7}, "agent": {"id": "001", "name": "host-001", "groups": ["nv-alpha-servers"]}}]}
    assert TestClient(fixture_app).post("/api/v1/soc/ingest/alerts", json=live,
                                        headers={"Authorization": f"Bearer {forwarder_token}"}).json()["accepted"] == 1
    start, end = fake.T0, fake.T0 + timedelta(seconds=10)
    plan, report = _backfill(env, fixture_app, forwarder_token, docs, groups).plan(start, end, orgs=["t-alpha"])
    assert report["counts"]["scanned"] == 5 and report["by_organization"]["t-alpha"] == {"duplicate": 1, "new": 2}
    assert report["by_organization"]["t-beta"] == {"new": 1} and report["counts"]["eligible"] == 3
    assert len(_rows(owner, tag)[0]) == 1                                      # planning stored nothing (only the live alert)
    counts = _backfill(env, fixture_app, forwarder_token, docs, groups).run_import(plan, plan["plan_sha256"])
    assert (counts["accepted"], counts["duplicates"]) == (2, 1)
    alerts, quarantined = _rows(owner, tag)
    assert {a.org_id for a in alerts} == {world.alpha} and len(alerts) == 3     # beta's alert was not sent; no copies
    assert quarantined == 0                                                      # unattributable alerts are not sent
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        src = c.execute(text("SELECT event_count FROM novrsoc.log_sources WHERE name = :n"), {"n": f"fw-{tag}"}).scalar()
        bkf = c.execute(text("SELECT count(*) FROM novrsoc.ingest_batches WHERE batch_id LIKE 'bkf-%'")).scalar()
    assert src == 1 and bkf >= 1
    again = _backfill(env, fixture_app, forwarder_token, docs, groups, BACKFILL_STATE_DIR=env["BACKFILL_STATE_DIR"] + "-2").run_import(plan, plan["plan_sha256"])
    assert again["accepted"] == 0 and len(_rows(owner, tag)[0]) == 3            # a second import replays receipts only

    # Rollback from the ledger: only what the import inserted and nobody touched; never the live forwarder's alert.
    from app import cli
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    ledger = Path(env["BACKFILL_STATE_DIR"]) / "backfill-ledger.jsonl"
    with owner.begin() as c:
        c.execute(text("UPDATE novrsoc.alerts SET status = 'acknowledged' WHERE external_id = :x"), {"x": docs[2]["id"]})
    capsys.readouterr()
    assert cli.backfill_rollback(ledger, execute=False) == 0
    dry = json.loads(capsys.readouterr().out.split("dry run")[0])
    assert (dry["inserted_by_the_import"], dry["removable"], dry["kept_worked_on"]) == (2, 1, 1)
    assert len(_rows(owner, tag)[0]) == 3                                       # a dry run removes nothing
    assert cli.backfill_rollback(ledger, execute=True) == 0
    left = {a.external_id for a in _rows(owner, tag)[0]}
    assert left == {docs[0]["id"], docs[2]["id"]}                               # the live alert and the worked-on one stay
    with owner.begin() as c:
        c.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(world.alpha)})
        assert c.execute(text("SELECT event_count FROM novrsoc.log_sources WHERE name = :n"), {"n": f"fw-{tag}"}).scalar() == 0
        assert c.execute(text("SELECT count(*) FROM novrsoc.audit_events WHERE action = 'BACKFILL_ROLLED_BACK'")).scalar() >= 1


def test_a_mapping_change_after_planning_stops_the_import(fixture_app, forwarder_token, owner, world, env):
    tag = f"bs{uuid.uuid4().hex[:6]}-"
    group = f"bkf-{uuid.uuid4().hex[:8]}"
    with owner.begin() as c:
        c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g)"), {"o": world.gamma, "g": group})
    docs = [fake.alert(i, fake.T0 + timedelta(seconds=i), agent="555") for i in range(3)]
    for d in docs:
        d["id"] = f"{tag}{d['id']}"
    groups = {"555": [group]}
    try:
        plan, report = _backfill(env, fixture_app, forwarder_token, docs, groups).plan(fake.T0, fake.T0 + timedelta(seconds=10))
        assert report["by_organization"] == {"t-gamma": {"new": 3}}
        with owner.begin() as c:   # the group is moved to another organization before the import runs
            c.execute(text("UPDATE novrsoc.wazuh_group_mappings SET org_id = :o WHERE group_name = :g"), {"o": world.beta, "g": group})
        with pytest.raises(bf.Stale):
            _backfill(env, fixture_app, forwarder_token, docs, groups).run_import(plan, plan["plan_sha256"])
        assert _rows(owner, tag) == ([], 0)                                       # nothing was sent to either organization
    finally:
        with owner.begin() as c:
            c.execute(text("DELETE FROM novrsoc.wazuh_group_mappings WHERE group_name = :g"), {"g": group})
