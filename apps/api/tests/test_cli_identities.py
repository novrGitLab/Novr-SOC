"""Operator CLI: issuing and revoking machine credentials (Phase 5)."""
import stat
import uuid

from fastapi.testclient import TestClient
from sqlalchemy import text

from app import cli


def test_issue_writes_the_secret_once_and_revoke_takes_effect(db, owner, world, fixture_app, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("NOVRSOC_MIGRATION_DATABASE_URL", db.owner_url)
    out = tmp_path / "fwd.token"
    assert cli.create_service_identity("forwarder", "cli-forwarder", "t-platform", ["alerts:ingest"], out) == 0
    token = out.read_text().strip()
    printed = capsys.readouterr().out
    assert token.startswith("nsk_") and token not in printed and token.split(".")[1] not in printed
    if hasattr(stat, "S_IMODE") and not str(out).startswith("C:"):
        assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert cli.create_service_identity("forwarder", "again", "t-platform", ["alerts:ingest"], out) == 2   # never overwritten
    assert cli.create_service_identity("forwarder", "tenant", "t-alpha", ["alerts:ingest"], tmp_path / "x") == 2  # platform only
    assert cli.create_service_identity("root", "bad-kind", "t-platform", [], tmp_path / "y") == 2

    batch = {"batch_id": f"batch-{uuid.uuid4().hex}", "alerts": [{"id": f"cli-{uuid.uuid4().hex}", "timestamp": "2026-11-10T08:00:00Z",
             "rule": {"id": "1", "level": 3}, "agent": {"id": "004", "name": "b", "groups": ["nv-beta-servers"]}}]}
    c = TestClient(fixture_app)
    assert c.post("/api/v1/soc/ingest/alerts", json=batch, headers={"Authorization": f"Bearer {token}"}).status_code == 200
    ident = token[4:36]
    ident = str(uuid.UUID(ident))
    assert cli.revoke_service_identity(ident) == 0
    batch["batch_id"] = f"batch-{uuid.uuid4().hex}"
    assert c.post("/api/v1/soc/ingest/alerts", json=batch, headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert cli.revoke_service_identity(ident) == 1
    with owner.begin() as conn:
        actions = {r[0] for r in conn.execute(text("SELECT action FROM novrsoc.audit_events WHERE resource_id = :i"), {"i": ident})}
    assert {"SERVICE_IDENTITY_ISSUED", "SERVICE_IDENTITY_REVOKED"} <= actions
