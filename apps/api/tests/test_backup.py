"""Encrypted backups: AES-256-GCM round trip, tamper detection, recorded runs (dump command faked; no pg_dump needed)."""
import os
import sys
from urllib.parse import urlsplit

import pytest
from cryptography.exceptions import InvalidTag
from sqlalchemy import text

from app import backup


def test_encryption_round_trip_and_tamper_detection():
    key = os.urandom(32)
    blob = backup.encrypt(key, b"PGDMP fake dump")
    assert blob.startswith(b"NVSB1") and b"fake dump" not in blob
    assert backup.decrypt(key, blob) == b"PGDMP fake dump"
    with pytest.raises(InvalidTag):
        backup.decrypt(key, blob[:-1] + bytes([blob[-1] ^ 1]))
    with pytest.raises(InvalidTag):
        backup.decrypt(os.urandom(32), blob)


def test_backup_run_is_recorded_with_sha256_and_mode(db, owner, tmp_path, monkeypatch, login):
    fake = tmp_path / "fake_dump.py"
    # The fake dump records what it was given: the password must arrive in PGPASSWORD, never in the arguments.
    fake.write_text("import os, sys; sys.stdout.buffer.write(b'PGDMP synthetic dump ' + repr(sys.argv[1:]).encode()"
                    " + b' PGPASSWORD=' + str(bool(os.environ.get('PGPASSWORD'))).encode())")
    monkeypatch.setenv("NOVRSOC_PG_DUMP_CMD", f'"{sys.executable}" "{fake}"')
    key = os.urandom(32)
    out = backup.run_backup(db.owner_url, tmp_path / "out", key)
    blob = open(out["file"], "rb").read()
    plain = backup.decrypt(key, blob)
    assert plain.startswith(b"PGDMP synthetic dump") and plain.endswith(b"PGPASSWORD=True")
    password = urlsplit(db.owner_url).password
    assert password and password.encode() not in plain and b"novrsoc_owner@" in plain
    with owner.begin() as c:
        row = c.execute(text("SELECT status, sha256, size_bytes, encrypted FROM novrsoc.backup_runs WHERE id = :i"), {"i": out["id"]}).one()
    assert tuple(row) == ("succeeded", out["sha256"], len(blob), True)
    assert any(b["id"] == out["id"] for b in login("admin").get("/api/v1/admin/backups").json()["items"])
    monkeypatch.setenv("NOVRSOC_PG_DUMP_CMD", f'"{sys.executable}" -c "import sys; sys.exit(3)"')
    with pytest.raises(SystemExit):
        backup.run_backup(db.owner_url, tmp_path / "out", key)
    with owner.begin() as c:
        assert c.execute(text("SELECT count(*) FROM novrsoc.backup_runs WHERE status = 'failed'")).scalar() >= 1
