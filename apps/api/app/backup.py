"""Encrypted logical backups and restore drills (operator CLI; contracts v1/governance.BackupJob: encrypted, always).

  python -m app.cli backup --out-dir <dir> --key-file <32-byte key file>
  python -m app.cli restore-drill --file <backup.nvsb> --key-file <key>

backup: runs the dump command (NOVRSOC_PG_DUMP_CMD, default `pg_dump`; it receives the schema-owner URL WITHOUT the
password as its last argument, the password as PGPASSWORD, and must write a custom-format dump to stdout), encrypts it with AES-256-GCM (header "NVSB1" + 12-byte nonce,
the header is authenticated), writes it with mode 0600 and records the run (size, SHA-256 of the encrypted file).
restore-drill: decrypts, restores into a DISPOSABLE database (NOVRSOC_PG_RESTORE_CMD, default `pg_restore`, receives the
target URL and reads the dump on stdin), checks that the schema and migration revision are present, records the drill and
drops the disposable database. It never restores over the live database.
Keys never leave the key file; store it outside the server (Server 2) and outside the backup target.
"""
from __future__ import annotations

import base64
import hashlib
import os
import shlex
import subprocess
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlsplit, urlunsplit

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import create_engine, text

MAGIC = b"NVSB1"


def load_key(path: Path) -> bytes:
    raw = path.read_bytes().strip()
    key = raw if len(raw) == 32 else base64.b64decode(raw)
    if len(key) != 32:
        raise SystemExit("the backup key must be 32 bytes (raw or base64)")
    return key


def encrypt(key: bytes, data: bytes) -> bytes:
    nonce = os.urandom(12)
    return MAGIC + nonce + AESGCM(key).encrypt(nonce, data, MAGIC)


def decrypt(key: bytes, blob: bytes) -> bytes:
    if not blob.startswith(MAGIC):
        raise SystemExit("not a NovrSOC backup file")
    return AESGCM(key).decrypt(blob[5:17], blob[17:], MAGIC)


def _cmd(env_name: str, default: str) -> list[str]:
    tokens = shlex.split(os.environ.get(env_name) or default, posix=os.name != "nt")
    # Non-POSIX splitting (Windows paths) keeps the quotes around a token: remove one matched pair.
    return [t[1:-1] if len(t) >= 2 and t[0] == t[-1] and t[0] in "\"'" else t for t in tokens]


def _libpq(url: str) -> tuple[str, dict[str, str]]:
    """The URL for pg_dump/pg_restore WITHOUT its password, and an environment carrying it as PGPASSWORD.
    A password in a command-line argument is readable by every local user (/proc/<pid>/cmdline); the environment of
    a process is readable only by its owner."""
    parts = urlsplit(url.replace("postgresql+psycopg://", "postgresql://"))
    env = dict(os.environ)
    if parts.password is not None:
        env["PGPASSWORD"] = unquote(parts.password)
        user = parts.username or ""
        host = parts.hostname or ""
        if ":" in host:
            host = f"[{host}]"
        netloc = f"{user}@{host}" + (f":{parts.port}" if parts.port else "")
        parts = parts._replace(netloc=netloc)
    return urlunsplit(parts), env


def run_backup(owner_url: str, out_dir: Path, key: bytes, target_label: str = "local") -> dict:
    started = datetime.now(timezone.utc)
    eng = create_engine(owner_url)
    run_id = uuid.uuid4()
    with eng.begin() as c:
        c.execute(text("INSERT INTO novrsoc.backup_runs (id, kind, started_at, status, target) VALUES (:i, 'logical_dump', :s, 'running', :t)"),
                  {"i": run_id, "s": started, "t": target_label})
    plain_url, env = _libpq(owner_url)
    try:
        dump = subprocess.run(_cmd("NOVRSOC_PG_DUMP_CMD", "pg_dump -Fc") + [plain_url], capture_output=True, check=True,
                              timeout=3600, env=env).stdout
        if not dump:
            raise RuntimeError("the dump command produced no output")
        blob = encrypt(key, dump)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"novrsoc-{started.strftime('%Y%m%dT%H%M%SZ')}-{run_id.hex[:8]}.nvsb"
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(blob)
        digest = hashlib.sha256(blob).hexdigest()
        with eng.begin() as c:
            c.execute(text("""UPDATE novrsoc.backup_runs SET status = 'succeeded', finished_at = now(), size_bytes = :n, sha256 = :h,
                              note = :note WHERE id = :i"""), {"n": len(blob), "h": digest, "note": path.name, "i": run_id})
        return {"id": str(run_id), "file": str(path), "size_bytes": len(blob), "sha256": digest}
    except (subprocess.SubprocessError, OSError, RuntimeError) as e:
        with eng.begin() as c:
            c.execute(text("UPDATE novrsoc.backup_runs SET status = 'failed', finished_at = now(), note = :n WHERE id = :i"),
                      {"n": type(e).__name__, "i": run_id})
        raise SystemExit(f"backup failed: {type(e).__name__}")


def run_restore_drill(owner_url: str, admin_url: str, file: Path, key: bytes) -> dict:
    blob = file.read_bytes()
    digest = hashlib.sha256(blob).hexdigest()
    eng = create_engine(owner_url)
    with eng.begin() as c:
        backup_id = c.execute(text("SELECT id FROM novrsoc.backup_runs WHERE sha256 = :h"), {"h": digest}).scalar()
    if backup_id is None:
        raise SystemExit("this file does not match a recorded backup (SHA-256)")
    dump = decrypt(key, blob)
    started = time.monotonic()
    name = f"novrsoc_drill_{uuid.uuid4().hex[:8]}"
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
    target = admin_url.rsplit("/", 1)[0] + f"/{name}"
    status, tables, checks = "failed", 0, False
    try:
        restore_url, env = _libpq(target)
        subprocess.run(_cmd("NOVRSOC_PG_RESTORE_CMD", "pg_restore --no-owner --no-privileges -d") + [restore_url],
                       input=dump, capture_output=True, timeout=3600, env=env)
        with create_engine(target).connect() as c:
            tables = c.execute(text("SELECT count(*) FROM information_schema.tables WHERE table_schema = 'novrsoc'")).scalar()
            rev = c.execute(text("SELECT version_num FROM novrsoc.alembic_version")).scalar() if tables else None
        checks = bool(tables) and rev is not None
        status = "succeeded" if checks else "failed"
    finally:
        with admin.connect() as c:
            c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    with eng.begin() as c:
        c.execute(text("""INSERT INTO novrsoc.restore_drills (backup_id, status, restored_tables, row_count_checks_passed, duration_seconds, note)
                          VALUES (:b, :s, :t, :ok, :d, 'disposable database, dropped after the check')"""),
                  {"b": backup_id, "s": status, "t": tables, "ok": checks, "d": int(time.monotonic() - started)})
    return {"backup_id": str(backup_id), "status": status, "restored_tables": tables}
