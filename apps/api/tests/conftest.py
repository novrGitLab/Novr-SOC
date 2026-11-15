"""Test harness: a throwaway database per test session inside the disposable dev cluster.

Needs NOVRSOC_TEST_ADMIN_DATABASE_URL (superuser of the LOCAL disposable cluster; written to apps/api/.env
by scripts/dev/bootstrap_env.py) plus the owner/app URLs. Refuses any non-loopback host.
"""
from __future__ import annotations

import os
import secrets
import uuid
from argparse import Namespace
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import pytest
from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text

from app import devseed
from app.core.config import LOOPBACK_HOSTS, Settings
from app.main import create_app

ROOT = Path(__file__).resolve().parents[3]
ENV_FILE = ROOT / "apps" / "api" / ".env"
PASSWORD = "correct-horse-battery-staple-42"  # gitleaks:allow (fixed password of throwaway test users in per-run databases)


def _env(key: str) -> str:
    if os.environ.get(key):
        return os.environ[key]
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
            if line.startswith(key + "="):
                return line.split("=", 1)[1].strip()
    pytest.skip(f"{key} not configured (run scripts/dev/bootstrap_env.py and start deploy/dev/compose.yaml)")


def _with_db(url: str, db: str) -> str:
    p = urlsplit(url)
    if (p.hostname or "") not in LOOPBACK_HOSTS:
        raise RuntimeError("tests only run against a loopback database")
    return urlunsplit((p.scheme, p.netloc, "/" + db, p.query, p.fragment))


def make_database(admin_url: str, name: str) -> None:
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'CREATE DATABASE "{name}"'))
        c.execute(text("""DO $$ BEGIN IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'novrsoc_nhai') THEN
                              CREATE ROLE novrsoc_nhai NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS CONNECTION LIMIT 2;
                            END IF; END $$"""))
    admin.dispose()
    eng = create_engine(_with_db(admin_url, name), isolation_level="AUTOCOMMIT")
    with eng.connect() as c:
        c.execute(text("REVOKE CREATE ON SCHEMA public FROM PUBLIC"))
        c.execute(text("CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public"))
        c.execute(text("CREATE SCHEMA novrsoc AUTHORIZATION novrsoc_owner"))
        c.execute(text("GRANT USAGE ON SCHEMA novrsoc TO novrsoc_app"))
        c.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO novrsoc_app, novrsoc_owner'))
    eng.dispose()


def drop_database(admin_url: str, name: str) -> None:
    admin = create_engine(admin_url, isolation_level="AUTOCOMMIT")
    with admin.connect() as c:
        c.execute(text(f'DROP DATABASE IF EXISTS "{name}" WITH (FORCE)'))
    admin.dispose()


def alembic_config(owner_url: str) -> Config:
    cfg = Config(str(ROOT / "packages" / "db" / "alembic.ini"))
    cfg.cmd_opts = Namespace(x=[f"url={owner_url}"])  # type: ignore[attr-defined]
    return cfg


@dataclass
class Db:
    name: str
    admin_url: str
    owner_url: str
    app_url: str


@pytest.fixture(scope="session")
def db() -> Db:
    admin = _env("NOVRSOC_TEST_ADMIN_DATABASE_URL")
    owner = _env("NOVRSOC_MIGRATION_DATABASE_URL")
    app_url = _env("NOVRSOC_DATABASE_URL")
    name = f"novrsoc_test_{secrets.token_hex(4)}"
    make_database(admin, name)
    d = Db(name, admin, _with_db(owner, name), _with_db(app_url, name))
    command.upgrade(alembic_config(d.owner_url), "head")
    yield d
    from app.db import session as dbs
    if dbs._engine is not None:
        dbs._engine.dispose()
    drop_database(admin, name)


@pytest.fixture(scope="session")
def owner(db: Db):
    eng = create_engine(db.owner_url)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def app_engine(db: Db):
    eng = create_engine(db.app_url)
    yield eng
    eng.dispose()


@pytest.fixture(scope="session")
def settings(db: Db) -> Settings:
    return Settings(_env_file=None, env="test", database_url=db.app_url, session_cookie_secure=False)  # type: ignore[call-arg]


@pytest.fixture(scope="session")
def app(settings: Settings):
    return create_app(settings)


@pytest.fixture(scope="session")
def fixture_settings(settings: Settings) -> Settings:
    return settings.model_copy(update={"wazuh_mode": "local_fixture"})


@pytest.fixture(scope="session")
def fixture_app(fixture_settings: Settings):
    """The same API with the labelled LOCAL FIXTURE Wazuh connector as its data source (Phase 4)."""
    return create_app(fixture_settings)


@dataclass
class World:
    platform: uuid.UUID
    alpha: uuid.UUID
    beta: uuid.UUID
    gamma: uuid.UUID
    users: dict[str, uuid.UUID] = field(default_factory=dict)


@pytest.fixture(scope="session")
def world(owner) -> World:
    with owner.begin() as c:
        platform = devseed.create_org(c, "t-platform", "Test Platform", "platform")
        alpha = devseed.create_org(c, "t-alpha", "Test Alpha")
        beta = devseed.create_org(c, "t-beta", "Test Beta")
        gamma = devseed.create_org(c, "t-gamma", "Test Gamma")
        w = World(platform, alpha, beta, gamma)
        spec = {
            "admin": ("super_admin", platform, {}),
            "manager": ("soc_manager", platform, {alpha: "operations"}),
            "analyst_a": ("analyst", alpha, {}),
            "analyst_b": ("analyst", beta, {}),
            "analyst_assigned": ("analyst", platform, {beta: "operations"}),
            "exec_a": ("executive", alpha, {}),
            "exec_reporting": ("executive", alpha, {gamma: "reporting"}),
            "portal_a": ("portal_user", alpha, {}),
            "manager_b": ("soc_manager", beta, {}),
            "locked": ("analyst", alpha, {}),
            "disabled": ("analyst", alpha, {}),
        }
        for key, (role, home, assign) in spec.items():
            w.users[key] = devseed.create_user(c, f"{key}@test.novrsoc.invalid", PASSWORD, role, home, assign)
        c.execute(text("UPDATE novrsoc.users SET status = 'disabled' WHERE id = :id"), {"id": w.users["disabled"]})
    return w


class Session:
    def __init__(self, app, email: str, password: str = PASSWORD):
        self.client = TestClient(app)
        r = self.client.post("/api/v1/auth/login", json={"email": email, "password": password})
        assert r.status_code == 200, r.text
        self.login_response = r
        self.csrf = r.json()["csrf_token"]

    def get(self, url: str, org: uuid.UUID | None = None, **kw):
        return self.client.get(url, headers=self._h(org, kw.pop("headers", {})), **kw)

    def post(self, url: str, json=None, org: uuid.UUID | None = None, csrf: bool = True, **kw):
        h = self._h(org, kw.pop("headers", {}))
        if csrf:
            h["X-CSRF-Token"] = self.csrf
        return self.client.post(url, json=json, headers=h, **kw)

    @staticmethod
    def _h(org, extra):
        h = dict(extra)
        if org is not None:
            h["X-Org-Id"] = str(org)
        return h


@pytest.fixture(scope="session")
def login(app, world):
    def _login(key: str) -> Session:
        return Session(app, f"{key}@test.novrsoc.invalid")
    return _login


def audit_actions(owner_engine, org: uuid.UUID | None = None, action: str | None = None) -> list[dict]:
    q = "SELECT * FROM novrsoc.audit_events WHERE true"
    params = {}
    if org is not None:
        q += " AND org_id = :o"; params["o"] = org
    if action:
        q += " AND action = :a"; params["a"] = action
    with owner_engine.connect() as c:
        return [dict(r._mapping) for r in c.execute(text(q + " ORDER BY id"), params)]
