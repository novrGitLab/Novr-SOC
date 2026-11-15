"""Shared fixtures for the Phase 4 module tests (endpoints, SOC, reports)."""
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

from app import devseed
from app.connectors.wazuh_fixture import load_fixture
from app.modules.soc.service import ingest_alerts
from novrsoc_contracts.v1.soc import WazuhAlertIn
from tests.conftest import PASSWORD

ALPHA_GROUPS = ("nv-alpha-servers", "nv-alpha-workstations")
BETA_GROUPS = ("nv-beta-servers",)


@pytest.fixture(scope="session")
def mapped(owner, world):
    with owner.begin() as c:
        for g in ALPHA_GROUPS:
            c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g)"), {"o": world.alpha, "g": g})
        for g in BETA_GROUPS:
            c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g)"), {"o": world.beta, "g": g})
    return True


@pytest.fixture(scope="session")
def fixture_alerts(owner, mapped):
    """The fixture's alerts, ingested through the real ingest service (organization from the group map)."""
    alerts = [WazuhAlertIn.model_validate(a) for a in load_fixture()["alerts"]]
    with owner.begin() as c:
        counts = ingest_alerts(c, alerts, source="local_fixture")
    return counts


@pytest.fixture(scope="session")
def forwarder_token(owner, world):
    with owner.begin() as c:
        _, token = devseed.create_service_identity(c, world.platform, "forwarder", "test-forwarder", scopes=["alerts:ingest"])
    return token


class Client:
    """A signed-in user on a chosen app (cookie session + CSRF)."""

    def __init__(self, app, key: str):
        self.c = TestClient(app)
        r = self.c.post("/api/v1/auth/login", json={"email": f"{key}@test.novrsoc.invalid", "password": PASSWORD})
        assert r.status_code == 200, r.text
        self.csrf = r.json()["csrf_token"]

    def get(self, url, org=None, **kw):
        return self.c.get(url, headers={"X-Org-Id": str(org)} if org else {}, **kw)

    def post(self, url, json=None, org=None):
        h = {"X-CSRF-Token": self.csrf}
        if org:
            h["X-Org-Id"] = str(org)
        return self.c.post(url, json=json, headers=h)

    def _h(self, org):
        h = {"X-CSRF-Token": self.csrf}
        if org:
            h["X-Org-Id"] = str(org)
        return h

    def patch(self, url, json=None, org=None):
        return self.c.patch(url, json=json, headers=self._h(org))

    def put(self, url, json=None, org=None):
        return self.c.put(url, json=json, headers=self._h(org))

    def delete(self, url, org=None):
        return self.c.delete(url, headers=self._h(org))


@pytest.fixture(scope="session")
def as_user(fixture_app, world):
    cache = {}

    def _get(key: str, app=None) -> Client:
        k = (key, id(app or fixture_app))
        if k not in cache:
            cache[k] = Client(app or fixture_app, key)
        return cache[k]
    return _get


def new_id() -> str:
    return uuid.uuid4().hex[:8]
