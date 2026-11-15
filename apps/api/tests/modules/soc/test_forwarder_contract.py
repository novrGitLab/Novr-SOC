"""The real forwarder (services/edge/forwarder) against the real ingest endpoint and database (workstream A).

Fake indexer and manager; the API is the FastAPI app in-process. Proves the forwarder's payload, batch ids and
acknowledgement checks match the API, including replay after a lost answer and quarantine counting.
"""
import importlib
import json
import sys
import tempfile
from datetime import timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text

FWD = Path(__file__).resolve().parents[5] / "services" / "edge" / "forwarder"
sys.path.insert(0, str(FWD))
sys.path.insert(0, str(FWD / "tests"))
core = importlib.import_module("novrsoc_forwarder.core")
state_mod = importlib.import_module("novrsoc_forwarder.state")
fake = importlib.import_module("test_forwarder")


class ApiViaTestClient:
    def __init__(self, app, token, lose_first_answer=False):
        self.c, self.token, self.lose = TestClient(app), token, lose_first_answer

    def request(self, method, url, headers=None, body=None):
        path = url.split("novrsoc-api.test", 1)[1]
        h = {"Authorization": f"Bearer {self.token}"}
        r = self.c.post(path, json=body, headers=h)
        if self.lose:
            self.lose = False
            raise core.HttpError("api timed out")
        return r.status_code, r.content


@pytest.fixture
def forwarder_env(tmp_path, forwarder_token):
    secrets = {}
    for name, value in (("token", forwarder_token), ("idx", "x"), ("mgr", "y")):
        p = tmp_path / name
        p.write_text(value)
        secrets[name] = str(p)
    return {"NOVRSOC_API_URL": "https://novrsoc-api.test", "WAZUH_INDEXER_URL": "https://idx.test", "WAZUH_API_URL": "https://mgr.test",
            "NOVRSOC_FORWARDER_TOKEN_FILE": secrets["token"], "WAZUH_INDEXER_USER": "ro", "WAZUH_INDEXER_PASSWORD_FILE": secrets["idx"],
            "WAZUH_API_USER": "ro", "WAZUH_API_PASSWORD_FILE": secrets["mgr"], "FORWARDER_STATE_DIR": str(tmp_path / "state"),
            "FORWARDER_START_AT": fake.T0.isoformat(), "FORWARDER_BATCH": "2", "FORWARDER_LATE_EVERY": "0"}


def test_forwarder_delivers_to_the_real_api_with_replay_and_quarantine(fixture_app, forwarder_token, forwarder_env, owner, world, mapped):
    docs = [fake.alert(i, fake.T0 + timedelta(seconds=i), agent=agent)
            for i, agent in enumerate(["004", "004", "777"])]   # 004 = beta's fixture agent; 777 is unmapped
    for d in docs:
        d["id"] = f"fc-{d['id']}"
    manager = fake.FakeManager({"004": ["nv-beta-servers"], "777": ["lab-unmapped"]})
    api = ApiViaTestClient(fixture_app, forwarder_token, lose_first_answer=True)
    f = core.Forwarder(core.Config(forwarder_env), api=api, indexer=fake.FakeIndexer(docs), manager=manager,
                       state=state_mod.State(forwarder_env["FORWARDER_STATE_DIR"]), now=lambda: fake.NOW, sleep=lambda s: None)
    with pytest.raises(core.Retryable):
        f.forward_once(1)                   # first answer lost: stored by the API, but the checkpoint must not move
    assert f.state.load().sort is None
    assert f.forward_once(2) == 3           # replay of the same batch_id + the rest
    with owner.begin() as c:
        rows = c.execute(text("SELECT external_id, org_id FROM novrsoc.alerts WHERE external_id LIKE 'fc-%'")).all()
        q = c.execute(text("SELECT count(*) FROM novrsoc.alert_quarantine WHERE external_id LIKE 'fc-%'")).scalar()
        replayed = c.execute(text("SELECT count(*) FROM novrsoc.ingest_batches WHERE batch_id LIKE 'fwd-%'")).scalar()
    assert sorted(r.external_id for r in rows) == sorted(d["id"] for d in docs[:2]) and {r.org_id for r in rows} == {world.beta}
    assert q == 1 and replayed == 2
