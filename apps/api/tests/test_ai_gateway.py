"""AI Gateway enforcement core: keys, lanes, model allowlists, limits, timeouts, usage audit. Fake backend only."""
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.ai_gateway.core import Caller, Gateway, GatewayRejected, KeyRecord, issue_key
from app.connectors.inference import ChatMessage, FakeInferenceBackend
from novrsoc_contracts.v1.ai_gateway import Lane, Quota, RejectReason

NOW = datetime.now(timezone.utc)
MSG = [ChatMessage("user", "explain this alert: SECRET-PROMPT-TEXT")]


def key(lane=Lane.GENERAL, models=("qwen2.5:3b",), org=None, rpm=60, tpd=100_000, conc=2, **kw):
    kid, token, h = issue_key()
    rec = KeyRecord(kid, h, lane, org, frozenset(models), Quota(requests_per_minute=rpm, tokens_per_day=tpd, max_concurrency=conc),
                    kw.get("expires", NOW + timedelta(days=1)), kw.get("revoked"))
    return token, rec


def gw(backend=None, events=None):
    return Gateway(backend or FakeInferenceBackend(), record_usage=(events.append if events is not None else (lambda e: None)))


def test_keys_are_hashed_verified_revocable_and_expiring():
    token, rec = key()
    assert token.startswith("ngk_") and token.split(".", 1)[1].encode() not in rec.secret_hash
    assert Gateway.verify_key(token, {rec.key_id: rec}.get, NOW) is rec
    for bad in (token + "x", "ngk_" + "0" * 32 + "." + "A" * 43, "changeme"):
        with pytest.raises(GatewayRejected) as e:
            Gateway.verify_key(bad, {rec.key_id: rec}.get, NOW)
        assert e.value.reason == RejectReason.KEY_INVALID
    _, revoked = key(revoked=NOW)
    _, expired = key(expires=NOW - timedelta(seconds=1))
    for r in (revoked, expired):
        t = token.replace(rec.key_id.hex, r.key_id.hex)
        with pytest.raises(GatewayRejected):
            Gateway.verify_key(t, {r.key_id: r}.get, NOW)


def test_lanes_are_separate():
    g = gw()
    _, general = key(Lane.GENERAL)
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=general), Lane.SECURITY_ANALYSIS, model="qwen2.5:3b", messages=MSG, max_tokens=50)
    assert e.value.reason == RejectReason.WRONG_LANE
    # users only reach the security lane, and only with nhai:analyze in an active organization
    user = Caller(user_id=uuid.uuid4(), org_id=uuid.uuid4(), permissions=frozenset({"nhai:analyze"}))
    assert g.generate(user, Lane.SECURITY_ANALYSIS, model="qwen3:4b", messages=MSG, max_tokens=50).text
    for bad in (Caller(user_id=uuid.uuid4(), org_id=uuid.uuid4(), permissions=frozenset({"alerts:read"})),
                Caller(user_id=uuid.uuid4(), org_id=None, permissions=frozenset({"nhai:analyze"}))):
        with pytest.raises(GatewayRejected):
            g.generate(bad, Lane.SECURITY_ANALYSIS, model="qwen3:4b", messages=MSG, max_tokens=50)
    with pytest.raises(GatewayRejected):
        g.generate(user, Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=50)


def test_model_allowlist_is_the_intersection_of_key_and_lane():
    g = gw()
    _, k = key(Lane.GENERAL, models=("qwen2.5:3b", "qwen3:4b"))  # qwen3:4b is not in the general lane policy
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=k), Lane.GENERAL, model="qwen3:4b", messages=MSG, max_tokens=50)
    assert e.value.reason == RejectReason.MODEL_NOT_ALLOWED
    with pytest.raises(GatewayRejected):
        g.generate(Caller(key=k), Lane.GENERAL, model="llama3:70b", messages=MSG, max_tokens=50)


def test_input_limit_rate_limit_and_daily_quota():
    g = gw()
    _, k = key(rpm=2)
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=k), Lane.GENERAL, model="qwen2.5:3b", messages=[ChatMessage("user", "x" * 20_000)], max_tokens=10)
    assert e.value.reason == RejectReason.INPUT_TOO_LARGE
    for _ in range(2):
        g.generate(Caller(key=k), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=k), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    assert e.value.reason == RejectReason.RATE_LIMITED and e.value.http_status == 429
    _, small = key(tpd=1_000)
    big = FakeInferenceBackend(replies={"qwen2.5:3b": "y" * 5000})
    g2 = gw(big)
    g2.generate(Caller(key=small), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    with pytest.raises(GatewayRejected) as e:
        g2.generate(Caller(key=small), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    assert e.value.reason == RejectReason.DAILY_QUOTA_EXHAUSTED


class _Slow(FakeInferenceBackend):
    def __init__(self, delay):
        super().__init__(); self.delay = delay; self.started = threading.Event()

    def generate(self, **kw):
        self.started.set(); time.sleep(self.delay); return super().generate(**kw)


def test_concurrency_limit_and_timeout():
    slow = _Slow(0.5)
    g = gw(slow)
    _, k = key(conc=1)
    t = threading.Thread(target=lambda: g.generate(Caller(key=k), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10))
    t.start(); slow.started.wait(2)
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=k), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    assert e.value.reason == RejectReason.CONCURRENCY_LIMIT
    t.join()
    from novrsoc_contracts.v1.ai_gateway import LanePolicy
    fast = Gateway(_Slow(2.0), policies={Lane.GENERAL: LanePolicy(lane=Lane.GENERAL, allowed_models=["qwen2.5:3b"], timeout_seconds=1,
                                                                    max_input_chars=1000, max_output_tokens=50, max_concurrency=1)})
    _, k2 = key()
    with pytest.raises(GatewayRejected) as e:
        fast.generate(Caller(key=k2), Lane.GENERAL, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    assert e.value.reason == RejectReason.TIMEOUT and e.value.http_status == 504


def test_usage_is_audited_without_prompt_text_and_tenant_attributed():
    events = []
    g = gw(FakeInferenceBackend(fail=True), events)
    org = uuid.uuid4()
    _, k = key(Lane.SECURITY_ANALYSIS, models=("qwen3:4b",), org=org)
    with pytest.raises(GatewayRejected) as e:
        g.generate(Caller(key=k), Lane.SECURITY_ANALYSIS, model="qwen3:4b", messages=MSG, max_tokens=10)
    assert e.value.reason == RejectReason.BACKEND_UNAVAILABLE
    with pytest.raises(GatewayRejected):
        g.generate(Caller(key=k), Lane.SECURITY_ANALYSIS, model="qwen2.5:3b", messages=MSG, max_tokens=10)
    assert [ev.outcome for ev in events] == ["backend_error", "rejected"]
    assert all(ev.org_id == org and ev.key_id == k.key_id for ev in events)
    dumped = " ".join(ev.model_dump_json() for ev in events)
    assert "SECRET-PROMPT-TEXT" not in dumped and all(len(ev.prompt_sha256) == 64 for ev in events)
