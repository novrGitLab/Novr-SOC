"""AI Gateway enforcement core (contract: packages/contracts/.../v1/ai_gateway.py).

Pure, in-process policy enforcement used in front of the inference backend:
  key verification -> lane authorisation -> model allowlist (key ∩ lane) -> input size -> rate limit ->
  daily token quota -> concurrency (per key and per lane) -> backend call with timeout -> usage event.
Phase 2.5 scope: the logic and its tests, against the fake backend. The HTTP endpoints, key storage
(hashed, in PostgreSQL) and multi-instance counters belong to workstream F (decision in the report).
No production key is issued.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.connectors.base import ConnectorError
from app.connectors.inference import ChatMessage, InferenceBackend
from novrsoc_contracts.v1.ai_gateway import Lane, LanePolicy, Quota, RejectReason, UsageEvent

_KEY = re.compile(r"^ngk_([0-9a-f]{32})\.([A-Za-z0-9_-]{43,})$")

DEFAULT_POLICIES = {
    Lane.GENERAL: LanePolicy(lane=Lane.GENERAL, allowed_models=["qwen2.5:3b"], timeout_seconds=30,
                             max_input_chars=16_000, max_output_tokens=512, max_concurrency=2),
    Lane.SECURITY_ANALYSIS: LanePolicy(lane=Lane.SECURITY_ANALYSIS, allowed_models=["qwen3:4b", "qwen2.5:3b"],
                                       timeout_seconds=60, max_input_chars=64_000, max_output_tokens=1024,
                                       max_concurrency=2),
}


def issue_key() -> tuple[uuid.UUID, str, bytes]:
    """(key id, the key shown once, SHA-256 of the secret to store)."""
    key_id = uuid.uuid4()
    secret = secrets.token_urlsafe(32)
    return key_id, f"ngk_{key_id.hex}.{secret}", hashlib.sha256(secret.encode()).digest()


def parse_key(presented: str) -> tuple[uuid.UUID, bytes] | None:
    m = _KEY.match(presented.strip())
    return (uuid.UUID(hex=m.group(1)), hashlib.sha256(m.group(2).encode()).digest()) if m else None


@dataclass(frozen=True)
class KeyRecord:
    key_id: uuid.UUID
    secret_hash: bytes
    lane: Lane
    org_id: uuid.UUID | None
    allowed_models: frozenset[str]
    quota: Quota
    expires_at: datetime
    revoked_at: datetime | None = None


@dataclass(frozen=True)
class Caller:
    """Either a verified key or a signed-in user (security lane only, needs nhai:analyze)."""
    key: KeyRecord | None = None
    user_id: uuid.UUID | None = None
    org_id: uuid.UUID | None = None
    permissions: frozenset[str] = frozenset()


class GatewayRejected(Exception):
    def __init__(self, reason: RejectReason, http_status: int):
        super().__init__(reason.value)
        self.reason, self.http_status = reason, http_status


@dataclass
class _Counters:
    minute: deque = field(default_factory=deque)
    day: str = ""
    tokens_today: int = 0
    in_flight: int = 0


class Gateway:
    def __init__(self, backend: InferenceBackend, *, policies: dict[Lane, LanePolicy] | None = None,
                 record_usage: Callable[[UsageEvent], None] = lambda e: None, clock: Callable[[], float] = time.time):
        self.backend, self.policies, self.record_usage, self.clock = backend, policies or DEFAULT_POLICIES, record_usage, clock
        self._lock = threading.Lock()
        self._keys: dict[uuid.UUID, _Counters] = defaultdict(_Counters)
        self._lane_in_flight: dict[Lane, int] = defaultdict(int)
        self._pool = ThreadPoolExecutor(max_workers=8, thread_name_prefix="ai-gw")

    # ---- authentication -------------------------------------------------------------------------
    @staticmethod
    def verify_key(presented: str, lookup: Callable[[uuid.UUID], KeyRecord | None], now: datetime) -> KeyRecord:
        parsed = parse_key(presented)
        rec = lookup(parsed[0]) if parsed else None
        if not parsed or rec is None or not hmac.compare_digest(parsed[1], rec.secret_hash):
            raise GatewayRejected(RejectReason.KEY_INVALID, 401)
        if rec.revoked_at is not None or rec.expires_at <= now:
            raise GatewayRejected(RejectReason.KEY_REVOKED_OR_EXPIRED, 401)
        return rec

    # ---- authorisation + limits -----------------------------------------------------------------
    def _authorise(self, caller: Caller, lane: Lane, model: str, input_chars: int) -> None:
        policy = self.policies[lane]
        if caller.key is not None:
            if caller.key.lane != lane:
                raise GatewayRejected(RejectReason.WRONG_LANE, 403)
            allowed = caller.key.allowed_models & set(policy.allowed_models)
        else:
            if lane != Lane.SECURITY_ANALYSIS or caller.user_id is None or caller.org_id is None \
                    or "nhai:analyze" not in caller.permissions:
                raise GatewayRejected(RejectReason.WRONG_LANE, 403)
            allowed = set(policy.allowed_models)
        if model not in allowed:
            raise GatewayRejected(RejectReason.MODEL_NOT_ALLOWED, 403)
        if input_chars > policy.max_input_chars:
            raise GatewayRejected(RejectReason.INPUT_TOO_LARGE, 413)

    def _admit(self, caller: Caller, lane: Lane) -> None:
        now = self.clock()
        with self._lock:
            if self._lane_in_flight[lane] >= self.policies[lane].max_concurrency:
                raise GatewayRejected(RejectReason.CONCURRENCY_LIMIT, 429)
            if caller.key is not None:
                c = self._keys[caller.key.key_id]
                while c.minute and now - c.minute[0] >= 60:
                    c.minute.popleft()
                day = time.strftime("%Y-%m-%d", time.gmtime(now))
                if c.day != day:
                    c.day, c.tokens_today = day, 0
                if len(c.minute) >= caller.key.quota.requests_per_minute:
                    raise GatewayRejected(RejectReason.RATE_LIMITED, 429)
                if c.tokens_today >= caller.key.quota.tokens_per_day:
                    raise GatewayRejected(RejectReason.DAILY_QUOTA_EXHAUSTED, 429)
                if c.in_flight >= caller.key.quota.max_concurrency:
                    raise GatewayRejected(RejectReason.CONCURRENCY_LIMIT, 429)
                c.minute.append(now)
                c.in_flight += 1
            self._lane_in_flight[lane] += 1

    def _release(self, caller: Caller, lane: Lane, tokens: int) -> None:
        with self._lock:
            self._lane_in_flight[lane] -= 1
            if caller.key is not None:
                c = self._keys[caller.key.key_id]
                c.in_flight -= 1
                c.tokens_today += tokens

    # ---- the call -------------------------------------------------------------------------------
    def generate(self, caller: Caller, lane: Lane, *, model: str, messages: list[ChatMessage], max_tokens: int,
                 temperature: float = 0.2, request_id: str | None = None, json_schema: dict | None = None):
        request_id = request_id or uuid.uuid4().hex
        prompt = "\n".join(m.content for m in messages)
        event = dict(request_id=request_id, occurred_at=datetime.now(timezone.utc), lane=lane, model=model,
                     key_id=caller.key.key_id if caller.key else None, user_id=caller.user_id,
                     org_id=(caller.key.org_id if caller.key else caller.org_id),
                     prompt_sha256=hashlib.sha256(prompt.encode()).hexdigest())
        try:
            self._authorise(caller, lane, model, len(prompt))
            self._admit(caller, lane)
        except GatewayRejected as r:
            self.record_usage(UsageEvent(**event, outcome="rejected", reject_reason=r.reason))
            raise
        policy, tokens, started = self.policies[lane], 0, self.clock()
        try:
            extra = {"json_schema": json_schema} if json_schema is not None else {}   # schema-constrained decoding (Ollama `format`)
            fut = self._pool.submit(self.backend.generate, model=model, messages=messages,
                                    max_tokens=min(max_tokens, policy.max_output_tokens), temperature=temperature,
                                    timeout_seconds=policy.timeout_seconds, **extra)
            try:
                gen = fut.result(timeout=policy.timeout_seconds)
            except FutureTimeout:
                fut.cancel()
                self.record_usage(UsageEvent(**event, outcome="timeout"))
                raise GatewayRejected(RejectReason.TIMEOUT, 504) from None
            except ConnectorError:
                self.record_usage(UsageEvent(**event, outcome="backend_error"))
                raise GatewayRejected(RejectReason.BACKEND_UNAVAILABLE, 503) from None
            tokens = gen.prompt_tokens + gen.completion_tokens
            self.record_usage(UsageEvent(**event, outcome="ok", prompt_tokens=gen.prompt_tokens,
                                         completion_tokens=gen.completion_tokens,
                                         latency_ms=int((self.clock() - started) * 1000)))
            return gen
        finally:
            self._release(caller, lane, tokens)
