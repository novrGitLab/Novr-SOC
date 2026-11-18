"""Local inference (Ollama) connector interface.

Ollama runs on a private host behind an AUTHENTICATED reverse proxy (TLS, bearer token). It is never
published to the internet and never reached by the browser. Only the AI Gateway (app/ai_gateway) calls
this interface, after key/permission, model-allowlist, quota, concurrency and timeout checks.

Configuration (names only): OLLAMA_URL (the proxy), OLLAMA_PROXY_TOKEN, OLLAMA_CA_CERT,
OLLAMA_TLS_SERVERNAME, OLLAMA_TIMEOUT_SECONDS. Phase 2.5 ships a fake backend only.
"""
from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, Protocol

from app.connectors.base import ConnectorHealth, ConnectorUnavailable, Endpoint, load_endpoint

Role = Literal["system", "user", "assistant"]


@dataclass(frozen=True)
class ChatMessage:
    role: Role
    content: str


@dataclass(frozen=True)
class Generation:
    model: str
    text: str
    prompt_tokens: int
    completion_tokens: int
    latency_ms: int


class InferenceBackend(Protocol):
    def generate(self, *, model: str, messages: Sequence[ChatMessage], max_tokens: int, temperature: float,
                 timeout_seconds: float, json_schema: Mapping | None = None) -> Generation: ...
    def available_models(self) -> list[str]: ...
    def health(self) -> ConnectorHealth: ...


def ollama_endpoint(env: Mapping[str, str], app_env: str) -> Endpoint:
    return load_endpoint("OLLAMA", env, app_env=app_env, credential_names=("OLLAMA_PROXY_TOKEN",),
                         default_timeout=60.0, allow_loopback_http=True)


class FakeInferenceBackend:
    """Deterministic stand-in for tests and local preview. Returns `replies[model]` or a fixed text."""

    def __init__(self, models: Sequence[str] = ("qwen3:4b", "qwen2.5:3b"), replies: Mapping[str, str] | None = None,
                 fail: bool = False):
        self.models, self.replies, self.fail, self.calls = list(models), dict(replies or {}), fail, []

    def generate(self, *, model, messages, max_tokens, temperature, timeout_seconds, json_schema=None) -> Generation:
        self.calls.append({"model": model, "messages": list(messages), "max_tokens": max_tokens})
        if self.fail:
            raise ConnectorUnavailable("inference backend unavailable")
        text = self.replies.get(model, "fake response")
        return Generation(model=model, text=text, prompt_tokens=sum(len(m.content) // 4 for m in messages),
                          completion_tokens=len(text) // 4, latency_ms=1)

    def available_models(self) -> list[str]:
        return list(self.models)

    def health(self) -> ConnectorHealth:
        return ConnectorHealth("OLLAMA", configured=True, reachable=None, tls_verified=False, detail="fake backend")


# ---------------------------------------------------------------- Phase 5: real and test backends (NHAI worker only)
import json as _json  # noqa: E402
import time as _time  # noqa: E402
from urllib.parse import urlsplit as _urlsplit  # noqa: E402

import httpx  # noqa: E402

from app.connectors.base import LOOPBACK, ConnectorRejected, ConnectorTimeout, ConnectorUnconfigured  # noqa: E402


def ollama_worker_endpoint(env: Mapping[str, str], app_env: str) -> tuple[Endpoint, str | None]:
    """Endpoint for the NHAI worker. Two accepted shapes:
      * co-located with Ollama (Server 1): OLLAMA_URL=http://127.0.0.1:11434 - plain HTTP is accepted ONLY for a
        loopback address, so prompts never leave the host; no token (Ollama has none);
      * remote: https behind an authenticated reverse proxy, OLLAMA_PROXY_TOKEN required, TLS verified.
    Returns (endpoint, bearer token or None)."""
    url = (env.get("OLLAMA_URL") or "").strip().rstrip("/")
    parts = _urlsplit(url) if url else None
    if parts is not None and parts.scheme == "http":
        if (parts.hostname or "").lower() not in LOOPBACK:
            raise ConnectorUnconfigured("OLLAMA_URL may use http only for a loopback address (127.0.0.1 / ::1)")
        try:
            timeout = float(env.get("OLLAMA_TIMEOUT_SECONDS") or 300)
        except ValueError:
            raise ConnectorUnconfigured("OLLAMA_TIMEOUT_SECONDS must be a number") from None
        return Endpoint(name="OLLAMA", base_url=url, tls=None, timeout_seconds=timeout, credential_names=()), None
    ep = ollama_endpoint(env, app_env)
    return ep, env["OLLAMA_PROXY_TOKEN"]


class OllamaBackend:
    """Local Ollama (/api/chat, non-streaming, JSON-schema constrained output). Never exposed publicly; only the NHAI
    worker uses it, through the AI Gateway's limits."""

    def __init__(self, ep: Endpoint, token: str | None, *, transport: httpx.BaseTransport | None = None,
                 num_ctx: int = 4096):
        verify = ep.tls.context if ep.tls else True
        headers = {"Accept": "application/json"}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self.ep, self.num_ctx = ep, num_ctx
        self.client = httpx.Client(base_url=ep.base_url, verify=verify, timeout=ep.timeout_seconds, transport=transport,
                                   headers=headers, follow_redirects=False)

    def _call(self, method: str, path: str, *, json=None, timeout: float | None = None) -> dict:
        try:
            r = self.client.request(method, path, json=json, timeout=timeout or self.ep.timeout_seconds)
        except httpx.TimeoutException:
            raise ConnectorTimeout("The NHAI interface did not answer in time") from None
        except httpx.HTTPError:
            raise ConnectorUnavailable("The NHAI interface could not be reached") from None
        if r.status_code in (401, 403):
            raise ConnectorRejected("The NHAI interface (or its proxy) refused the request")
        if r.status_code != 200:
            raise ConnectorUnavailable(f"The NHAI interface answered {r.status_code}")
        try:
            return r.json()
        except ValueError:
            raise ConnectorUnavailable("The NHAI interface returned a response that is not JSON") from None

    def generate(self, *, model, messages, max_tokens, temperature, timeout_seconds, json_schema=None) -> Generation:
        started = _time.monotonic()
        body = self._call("POST", "/api/chat", timeout=timeout_seconds, json={
            "model": model, "stream": False, "messages": [{"role": m.role, "content": m.content} for m in messages],
            "format": json_schema or "json", "keep_alive": "15m",
            "options": {"temperature": temperature, "num_predict": max_tokens, "num_ctx": self.num_ctx}})
        content = ((body.get("message") or {}).get("content")) or ""
        return Generation(model=model, text=content, prompt_tokens=int(body.get("prompt_eval_count") or 0),
                          completion_tokens=int(body.get("eval_count") or 0),
                          latency_ms=int((_time.monotonic() - started) * 1000))

    def available_models(self) -> list[str]:
        return [m.get("name", "") for m in self._call("GET", "/api/tags").get("models", [])]

    # ---- diagnostics (app.nhai.diagnose): Ollama's own measurements, never tenant data
    def loaded(self) -> list[dict]:
        """Models resident in memory now (GET /api/ps): name, size, expiry."""
        return list(self._call("GET", "/api/ps", timeout=10).get("models", []))

    def warm(self, model: str, timeout_seconds: float, keep_alive: str = "15m") -> dict:
        """Load the model without generating (an empty prompt); the answer carries load_duration in nanoseconds."""
        return self._call("POST", "/api/generate", timeout=timeout_seconds,
                          json={"model": model, "prompt": "", "stream": False, "keep_alive": keep_alive})

    def bench(self, model: str, messages: list[ChatMessage], num_predict: int, timeout_seconds: float) -> dict:
        """One fixed, non-streaming chat; the raw answer carries Ollama's durations (ns) and token counts."""
        return self._call("POST", "/api/chat", timeout=timeout_seconds, json={
            "model": model, "stream": False, "messages": [{"role": m.role, "content": m.content} for m in messages],
            "keep_alive": "15m", "options": {"temperature": 0, "num_predict": num_predict, "num_ctx": self.num_ctx}})

    def health(self) -> ConnectorHealth:
        self._call("GET", "/api/version", timeout=10)
        return ConnectorHealth("OLLAMA", configured=True, reachable=True, tls_verified=self.ep.tls is not None, detail="answered")


class TestInferenceAdapter:
    """DETERMINISTIC stand-in for development and tests (NOVRSOC_NHAI_BACKEND=test_adapter; refused elsewhere).
    It is not a language model: it restates the evidence it is given, cites E1, proposes the stored severity and
    labels itself in `limitations`. `script` replaces the output text (tests of validation and failures)."""

    __test__ = False  # not a pytest test class
    MODEL = "test-adapter"

    def __init__(self, script: str | None = None, fail: Exception | None = None, delay_seconds: float = 0.0):
        self.script, self.fail, self.delay, self.calls = script, fail, delay_seconds, []

    def generate(self, *, model, messages, max_tokens, temperature, timeout_seconds, json_schema=None) -> Generation:
        self.calls.append({"model": model, "chars": sum(len(m.content) for m in messages), "max_tokens": max_tokens})
        if self.delay:
            _time.sleep(self.delay)
        if self.fail is not None:
            raise self.fail
        if self.script is not None:
            text_ = self.script
        else:
            payload = _json.loads(messages[-1].content)
            ev = payload["evidence"]
            try:
                first = _json.loads(ev[0]["excerpt"])
            except ValueError:
                first = {}
            if not isinstance(first, dict) or "rule_id" not in first:
                return self._generic(model, messages, payload)
            text_ = _json.dumps({
                "summary": f"Test adapter (not a language model): NovrSIEM rule {first['rule_id']} "
                           f"'{first['rule_description']}' on agent {first['agent_name']}.",
                "statements": [{"text": f"NovrSIEM rated this alert {first['siem_severity_authoritative']} "
                                        f"(rule level {first['rule_level']}).", "citation_ids": ["E1"]}],
                "recommendations": [{"text": "Review the original log line and the agent before deciding.",
                                     "citation_ids": ["E1"], "requires_human_approval": True}],
                "confidence": "low",
                "limitations": ["Generated by the deterministic test adapter; this is not a model analysis."],
                "severity_assessment": {"proposed": first["siem_severity_authoritative"], "rationale": "Restates the NovrSIEM severity.",
                                        "citation_ids": ["E1"], "uncertainty": "high"},
                "missing_evidence": []})
        return Generation(model=model, text=text_, prompt_tokens=sum(len(m.content) // 4 for m in messages),
                          completion_tokens=len(text_) // 4, latency_ms=1)

    def _generic(self, model, messages, payload) -> Generation:
        ev = payload["evidence"]
        cite = [e["id"] for e in ev[:3]]
        text_ = _json.dumps({
            "summary": f"Test adapter (not a language model): {len(ev)} evidence item(s) for task {payload['task']} were provided; "
                       "they are listed as statements, unchanged in meaning.",
            "statements": [{"text": f"Evidence {e['id']} is a {e['type'].replace('_', ' ')} record.", "citation_ids": [e["id"]]}
                           for e in ev[:5]],
            "recommendations": [{"text": "Read the cited records before acting on this summary.", "citation_ids": cite[:1],
                                 "requires_human_approval": True}],
            "confidence": "low",
            "limitations": ["Generated by the deterministic test adapter; this is not a model analysis."],
            "missing_evidence": []})
        return Generation(model=model, text=text_, prompt_tokens=sum(len(m.content) // 4 for m in messages),
                          completion_tokens=len(text_) // 4, latency_ms=1)

    def available_models(self) -> list[str]:
        return [self.MODEL]

    def health(self) -> ConnectorHealth:
        return ConnectorHealth("OLLAMA", configured=True, reachable=None, tls_verified=False, detail="test adapter (not a model)")
