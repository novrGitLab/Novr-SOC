"""Ollama adapter for the NHAI worker (Phase 5). Fake HTTP transports only; no real Ollama is contacted."""
import json
from pathlib import Path

import httpx
import pytest

from app.connectors.base import ConnectorRejected, ConnectorTimeout, ConnectorUnavailable, ConnectorUnconfigured
from app.connectors.inference import ChatMessage, OllamaBackend, ollama_worker_endpoint


def backend(handler, env=None):
    ep, token = ollama_worker_endpoint(env or {"OLLAMA_URL": "http://127.0.0.1:11434"}, "production")
    return OllamaBackend(ep, token, transport=httpx.MockTransport(handler))


def test_request_shape_is_non_streaming_schema_constrained_and_bounded():
    seen = {}

    def handler(req):
        seen.update(json.loads(req.content))
        seen["path"] = req.url.path
        return httpx.Response(200, json={"message": {"content": "{}"}, "prompt_eval_count": 900, "eval_count": 212})
    g = backend(handler).generate(model="qwen2.5:3b", messages=[ChatMessage("system", "s"), ChatMessage("user", "u")],
                                  max_tokens=384, temperature=0.1, timeout_seconds=300, json_schema={"type": "object"})
    assert seen["path"] == "/api/chat" and seen["stream"] is False and seen["format"] == {"type": "object"}
    assert seen["options"]["num_predict"] == 384 and seen["options"]["temperature"] == 0.1
    assert (g.prompt_tokens, g.completion_tokens, g.text) == (900, 212, "{}")


def test_plain_http_only_for_loopback_and_remote_needs_https_and_token():
    ep, token = ollama_worker_endpoint({"OLLAMA_URL": "http://127.0.0.1:11434"}, "production")
    assert ep.tls is None and token is None
    with pytest.raises(ConnectorUnconfigured, match="loopback"):
        ollama_worker_endpoint({"OLLAMA_URL": "http://10.0.0.5:11434"}, "production")
    with pytest.raises(ConnectorUnconfigured, match="OLLAMA_PROXY_TOKEN"):
        ollama_worker_endpoint({"OLLAMA_URL": "https://ollama-proxy.internal"}, "production")
    ep, token = ollama_worker_endpoint({"OLLAMA_URL": "https://ollama-proxy.internal", "OLLAMA_PROXY_TOKEN": "t"}, "production")
    assert ep.tls is not None and token == "t"


@pytest.mark.parametrize("answer,error", [
    (lambda r: (_ for _ in ()).throw(httpx.ReadTimeout("slow", request=r)), ConnectorTimeout),
    (lambda r: (_ for _ in ()).throw(httpx.ConnectError("down", request=r)), ConnectorUnavailable),
    (lambda r: httpx.Response(401), ConnectorRejected),
    (lambda r: httpx.Response(500), ConnectorUnavailable),
    (lambda r: httpx.Response(200, content=b"not json"), ConnectorUnavailable)])
def test_errors_are_mapped_honestly(answer, error):
    with pytest.raises(error):
        backend(answer).generate(model="m", messages=[ChatMessage("user", "u")], max_tokens=16, temperature=0, timeout_seconds=5)


def test_the_api_process_never_calls_ollama():
    """Only the NHAI worker may construct the Ollama backend; API modules and routers never import it."""
    app_dir = Path(__file__).resolve().parents[3] / "app"
    offenders = [p for p in list((app_dir / "modules").rglob("*.py")) + list((app_dir / "routers").rglob("*.py"))
                 if "OllamaBackend" in p.read_text(encoding="utf-8") or "nhai.worker" in p.read_text(encoding="utf-8")]
    assert offenders == []
