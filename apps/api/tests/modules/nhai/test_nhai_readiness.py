"""NHAI readiness: the context budget (Ollama silently drops the start of an over-long prompt), schema-constrained output
reaching the model, and the Server 1 diagnostics. Fake HTTP transports only; no real Ollama is contacted."""
import json

import httpx
import pytest

from app.ai_gateway.core import Caller
from app.connectors.inference import ChatMessage, OllamaBackend, TestInferenceAdapter, ollama_worker_endpoint
from app.nhai import diagnose
from app.nhai.validate import output_schema
from app.nhai.worker import backend_for, gateway_for, nhai_budget
from novrsoc_contracts.v1.ai_gateway import Lane

NS = 1_000_000_000


def test_the_default_budget_fits_and_the_old_4096_window_did_not(settings):
    s = settings.model_copy(update={"nhai_backend": "ollama"})
    b = nhai_budget(s)
    assert b["fits"] and b["num_ctx"] == 8192 and b["needed_tokens"] > 4096       # the former fixed window was too small
    small = s.model_copy(update={"nhai_num_ctx": 4096})
    assert nhai_budget(small)["fits"] is False
    with pytest.raises(SystemExit, match="NOVRSOC_NHAI_NUM_CTX"):
        backend_for(small)                                                          # the worker refuses to start


def test_the_output_schema_reaches_the_backend_and_ollama_gets_it_as_format(settings):
    seen = {}

    def handler(req):
        seen.update(json.loads(req.content))
        return httpx.Response(200, json={"message": {"content": "{}"}, "prompt_eval_count": 10, "eval_count": 5})
    ep, tok = ollama_worker_endpoint({"OLLAMA_URL": "http://127.0.0.1:11434"}, "production")
    backend = OllamaBackend(ep, tok, transport=httpx.MockTransport(handler), num_ctx=8192)
    gw = gateway_for(settings, backend, "qwen2.5:3b")
    import uuid
    gw.generate(Caller(user_id=uuid.uuid4(), org_id=uuid.uuid4(), permissions=frozenset({"nhai:analyze"})), Lane.SECURITY_ANALYSIS,
                model="qwen2.5:3b", messages=[ChatMessage("user", "x")], max_tokens=64, json_schema=output_schema())
    assert seen["format"] == output_schema() and seen["options"]["num_ctx"] == 8192


def fake_ollama(resident=False, rates=(60, 2.6), model="qwen2.5:3b"):
    adapter = TestInferenceAdapter()

    def handler(req):
        path, body = req.url.path, json.loads(req.content or b"{}")
        if path == "/api/tags":
            return httpx.Response(200, json={"models": [{"name": model}]})
        if path == "/api/ps":
            return httpx.Response(200, json={"models": [{"name": model, "size": 2_200_000_000}] if resident else []})
        if path == "/api/generate":
            return httpx.Response(200, json={"load_duration": 21 * NS, "done": True})
        if path == "/api/chat" and "format" not in body:      # the throughput probe
            rate = rates
            return httpx.Response(200, json={"message": {"content": "It blocks stolen-password logins."},
                                             "prompt_eval_count": 40, "prompt_eval_duration": int(40 / rate[0] * NS),
                                             "eval_count": 13, "eval_duration": int(13 / rate[1] * NS), "total_duration": 8 * NS})
        if path == "/api/chat":                               # the structured check: a valid, grounded answer
            from app.connectors.inference import ChatMessage as M
            g = adapter.generate(model=model, messages=[M(m["role"], m["content"]) for m in body["messages"]], max_tokens=384,
                                 temperature=0.1, timeout_seconds=300)
            return httpx.Response(200, json={"message": {"content": g.text}, "prompt_eval_count": 900, "eval_count": 200})
        return httpx.Response(404)
    return handler


def _backend(handler):
    ep, tok = ollama_worker_endpoint({"OLLAMA_URL": "http://127.0.0.1:11434"}, "production")
    return OllamaBackend(ep, tok, transport=httpx.MockTransport(handler), num_ctx=8192)


def test_diagnostics_measure_load_throughput_projection_and_structured_output(settings):
    s = settings.model_copy(update={"nhai_backend": "ollama"})
    out = {}
    ok = diagnose.check_inference(s, _backend(fake_ollama()), "qwen2.5:3b", out)
    assert out["load"] == {"was_resident": False, "load_seconds": 21.0}
    assert out["throughput"]["prompt_tokens_per_s"] == 60.0 and out["throughput"]["generated_tokens_per_s"] == 2.6
    p = out["projection"]
    # worst case: 5334 input tokens / 60 + 384 / 2.6 = 236.6 s warm, + 21 s cold load = 257.6 s: inside the 300 s timeout
    assert (p["worst_case_seconds_warm"], p["worst_case_seconds_cold"], p["fits_timeout"]) == (236.6, 257.6, True)
    assert out["structured"]["valid"] is True and out["structured"]["citations"] >= 1
    assert ok


def test_at_40_prompt_tokens_per_second_the_default_worst_case_misses_the_timeout_cold(settings):
    """The arithmetic behind the readiness gate: 5334 / 40 + 384 / 2.6 = 281.0 s warm, 302.0 s with a 21 s cold load."""
    s = settings.model_copy(update={"nhai_backend": "ollama"})
    out = {}
    assert diagnose.check_inference(s, _backend(fake_ollama(rates=(40, 2.6))), "qwen2.5:3b", out) is False
    assert (out["projection"]["worst_case_seconds_warm"], out["projection"]["worst_case_seconds_cold"]) == (281.0, 302.0)


def test_diagnostics_say_so_when_the_host_is_too_slow_or_the_model_is_missing(settings):
    s = settings.model_copy(update={"nhai_backend": "ollama"})
    out = {}
    assert diagnose.check_inference(s, _backend(fake_ollama(rates=(5, 0.5))), "qwen2.5:3b", out) is False
    assert out["projection"]["fits_timeout"] is False and out["projection"]["max_output_tokens_that_fit"] < 384
    out = {}
    assert diagnose.check_inference(s, _backend(fake_ollama(model="llama3:8b")), "qwen2.5:3b", out) is False
    assert "ollama pull qwen2.5:3b" in out["ollama"]["problem"]


def test_the_database_check_flags_a_worker_that_does_not_use_its_dedicated_role(settings):
    """Run with the API's role on purpose: the diagnosis must refuse it (wrong role, whole-table reads)."""
    out = {}
    assert diagnose.check_db(settings, out) is False
    assert out["db"]["role"] == "novrsoc_app" and out["db"]["superuser"] is False and out["db"]["bypass_rls"] is False
    assert any("novrsoc_nhai" in p for p in out["db"]["problems"])
    assert any(p.startswith("alerts_whole_table") for p in out["db"]["problems"])


def test_the_synthetic_bundle_is_labelled_and_never_names_a_real_organization():
    b = diagnose.synthetic_bundle()
    assert "DIAGNOSTIC SYNTHETIC" in b.evidence[0].excerpt and "not a real event" in b.evidence[0].excerpt
