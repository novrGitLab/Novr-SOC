"""NHAI readiness diagnostics, run ON Server 1 next to Ollama, with the worker's own environment file:

  sudo -u novrsoc-nhai env $(cat /etc/novrsoc-nhai/nhai-worker.env | xargs) \\
      /opt/novrsoc-v2/apps/api/.venv/bin/python -m app.nhai.diagnose [--db] [--skip-inference] [--json]

What it measures (Ollama's own counters, not wall-clock guesses), with NO tenant data:
  config      backend, model, timeouts, context window and the worst-case context budget (nhai_budget);
  ollama      version, whether the model is installed, what is resident in memory (/api/ps);
  load        loading the model without generating (load_duration): the cold-start cost a first job pays;
  throughput  one fixed tiny chat: prompt-evaluation and generation rates (tokens/s);
  projection  the worst case for a real job (largest admitted prompt, longest answer) against the inference timeout;
  structured  one SYNTHETIC evidence bundle (labelled as such, no real record) through the worker's real path: gateway
              limits, JSON-schema output, deterministic validation and grounding checks;
  db (--db)   the worker's database role: who it is, that it is not a superuser and cannot bypass RLS, that it can claim
              jobs, and that it can read ONLY the severity columns of alerts (never a whole table). Read-only: it does not
              claim, expire or change any job.
Exit status 0 when every check passes, 1 otherwise. Nothing here starts the worker or queues a job.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone

from app.connectors.base import ConnectorError
from app.connectors.inference import ChatMessage
from app.core.config import Settings

NS = 1_000_000_000


def _rate(count, ns) -> float | None:
    return round(count / (ns / NS), 2) if count and ns else None


def synthetic_bundle():
    """A synthetic alert bundle for the structured-output check. Every value is invented and says so."""
    from novrsoc_contracts.v1.common import ResourceRef
    from novrsoc_contracts.v1.nhai import ContextBundle, EvidenceItem, NhaiTask
    now = datetime.now(timezone.utc)
    excerpt = {"rule_id": "5710", "rule_description": "sshd: attempt to login using a non-existent user (DIAGNOSTIC SYNTHETIC)",
               "rule_level": 5, "siem_severity_authoritative": "low", "agent_name": "diagnostic-host", "src_ip": None,
               "observed_at": now.isoformat(), "note": "synthetic record for the NHAI readiness check; not a real event"}
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=uuid.uuid4(), task=NhaiTask.ALERT_EXPLANATION,
                         subject=ResourceRef(type="alert", id=str(uuid.uuid4())), assembled_at=now, assembled_for=uuid.uuid4(),
                         evidence=[EvidenceItem(citation_id="E1", ref=ResourceRef(type="alert", id="diagnostic"), excerpt=json.dumps(excerpt))])


def check_inference(settings: Settings, backend, model: str, out: dict) -> bool:
    from app.ai_gateway.core import Caller, GatewayRejected
    from app.nhai.validate import OutputRejected, output_schema, validate
    from app.nhai.worker import gateway_for, messages_for
    from novrsoc_contracts.v1.ai_gateway import Lane
    ok = True
    try:
        out["ollama"] = {"installed_models": backend.available_models(), "resident": [
            {"name": m.get("name"), "size_mib": round((m.get("size") or 0) / 1048576), "expires_at": m.get("expires_at")}
            for m in backend.loaded()]}
    except ConnectorError as e:
        out["ollama"] = {"error": str(e)}
        return False
    if model not in out["ollama"]["installed_models"]:
        out["ollama"]["problem"] = f"model {model} is not installed (ollama pull {model})"
        return False
    cold = all(r["name"] != model for r in out["ollama"]["resident"])
    try:
        w = backend.warm(model, settings.nhai_inference_timeout_seconds)
        out["load"] = {"was_resident": not cold, "load_seconds": round((w.get("load_duration") or 0) / NS, 2)}
    except ConnectorError as e:
        out["load"] = {"was_resident": not cold, "error": str(e),
                       "hint": "the model did not load within the inference timeout: check free memory (free -m), disk and CPU"}
        return False
    msgs = [ChatMessage("system", "Answer in one short sentence."), ChatMessage("user", "Name one benefit of multi-factor authentication.")]
    try:
        b = backend.bench(model, msgs, 64, settings.nhai_inference_timeout_seconds)
    except ConnectorError as e:
        out["throughput"] = {"error": str(e)}
        return False
    prompt_rate = _rate(b.get("prompt_eval_count"), b.get("prompt_eval_duration"))
    gen_rate = _rate(b.get("eval_count"), b.get("eval_duration"))
    out["throughput"] = {"prompt_tokens": b.get("prompt_eval_count"), "prompt_tokens_per_s": prompt_rate,
                         "generated_tokens": b.get("eval_count"), "generated_tokens_per_s": gen_rate,
                         "total_seconds": round((b.get("total_duration") or 0) / NS, 2)}
    from app.nhai.worker import nhai_budget
    budget = nhai_budget(settings)
    if prompt_rate and gen_rate:
        worst = budget["estimated_input_tokens"] / prompt_rate + settings.nhai_max_output_tokens / gen_rate
        cold_worst = worst + out["load"]["load_seconds"] if cold else worst
        out["projection"] = {"worst_case_seconds_warm": round(worst, 1), "worst_case_seconds_cold": round(cold_worst, 1),
                             "inference_timeout_seconds": settings.nhai_inference_timeout_seconds,
                             "fits_timeout": cold_worst <= settings.nhai_inference_timeout_seconds,
                             "max_output_tokens_that_fit": int(max(0, (settings.nhai_inference_timeout_seconds -
                                                                       budget["estimated_input_tokens"] / prompt_rate) * gen_rate))}
        ok &= out["projection"]["fits_timeout"]
    bundle = synthetic_bundle()
    gateway = gateway_for(settings, backend, model)
    started = time.monotonic()
    try:
        gen = gateway.generate(Caller(user_id=bundle.assembled_for, org_id=bundle.org_id, permissions=frozenset({"nhai:analyze"})),
                               Lane.SECURITY_ANALYSIS, model=model,
                               messages=messages_for(bundle), max_tokens=settings.nhai_max_output_tokens, temperature=0.1,
                               request_id=f"diagnose-{uuid.uuid4().hex[:8]}", json_schema=output_schema())
        res = validate(gen.text, bundle, authoritative_severity="low", model=model, latency_ms=gen.latency_ms)
        out["structured"] = {"valid": True, "seconds": round(time.monotonic() - started, 1), "citations": len(res.citations),
                             "statements_dropped_as_ungrounded": res.unsupported_statements_dropped,
                             "completion_tokens": gen.completion_tokens}
    except GatewayRejected as e:
        out["structured"] = {"valid": False, "seconds": round(time.monotonic() - started, 1), "rejected": e.reason.value}
        ok = False
    except OutputRejected as e:
        out["structured"] = {"valid": False, "seconds": round(time.monotonic() - started, 1), "output_rejected": e.code}
        ok = False
    return ok


def check_db(settings: Settings, out: dict) -> bool:
    from sqlalchemy import create_engine, text
    eng = create_engine(settings.database_url.get_secret_value(), pool_pre_ping=True)
    q = {
        "role": "SELECT current_user",
        "superuser": "SELECT rolsuper FROM pg_roles WHERE rolname = current_user",
        "bypass_rls": "SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user",
        "can_claim": "SELECT has_function_privilege('novrsoc.nhai_claim_job(text, integer)', 'EXECUTE')",
        "can_expire": "SELECT has_function_privilege('novrsoc.nhai_expire_jobs()', 'EXECUTE')",
        "alerts_whole_table": "SELECT has_table_privilege('novrsoc.alerts', 'SELECT')",
        "alerts_severity_column": "SELECT has_column_privilege('novrsoc.alerts', 'severity', 'SELECT')",
        "alerts_raw_column": "SELECT has_column_privilege('novrsoc.alerts', 'raw', 'SELECT')",
        "cases_table": "SELECT has_table_privilege('novrsoc.cases', 'SELECT')",
        "users_table": "SELECT has_table_privilege('novrsoc.users', 'SELECT')",
        "ai_activity_insert": "SELECT has_any_column_privilege('novrsoc.ai_activity', 'INSERT')",
        "tls": "SELECT coalesce((SELECT ssl FROM pg_stat_ssl WHERE pid = pg_backend_pid()), false)",
        "migration": "SELECT has_table_privilege('novrsoc.alembic_version', 'SELECT')",
    }
    try:
        with eng.connect() as c:
            c.execute(text("SET TRANSACTION READ ONLY"))
            got = {k: c.execute(text(v)).scalar() for k, v in q.items()}
    except Exception as e:  # noqa: BLE001  (report, never raise: this is a diagnosis)
        out["db"] = {"error": type(e).__name__, "detail": str(e).splitlines()[0][:300]}
        return False
    finally:
        eng.dispose()
    expected = {"superuser": False, "bypass_rls": False, "can_claim": True, "can_expire": True, "alerts_whole_table": False,
                "alerts_severity_column": True, "alerts_raw_column": False, "cases_table": False, "users_table": False,
                "ai_activity_insert": True}
    problems = [f"{k}: expected {v}, got {got[k]}" for k, v in expected.items() if got[k] != v]
    if got["role"] != "novrsoc_nhai":
        problems.append(f"connected as {got['role']}, not the dedicated role novrsoc_nhai")
    if settings.env == "production" and not got["tls"]:
        problems.append("the connection is not TLS-encrypted")
    out["db"] = {**got, "problems": problems}
    return not problems


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.nhai.diagnose", description="NHAI readiness diagnostics (Server 1)")
    ap.add_argument("--db", action="store_true", help="also check the worker's database role (read-only)")
    ap.add_argument("--skip-inference", action="store_true", help="configuration and database checks only")
    ap.add_argument("--json", action="store_true", help="JSON only")
    args = ap.parse_args(argv)
    settings = Settings()  # type: ignore[call-arg]
    from app.nhai.worker import backend_for, nhai_budget
    out: dict = {"checked_at": datetime.now(timezone.utc).isoformat(), "host": os.uname().nodename if hasattr(os, "uname") else "",
                 "config": {"backend": settings.nhai_backend, "model": settings.nhai_model, "num_ctx": settings.nhai_num_ctx,
                            "inference_timeout_seconds": settings.nhai_inference_timeout_seconds,
                            "job_deadline_seconds": settings.nhai_job_deadline_seconds, "budget": nhai_budget(settings)}}
    ok = out["config"]["budget"]["fits"]
    if not args.skip_inference:
        if settings.nhai_backend != "ollama":
            out["inference"] = "skipped: NOVRSOC_NHAI_BACKEND is not ollama"
        else:
            try:
                backend, model = backend_for(settings)
            except SystemExit as e:
                out["inference"] = {"error": str(e)}
                ok = False
            else:
                ok &= check_inference(settings, backend, model, out)
    if args.db:
        ok &= check_db(settings, out)
    out["ready"] = bool(ok)
    print(json.dumps(out, indent=None if args.json else 2, default=str))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
