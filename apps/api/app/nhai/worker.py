"""NHAI worker (Phase 5, workstream F): runs queued NHAI jobs, one at a time, outside the API process.

  python -m app.nhai.worker            loop (systemd on Server 1, next to Ollama)
  python -m app.nhai.worker --once     process at most one job and exit

Per job: claim (novrsoc.nhai_claim_job, bounded lease) -> switch to the job's organization context (RLS applies to
every further statement) -> prompt from the stored, redacted bundle -> AI Gateway (security lane: model allow-list,
input bound, single concurrency, timeout) -> deterministic validation (app.nhai.validate) -> store the draft result.
Transient failures (timeout, backend unavailable) re-queue the job while attempts remain; invalid or ungrounded model
output fails it with a reason. Nothing the worker does triggers a response action.
Database: the dedicated least-privilege role novrsoc_nhai (migration 0016): the claim/expire functions, a few columns of
nhai_jobs, the severity columns of alerts and findings, and INSERT into ai_activity / audit_events. Every statement after
the claim runs in the job's organization context (RLS).
Context window: the whole prompt plus the answer must fit nhai_num_ctx (checked at start by nhai_budget): Ollama silently
drops the BEGINNING of an over-long prompt, which is where the rules are.
"""
from __future__ import annotations

import json
import logging
import math
import os
import signal
import socket
import sys
import time
import uuid

from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.ai_gateway.core import Caller, Gateway, GatewayRejected
from app.audit import activity
from app.audit import service as audit
from app.connectors.base import ConnectorError
from app.connectors.inference import ChatMessage, OllamaBackend, TestInferenceAdapter, ollama_worker_endpoint
from app.core.config import Settings
from app.db import session as db_session
from app.nhai.validate import OutputRejected, output_schema, validate
from novrsoc_contracts.v1.ai_gateway import Lane, LanePolicy
from novrsoc_contracts.v1.nhai import NHAI_NAME, ContextBundle

log = logging.getLogger("novrsoc.nhai.worker")

SYSTEM_PROMPT = f"""You are {NHAI_NAME} (NHAI), assisting a human security analyst. You explain; you never act.
Rules:
- Use ONLY the evidence items provided. Cite them by id (E1, E2, ...) in every statement, recommendation and the
  severity assessment. Do not invent IP addresses, domains, URLs, hashes, CVEs, hosts or users.
- The NovrSIEM severity in E1 is authoritative. You may propose a different severity, with a rationale and citations,
  but say how uncertain you are. If evidence is thin, say so.
- List the evidence that is missing and would change your assessment (missing_evidence). Be specific.
- Recommendations are suggestions for a human. requires_human_approval is always true.
- Answer with ONE JSON object that matches the given schema. No other text."""

RETRYABLE = {"timeout", "backend_unavailable", "concurrency_limit"}


CHARS_PER_TOKEN = 3.0   # conservative for JSON with ids and timestamps (English prose is ~4)


def nhai_budget(settings: Settings) -> dict:
    """Worst-case context use: the largest input the gateway admits plus the longest answer, against nhai_num_ctx."""
    input_chars = settings.nhai_max_prompt_chars + 4000   # the gateway's max_input_chars (gateway_for)
    input_tokens = math.ceil(input_chars / CHARS_PER_TOKEN)
    need = input_tokens + settings.nhai_max_output_tokens
    return {"max_input_chars": input_chars, "estimated_input_tokens": input_tokens, "max_output_tokens": settings.nhai_max_output_tokens,
            "needed_tokens": need, "num_ctx": settings.nhai_num_ctx, "fits": need <= settings.nhai_num_ctx,
            "system_prompt_chars": len(SYSTEM_PROMPT), "output_schema_chars": len(json.dumps(output_schema()))}


def check_budget(settings: Settings) -> None:
    b = nhai_budget(settings)
    if not b["fits"]:
        raise SystemExit(f"NHAI context budget does not fit: up to {b['needed_tokens']} tokens (input {b['estimated_input_tokens']} + "
                         f"answer {b['max_output_tokens']}) but NOVRSOC_NHAI_NUM_CTX={b['num_ctx']}. Raise NOVRSOC_NHAI_NUM_CTX or lower "
                         "NOVRSOC_NHAI_MAX_PROMPT_CHARS / NOVRSOC_NHAI_MAX_OUTPUT_TOKENS; otherwise Ollama drops the start of the prompt.")


def backend_for(settings: Settings):
    if settings.nhai_backend == "test_adapter":
        return TestInferenceAdapter(), TestInferenceAdapter.MODEL
    if settings.nhai_backend == "ollama":
        check_budget(settings)
        ep, token = ollama_worker_endpoint(os.environ, settings.env)
        return OllamaBackend(ep, token, num_ctx=settings.nhai_num_ctx), settings.nhai_model
    raise SystemExit("NOVRSOC_NHAI_BACKEND is unconfigured: the NHAI worker has nothing to run against")


def gateway_for(settings: Settings, backend, model: str) -> Gateway:
    policy = LanePolicy(lane=Lane.SECURITY_ANALYSIS, allowed_models=[model], timeout_seconds=settings.nhai_inference_timeout_seconds,
                        max_input_chars=settings.nhai_max_prompt_chars + 4000, max_output_tokens=settings.nhai_max_output_tokens,
                        max_concurrency=1)
    return Gateway(backend, policies={Lane.SECURITY_ANALYSIS: policy}, record_usage=lambda e: log.info(
        "inference outcome=%s model=%s latency_ms=%s tokens=%s/%s", e.outcome, e.model, e.latency_ms, e.prompt_tokens, e.completion_tokens))


def messages_for(bundle: ContextBundle) -> list[ChatMessage]:
    payload = {"task": bundle.task.value, "subject": bundle.subject.model_dump(),
               "evidence": [{"id": e.citation_id, "citation_id": e.citation_id, "type": e.ref.type, "excerpt": e.excerpt}
                            for e in bundle.evidence],
               "output_schema": output_schema()}
    return [ChatMessage("system", SYSTEM_PROMPT), ChatMessage("user", json.dumps(payload))]


def _finish(conn, job_id, worker_id, status, *, error=None, result=None):
    return conn.execute(text("""UPDATE novrsoc.nhai_jobs SET status = :s, error_code = :e, result = CAST(:r AS jsonb),
                                finished_at = CASE WHEN :s IN ('queued') THEN NULL ELSE now() END,
                                lease_until = NULL, worker_id = CASE WHEN :s = 'queued' THEN NULL ELSE worker_id END
                                WHERE id = :id AND worker_id = :w AND status = 'running' RETURNING id"""),
                        {"s": status, "e": error, "r": result, "id": job_id, "w": worker_id}).first()


def run_once(engine: Engine, settings: Settings, gateway: Gateway, model: str, worker_id: str) -> str | None:
    """Process at most one job. Returns its final status, or None when no job was queued."""
    with engine.begin() as conn:
        conn.execute(text("SELECT novrsoc.nhai_expire_jobs()"))
        claimed = conn.execute(text("SELECT job_id, org_id FROM novrsoc.nhai_claim_job(:w, :l)"),
                               {"w": worker_id, "l": settings.nhai_inference_timeout_seconds + 120}).first()
    if claimed is None:
        return None
    job_id, org_id = claimed
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org_id)})
        # Consolidation: the authoritative severity exists for alerts (Wazuh) and VMS findings (scanner); assets and
        # NovrChat answers have none, so the model's severity, if any, stays advisory.
        job = conn.execute(text("""SELECT j.bundle, j.requested_by, j.attempts, j.max_attempts, j.task, j.subject_type, j.subject_id,
              CASE j.subject_type
                WHEN 'alert' THEN (SELECT a.severity FROM novrsoc.alerts a WHERE a.id = CAST(j.subject_id AS uuid))
                WHEN 'vms_finding' THEN (SELECT CASE f.severity WHEN 'info' THEN 'low' ELSE f.severity END
                                         FROM novrsoc.vms_findings f WHERE f.id = CAST(j.subject_id AS uuid))
              END AS severity,
              CASE j.subject_type
                WHEN 'alert' THEN EXISTS (SELECT 1 FROM novrsoc.alerts a WHERE a.id = CAST(j.subject_id AS uuid))
                WHEN 'vms_finding' THEN EXISTS (SELECT 1 FROM novrsoc.vms_findings f WHERE f.id = CAST(j.subject_id AS uuid))
                WHEN 'asset' THEN EXISTS (SELECT 1 FROM novrsoc.assets x WHERE x.id = CAST(j.subject_id AS uuid))
                WHEN 'case' THEN EXISTS (SELECT 1 FROM novrsoc.cases x WHERE x.id = CAST(j.subject_id AS uuid))
                WHEN 'chat_message' THEN true
                WHEN 'organization' THEN j.subject_id = j.org_id::text
                WHEN 'platform' THEN j.subject_id = j.org_id::text
                ELSE false
              END AS present
            FROM novrsoc.nhai_jobs j WHERE j.id = :id"""), {"id": job_id}).one()
    try:
        bundle = ContextBundle.model_validate(job.bundle)
    except ValidationError:
        bundle = None
    if bundle is None:  # a malformed stored bundle fails its job; it never stops the worker
        status, error, result = "failed", "invalid_bundle", None
    elif bundle.org_id != org_id:  # defence in depth: a bundle never crosses organizations
        status, error, result = "failed", "scope_violation", None
    elif not job.present:
        status, error, result = "failed", "subject_missing", None
    else:
        caller = Caller(user_id=job.requested_by, org_id=org_id, permissions=frozenset({"nhai:analyze"}))
        status, error, result = "failed", None, None
        try:
            gen = gateway.generate(caller, Lane.SECURITY_ANALYSIS, model=model, messages=messages_for(bundle),
                                   max_tokens=settings.nhai_max_output_tokens, temperature=0.1, request_id=str(job_id),
                                   json_schema=output_schema())
            res = validate(gen.text, bundle, authoritative_severity=job.severity, model=model, latency_ms=gen.latency_ms)
            status, result = "succeeded", res.model_dump_json()
        except GatewayRejected as r:
            error = r.reason.value
            if error in RETRYABLE and job.attempts < job.max_attempts:
                status = "queued"
            elif error == "timeout":
                status = "timed_out"
        except OutputRejected as r:
            error = r.code
        except ConnectorError:
            error = "backend_unavailable"
            status = "queued" if job.attempts < job.max_attempts else "failed"
    with engine.begin() as conn:
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org_id)})
        done = _finish(conn, job_id, worker_id, status, error=error, result=result)
        if done is not None and status != "queued":
            _record_activity(conn, job, job_id, worker_id, model, status, error, result)
    if done is not None and status != "queued":
        audit.record("NHAI_JOB_FINISHED", "success" if status == "succeeded" else "failure", org_id=org_id, actor_type="system",
                     actor_label=f"nhai-worker:{worker_id}", resource_type="nhai_job", resource_id=str(job_id),
                     details={"status": status, "error_code": error, "model": model})
    log.info("nhai job=%s status=%s error=%s", job_id, status, error)
    return status


def _record_activity(conn, job, job_id, worker_id, model, status, error, result) -> None:
    """AI activity for the SOAR activity centre: the outcome, and every recommendation (a proposed action when it names one).
    None of these executes anything."""
    common = dict(task=job.task, subject_type=job.subject_type, subject_id=job.subject_id, actor_type="system",
                  actor_label=f"nhai-worker:{worker_id}"[:200], model=model, nhai_job_id=job_id)
    module = {"alert": "soc", "vms_finding": "vms", "asset": "assets", "chat_message": "chat", "case": "soc",
              "organization": "nhai", "platform": "nhai"}.get(job.subject_type, "nhai")
    if status != "succeeded":
        activity.ai(conn, "analysis_failed", module, outcome="failure", summary=f"NHAI {job.task} ended {status} ({error})",
                    details={"status": status, "error_code": error}, **common)
        return
    res = json.loads(result)
    activity.ai(conn, "analysis_completed", module, outcome="success", summary=res.get("summary", "")[:500],
                details={"confidence": res.get("confidence"), "dropped": res.get("unsupported_statements_dropped", 0),
                         "citations": len(res.get("citations", []))}, **common)
    for r in res.get("recommendations", []):
        kind = "proposed_action" if r.get("action") else "recommendation"
        activity.ai(conn, kind, module, outcome="pending", summary=r.get("text", "")[:500],
                    details={"action": r.get("action"), "requires_human_approval": True, "executes_automatically": False,
                             "citations": r.get("citation_ids", [])}, **common)


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","event":"%(message)s"}')
    settings = Settings()  # type: ignore[call-arg]
    backend, model = backend_for(settings)
    gateway = gateway_for(settings, backend, model)
    engine = db_session.init_engine(settings.database_url.get_secret_value())  # also used by audit.record
    worker_id = f"{socket.gethostname()[:40]}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
    if "--once" in argv:
        run_once(engine, settings, gateway, model, worker_id)
        return 0
    stopping = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__("flag", True))
    stats = {"done": 0, "failures": 0, "last_beat": 0.0}
    while not stopping["flag"]:
        try:
            status = run_once(engine, settings, gateway, model, worker_id)
            if status is not None:
                stats["done"] += 1
                stats["failures"] = 0 if status == "succeeded" else stats["failures"] + (status in ("failed", "timed_out"))
            if time.time() - stats["last_beat"] >= 60:
                heartbeat(engine, worker_id, model, stats)
            if status is None:
                time.sleep(5)
        except Exception:  # one bad job must not stop the worker; the lease expiry re-queues it
            log.exception("nhai worker cycle failed")
            stats["failures"] += 1
            time.sleep(10)
    return 0


def heartbeat(engine: Engine, worker_id: str, model: str, stats: dict) -> None:
    """Liveness for NHAI readiness (migration 0021: the worker can write only its own row). Degraded after three
    consecutive failed jobs; the detail names the model so the readiness view shows what is actually running."""
    state = "degraded" if stats["failures"] >= 3 else "ok"
    detail = f"model={model}; jobs since start={stats['done']}; consecutive failures={stats['failures']}"
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT novrsoc.nhai_heartbeat(:i, :s, :d)"), {"i": worker_id, "s": state, "d": detail})
        stats["last_beat"] = time.time()
    except Exception:  # a missing heartbeat shows as "not reporting"; it never stops the worker
        log.exception("nhai heartbeat failed")


if __name__ == "__main__":
    raise SystemExit(main())
