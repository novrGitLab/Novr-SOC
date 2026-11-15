"""Novr Human-Assisted Intelligence (NHAI) API (Phase 5, workstream F).

The API never calls the model. It assembles the context bundle (server-side, the active organization only,
redacted, bounded), queues an asynchronous job, and serves jobs, draft results and human reviews. The NHAI worker
(app/nhai/worker.py) runs inference and deterministic validation. A result is a DRAFT until a human with
nhai:review accepts or rejects it; nothing is ever executed from a result.

Consolidation: the same worker, gateway and validator serve VMS finding explanations, asset summaries and NovrChat
answers. Every request, result, failure, recommendation and review is written to ai_activity (SOAR activity centre).
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import activity
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.nhai.evidence import alert_bundle, asset_bundle, finding_bundle
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.common import ActorRef, ResourceRef
from novrsoc_contracts.v1.nhai import (AlertExplanationRequest, AssetSummaryRequest, ContextBundle, FindingExplanationRequest, HumanReview,
                                       NhaiJob, NhaiJobList, NhaiResult, NhaiReviewRequest)

MODULE = ModuleInfo(name="nhai", workstream="F", prefix="/api/v1/nhai",
                    summary="Novr Human-Assisted Intelligence: asynchronous, evidence-grounded drafts for human review")
router = APIRouter(prefix="/api/v1/nhai", tags=["nhai"], responses=ERRORS)

_COLS = """id, task, subject_type, subject_id, status, requested_by, requested_label, queued_at, started_at, finished_at,
           deadline_at, attempts, error_code, result, review_decision, reviewer_id, reviewer_label, review_note, reviewed_at"""


def _job(r) -> NhaiJob:
    result = None
    if r.result is not None:
        result = NhaiResult.model_validate(r.result)
        if r.review_decision is not None:
            review = HumanReview(reviewer=ActorRef(type="user", id=r.reviewer_id, label=r.reviewer_label or ""),
                                 decision=r.review_decision, note=r.review_note, reviewed_at=r.reviewed_at)
            result = result.model_copy(update={"review": review, "status": "rejected" if r.review_decision == "reject" else "accepted"})
    return NhaiJob(id=r.id, task=r.task, subject=ResourceRef(type=r.subject_type, id=r.subject_id), status=r.status,
                   requested_by=ActorRef(type="user", id=r.requested_by, label=r.requested_label), queued_at=r.queued_at,
                   started_at=r.started_at, finished_at=r.finished_at, deadline_at=r.deadline_at, attempts=r.attempts,
                   error_code=r.error_code, result=result)


def _get(conn: Connection, job_id: uuid.UUID):
    r = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.nhai_jobs WHERE id = :id"), {"id": job_id}).first()
    if r is None:
        raise not_found("NHAI job not found")
    return r


MODULE_OF = {"alert": "soc", "vms_finding": "vms", "asset": "assets", "chat_message": "chat"}


def queue_job(conn: Connection, p: Principal, settings: Settings, request: Request, bundle: ContextBundle):
    """Queue one NHAI job for the bundle's subject (an identical queued/running job is returned instead).
    Returns (job row, created)."""
    task, stype, sid = bundle.task.value, bundle.subject.type, bundle.subject.id
    existing = conn.execute(text(f"""SELECT {_COLS} FROM novrsoc.nhai_jobs WHERE task = :t AND subject_type = :st
                                     AND subject_id = :s AND status IN ('queued', 'running')"""), {"t": task, "st": stype, "s": sid}).first()
    if existing is not None:
        return existing, False
    deadline = datetime.now(timezone.utc) + timedelta(seconds=settings.nhai_job_deadline_seconds)
    r = conn.execute(text(f"""INSERT INTO novrsoc.nhai_jobs (org_id, task, subject_type, subject_id, requested_by, requested_label,
                                                              deadline_at, bundle)
                              VALUES (:o, :t, :st, :s, :u, :l, :d, CAST(:b AS jsonb)) RETURNING {_COLS}"""),
                     {"o": p.org_id, "t": task, "st": stype, "s": sid, "u": p.user_id, "l": p.email, "d": deadline,
                      "b": bundle.model_dump_json()}).one()
    activity.ai(conn, "analysis_requested", MODULE_OF.get(stype, "nhai"), task=task, subject_type=stype, subject_id=sid,
                actor_id=p.user_id, actor_label=p.email, outcome="pending", nhai_job_id=r.id,
                summary=f"NHAI {task.replace('_', ' ')} requested ({len(bundle.evidence)} evidence items)",
                details={"evidence_items": len(bundle.evidence)})
    audit.record("NHAI_JOB_QUEUED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="nhai_job",
                 resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"task": task, "subject": sid, "evidence_items": len(bundle.evidence)})
    return r, True


def _require_backend(settings: Settings) -> None:
    if settings.nhai_backend == "unconfigured":
        raise ApiError(503, "integration_unconfigured", "NHAI inference is not configured for this installation")


def _answer(row, created: bool):
    return _job(row) if created else JSONResponse(_job(row).model_dump(mode="json"), status_code=200)


@router.post("/alert-explanations", response_model=NhaiJob, status_code=202,
             summary="Queue an evidence-grounded explanation of one alert (asynchronous)")
def request_alert_explanation(body: AlertExplanationRequest, request: Request, p: Principal = Depends(require("nhai:analyze")),
                              conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)):
    _require_backend(settings)
    bundle = alert_bundle(conn, p.org_id, p.user_id, body.alert_id, max_chars=settings.nhai_max_prompt_chars)
    return _answer(*queue_job(conn, p, settings, request, bundle))


@router.post("/finding-explanations", response_model=NhaiJob, status_code=202,
             summary="Queue an explanation of one VMS finding, with its CVE intelligence and asset (asynchronous)")
def request_finding_explanation(body: FindingExplanationRequest, request: Request, p: Principal = Depends(require("nhai:analyze")),
                                conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)):
    _require_backend(settings)
    if not p.has("vms:read"):
        raise ApiError(403, "forbidden", "Insufficient permissions", {"required": "vms:read"})
    bundle = finding_bundle(conn, p.org_id, p.user_id, body.finding_id, max_chars=settings.nhai_max_prompt_chars)
    return _answer(*queue_job(conn, p, settings, request, bundle))


@router.post("/asset-summaries", response_model=NhaiJob, status_code=202,
             summary="Queue an evidence-grounded summary of one asset across SIEM, VMS and intelligence (asynchronous)")
def request_asset_summary(body: AssetSummaryRequest, request: Request, p: Principal = Depends(require("nhai:analyze")),
                          conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)):
    _require_backend(settings)
    if not p.has("assets:read"):
        raise ApiError(403, "forbidden", "Insufficient permissions", {"required": "assets:read"})
    bundle = asset_bundle(conn, p.org_id, p.user_id, body.asset_id, max_chars=settings.nhai_max_prompt_chars)
    return _answer(*queue_job(conn, p, settings, request, bundle))


def jobs_for_subject(conn: Connection, subject_type: str, subject_id: str, limit: int = 5) -> list[NhaiJob]:
    rows = conn.execute(text(f"""SELECT {_COLS} FROM novrsoc.nhai_jobs WHERE subject_type = :t AND subject_id = :s
                                 ORDER BY queued_at DESC LIMIT :n"""), {"t": subject_type, "s": subject_id, "n": limit}).all()
    return [_job(r) for r in rows]


@router.get("/jobs", response_model=NhaiJobList, summary="NHAI jobs of the active organization (newest first)")
def list_jobs(subject_id: str | None = Query(None, max_length=200), limit: int = Query(50, ge=1, le=200),
              p: Principal = Depends(require("nhai:analyze")), conn: Connection = Depends(request_connection)) -> NhaiJobList:
    rows = conn.execute(text(f"""SELECT {_COLS} FROM novrsoc.nhai_jobs WHERE (CAST(:s AS text) IS NULL OR subject_id = :s)
                                 ORDER BY queued_at DESC LIMIT :n"""), {"s": subject_id, "n": limit}).all()
    return NhaiJobList(items=[_job(r) for r in rows])


@router.get("/jobs/{job_id}", response_model=NhaiJob, summary="One NHAI job, with its draft result when finished")
def get_job(job_id: uuid.UUID, p: Principal = Depends(require("nhai:analyze")), conn: Connection = Depends(request_connection)) -> NhaiJob:
    return _job(_get(conn, job_id))


@router.post("/jobs/{job_id}/review", response_model=NhaiJob, summary="Accept or reject a draft (human review)")
def review_job(job_id: uuid.UUID, body: NhaiReviewRequest, request: Request, p: Principal = Depends(require("nhai:review")),
               conn: Connection = Depends(request_connection)) -> NhaiJob:
    r = _get(conn, job_id)
    if r.status != "succeeded":
        raise ApiError(409, "conflict", "Only a finished draft can be reviewed")
    if r.review_decision is not None:
        raise ApiError(409, "conflict", "This draft was already reviewed")
    if body.decision == "reject" and len(body.note.strip()) < 3:
        raise ApiError(422, "validation_error", "A rejection needs a note")
    r = conn.execute(text(f"""UPDATE novrsoc.nhai_jobs SET review_decision = :d, reviewer_id = :u, reviewer_label = :l,
                              review_note = :n, reviewed_at = now() WHERE id = :id AND review_decision IS NULL RETURNING {_COLS}"""),
                     {"d": body.decision, "u": p.user_id, "l": p.email, "n": body.note, "id": job_id}).one()
    job_row = conn.execute(text("SELECT task, subject_type, subject_id FROM novrsoc.nhai_jobs WHERE id = :id"), {"id": job_id}).one()
    activity.ai(conn, "review", MODULE_OF.get(job_row.subject_type, "nhai"), task=job_row.task, subject_type=job_row.subject_type,
                subject_id=job_row.subject_id, actor_id=p.user_id, actor_label=p.email,
                outcome="success" if body.decision != "reject" else "refused", nhai_job_id=job_id,
                summary=f"Human review: {body.decision}" + (f" ({body.note[:200]})" if body.note else ""))
    audit.record("NHAI_RESULT_REVIEWED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="nhai_job", resource_id=str(job_id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"decision": body.decision})
    return _job(r)
