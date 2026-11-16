"""SOC foundation (Phase 4; ongoing owner: workstream A): stored alerts, alert ingest, cases and case timelines.

No automatic containment and no SOAR execution exist here. Case creation reuses soar.AlertToCasePromotion.

Ingest acknowledgement semantics (Phase 5): a 200 answer means every alert in the batch is durably stored,
counted as a duplicate, or quarantined (accepted + duplicates + quarantined = batch size), and the batch receipt is
recorded in the same transaction. A repeated batch_id from the same identity with the same alert ids returns the
stored acknowledgement (`replayed: true`) without ingesting again; any other reuse of a batch_id is refused (409).
Any non-200 answer means nothing was acknowledged and the forwarder must retry the same batch.
With NOVRSOC_WAZUH_MODE=live the agent groups are read from the Wazuh manager (authoritative); the groups in the
payload are ignored. If the manager cannot be asked, the batch is refused with 503 (not acknowledged).
"""
from __future__ import annotations

import hashlib
import uuid
from datetime import datetime, timezone
from typing import Literal

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, ServicePrincipal, client_ip, current_service, require
from app.connectors import registry
from app.connectors.base import ConnectorError
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, forbidden, not_found
from app.core.redact import FAILED, redact_value
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.modules.soc.service import ingest_alerts
from app.secops import sla
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.soar import AlertToCasePromotion, CasePromotionResult
from novrsoc_contracts.v1.endpoints import ConnectorState
from novrsoc_contracts.v1.soc import (AlertDetail, AlertEvidence, AlertIngestBatch, AlertIngestResult, AlertList, AlertStatusUpdate,
                                      AssignmentRequest,
                                      CaseDetail, CaseEvent, CaseList, CaseNoteCreate, CaseStatusUpdate, CaseSummary,
                                      StoredAlert)

MODULE = ModuleInfo(name="soc", workstream="A", prefix="/api/v1/soc",
                    summary="Stored alerts, alert ingest, cases and case timelines")
router = APIRouter(prefix="/api/v1/soc", tags=["soc"], responses=ERRORS)

_ALERT_COLS = """a.id, a.source, a.external_id, a.rule_id, a.rule_level, a.rule_description, a.severity, a.agent_id,
    a.agent_name, host(a.src_ip) AS src_ip, a.mitre_techniques, a.observed_at, a.received_at, a.status,
    (SELECT ca.case_id FROM novrsoc.case_alerts ca WHERE ca.alert_id = a.id ORDER BY ca.linked_at DESC LIMIT 1) AS case_id,
    a.asset_id, a.assignee_id, (SELECT u.email::text FROM novrsoc.users u WHERE u.id = a.assignee_id) AS assignee_label,
    a.log_source_id, (SELECT s.name FROM novrsoc.log_sources s WHERE s.id = a.log_source_id) AS log_source_name"""
_CASE_COLS = """c.id, c.number, c.title, c.severity, c.status, c.source, c.created_at, c.updated_at, c.closed_at,
    (SELECT count(*) FROM novrsoc.case_alerts ca WHERE ca.case_id = c.id) AS alert_count,
    c.assignee_id, (SELECT u.email::text FROM novrsoc.users u WHERE u.id = c.assignee_id) AS assignee_label,
    c.sla_response_due_at, c.sla_resolution_due_at, c.first_response_at, c.resolved_at, c.sla_policy_snapshot"""
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}


def _alert(r) -> StoredAlert:
    m = dict(r._mapping)
    m["mitre_techniques"] = list(m["mitre_techniques"] or [])
    return StoredAlert(**m)


def _case(r) -> CaseSummary:
    m = dict(r._mapping)
    number = m.pop("number")
    m.pop("closed_at", None)
    m.pop("sla_policy_snapshot", None)
    return CaseSummary(reference=f"CASE-{number:06d}", sla_state=sla.overall(*sla.case_states(r)), **m)


def _member(conn: Connection, p: Principal, user_id: uuid.UUID) -> str:
    """The assignee must hold a staff membership in the active organization; returns their email."""
    r = conn.execute(text("""SELECT u.email::text FROM novrsoc.memberships m JOIN novrsoc.users u ON u.id = m.user_id
                             WHERE m.org_id = :o AND m.user_id = :u AND u.status = 'active'
                               AND m.role_key IN ('super_admin', 'soc_manager', 'analyst')"""), {"o": p.org_id, "u": user_id}).scalar()
    if r is None:
        raise ApiError(422, "validation_error", "The assignee must be an active analyst or manager of this organization")
    return r


def create_case_for(conn: Connection, p: Principal, *, title: str, severity: str, source: str, source_id: str,
                    summary: str) -> tuple[uuid.UUID, bool]:
    """Create (or find) a case for a non-alert source: brand protection, email security, VMS. Same dedupe as alerts."""
    existing = conn.execute(text("SELECT id FROM novrsoc.cases WHERE source = :s AND source_id = :sid"),
                            {"s": source, "sid": source_id}).scalar()
    if existing:
        return existing, False
    r = conn.execute(text("""INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id, created_by)
                             VALUES (:o, :t, :sev, :s, :sid, :u) RETURNING id, created_at"""),
                     {"o": p.org_id, "t": title[:200], "sev": severity, "s": source, "sid": source_id, "u": p.user_id}).one()
    sla.apply_policy(conn, r.id, severity, r.created_at)
    _event(conn, p, r.id, "created", summary[:8000])
    return r.id, True


def _event(conn: Connection, p: Principal, case_id: uuid.UUID, kind: str, body: str = "", details: str = "{}") -> None:
    conn.execute(text("""INSERT INTO novrsoc.case_events (case_id, org_id, actor_id, actor_label, kind, body, details)
                         VALUES (:c, :o, :a, :l, :k, :b, CAST(:d AS jsonb))"""),
                 {"c": case_id, "o": p.org_id, "a": p.user_id, "l": p.email, "k": kind, "b": body, "d": details})


# ---------------------------------------------------------------- ingest (forwarder machine identity)
@router.post("/ingest/alerts", response_model=AlertIngestResult, summary="Forwarder: deliver Wazuh alerts (machine identity)")
def ingest(body: AlertIngestBatch, request: Request, s: ServicePrincipal = Depends(current_service),
           conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> AlertIngestResult:
    platform = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :id"), {"id": s.org_id}).scalar()
    if s.kind != "forwarder" or "alerts:ingest" not in s.scopes or platform != "platform":
        audit.record("ALERT_INGEST_REFUSED", "denied", org_id=s.org_id, actor_type="service", actor_id=s.identity_id,
                     resource_type="service_identity", resource_id=str(s.identity_id),
                     request_id=request.state.request_id, ip=client_ip(request))
        raise forbidden("Only a platform forwarder identity with the alerts:ingest scope may deliver alerts")
    digest = hashlib.sha256("\n".join(a.id for a in body.alerts).encode()).hexdigest()
    prior = _receipt(conn, body.batch_id)
    if prior is not None:
        return _replay(prior, body, s, digest, request)
    alerts = _authoritative_groups(body.alerts, settings)
    c = ingest_alerts(conn, alerts, source="wazuh")
    recorded = conn.execute(text("SELECT novrsoc.ingest_batch_record(:b, :i, :h, :n, :a, :d, :q)"),
                            {"b": body.batch_id, "i": s.identity_id, "h": digest, "n": len(alerts),
                             "a": c.accepted, "d": c.duplicates, "q": c.quarantined}).scalar()
    if not recorded:  # a concurrent delivery of the same batch_id won the race: answer with its receipt
        return _replay(_receipt(conn, body.batch_id), body, s, digest, request)
    audit.record("ALERT_BATCH_INGESTED", "success", org_id=s.org_id, actor_type="service", actor_id=s.identity_id,
                 resource_type="ingest_batch", resource_id=body.batch_id, request_id=request.state.request_id,
                 ip=client_ip(request), details={"accepted": c.accepted, "duplicates": c.duplicates, "quarantined": c.quarantined})
    return AlertIngestResult(batch_id=body.batch_id, accepted=c.accepted, duplicates=c.duplicates, quarantined=c.quarantined)


def _receipt(conn: Connection, batch_id: str):
    return conn.execute(text("SELECT * FROM novrsoc.ingest_batch_lookup(:b)"), {"b": batch_id}).first()


def _replay(prior, body: AlertIngestBatch, s: ServicePrincipal, digest: str, request: Request) -> AlertIngestResult:
    if prior.identity_id != s.identity_id or prior.content_sha256 != digest:
        audit.record("ALERT_BATCH_CONFLICT", "denied", org_id=s.org_id, actor_type="service", actor_id=s.identity_id,
                     resource_type="ingest_batch", resource_id=body.batch_id, request_id=request.state.request_id, ip=client_ip(request))
        raise ApiError(409, "conflict", "This batch_id was already acknowledged for different content or another identity")
    return AlertIngestResult(batch_id=body.batch_id, accepted=prior.accepted, duplicates=prior.duplicates,
                             quarantined=prior.quarantined, replayed=True)


def _authoritative_groups(alerts, settings: Settings):
    """In live mode the Wazuh manager, not the payload, says which groups an agent is in."""
    if settings.wazuh_mode != "live":
        return list(alerts)
    live = registry.wazuh(settings)
    if live is None:
        raise ApiError(503, "integration_unconfigured", "Live Wazuh mode is selected but the manager is not configured")
    out = []
    try:
        for a in alerts:
            groups = live.agent_groups(a.agent.id) or ()
            out.append(a.model_copy(update={"agent": a.agent.model_copy(update={"groups": list(groups)})}))
    except ConnectorError as e:
        raise ApiError(503, "integration_unavailable", "Agent groups could not be verified with the Wazuh manager: " + str(e)[:200])
    return out


# ---------------------------------------------------------------- alerts
@router.get("/alerts", response_model=AlertList, summary="Stored alerts of the active organization (newest first)")
def list_alerts(status: Literal["new", "acknowledged", "in_progress", "closed"] | None = None,
                severity: Literal["critical", "high", "medium", "low"] | None = None,
                limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000),
                q: str | None = Query(None, max_length=200), assigned: Literal["me", "unassigned"] | None = None,
                asset_id: uuid.UUID | None = None, log_source_id: uuid.UUID | None = None,
                p: Principal = Depends(require("alerts:read")), conn: Connection = Depends(request_connection)) -> AlertList:
    where, params = ["true"], {"limit": limit, "offset": offset}
    if status:
        where.append("a.status = :status"); params["status"] = status
    if severity:
        where.append("a.severity = :severity"); params["severity"] = severity
    if q:
        where.append("(a.rule_description ILIKE :q OR a.agent_name ILIKE :q OR a.rule_id = :qx OR host(a.src_ip) = :qx)")
        params["q"], params["qx"] = f"%{q.strip()}%", q.strip()
    if assigned == "me":
        where.append("a.assignee_id = :me"); params["me"] = p.user_id
    elif assigned == "unassigned":
        where.append("a.assignee_id IS NULL")
    if asset_id:
        where.append("a.asset_id = :asset"); params["asset"] = asset_id
    if log_source_id:
        where.append("a.log_source_id = :src"); params["src"] = log_source_id
    cond = " AND ".join(where)
    total = conn.execute(text(f"SELECT count(*) FROM novrsoc.alerts a WHERE {cond}"), params).scalar()
    rows = conn.execute(text(f"SELECT {_ALERT_COLS} FROM novrsoc.alerts a WHERE {cond} ORDER BY a.observed_at DESC, a.id LIMIT :limit OFFSET :offset"), params).all()
    return AlertList(items=[_alert(r) for r in rows], total=total, limit=limit, offset=offset)


def _alert_detail(conn: Connection, alert_id: uuid.UUID) -> AlertDetail:
    r = conn.execute(text(f"SELECT {_ALERT_COLS}, a.agent_groups, a.status_reason, a.raw FROM novrsoc.alerts a WHERE a.id = :id"),
                     {"id": alert_id}).first()
    if not r:
        raise not_found("Alert not found")
    m = dict(r._mapping)
    m["mitre_techniques"], m["agent_groups"] = list(m["mitre_techniques"] or []), list(m["agent_groups"] or [])
    return AlertDetail(**m)


@router.get("/alerts/{alert_id}", response_model=AlertDetail, summary="One stored alert")
def get_alert(alert_id: uuid.UUID, p: Principal = Depends(require("alerts:read")),
              conn: Connection = Depends(request_connection)) -> AlertDetail:
    return _alert_detail(conn, alert_id)


@router.get("/alerts/{alert_id}/evidence", response_model=AlertEvidence,
            summary="The original alert document from its source (read by the API, redacted)")
def alert_evidence(alert_id: uuid.UUID, p: Principal = Depends(require("alerts:read")),
                   conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> AlertEvidence:
    from app.modules.endpoints import org_scope  # the same scope rules as the endpoint views
    row = conn.execute(text("SELECT id, source, external_id, agent_id, raw FROM novrsoc.alerts WHERE id = :id"),
                       {"id": alert_id}).first()
    if row is None:
        raise not_found("Alert not found")
    now = datetime.now(timezone.utc)

    def answer(state: ConnectorState, doc):
        clean = redact_value(doc) if doc is not None else None
        return AlertEvidence(alert_id=row.id, external_id=row.external_id, source=state,
                             document=None if clean is FAILED else clean, retrieved_at=now)

    if row.source == "local_fixture":
        return answer(ConnectorState(connector="wazuh_indexer", state="local_fixture",
                                     detail="Stored copy of a local fixture alert. Not live telemetry."), row.raw)
    if settings.wazuh_mode != "live":  # the fixture is not an indexer: a real alert's evidence is simply unavailable here
        return answer(ConnectorState(connector="wazuh_indexer", state="unconfigured",
                                     detail="No live Wazuh indexer is configured, so the original alert cannot be retrieved."), None)
    indexer_state = registry.wazuh_states(settings)[1]
    if indexer_state.state != "connected":
        return answer(indexer_state, None)
    try:
        doc = registry.wazuh(settings).alert_document(org_scope(conn, p.org_id), row.agent_id, row.external_id)
    except ConnectorError as e:
        return answer(indexer_state.model_copy(update={"state": "unavailable", "detail": str(e)[:300]}), None)
    if doc is None:
        return answer(indexer_state.model_copy(update={"state": "unavailable", "detail":
                      "The alert is no longer in the indexer (retention), or its agent is no longer in this organization's groups."}), None)
    return answer(indexer_state, doc)


@router.post("/alerts/{alert_id}/status", response_model=AlertDetail, summary="Triage: change an alert's status")
def set_alert_status(alert_id: uuid.UUID, body: AlertStatusUpdate, request: Request,
                     p: Principal = Depends(require("alerts:triage")), conn: Connection = Depends(request_connection)) -> AlertDetail:
    r = conn.execute(text("""UPDATE novrsoc.alerts SET status = :s, status_reason = :r, updated_at = now()
                             WHERE id = :id RETURNING id"""), {"s": body.status, "r": body.reason, "id": alert_id}).first()
    if not r:
        raise not_found("Alert not found")
    audit.record("ALERT_STATUS_CHANGED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="alert", resource_id=str(alert_id), request_id=request.state.request_id,
                 ip=client_ip(request), details={"status": body.status})
    return _alert_detail(conn, alert_id)


@router.post("/alerts/{alert_id}/assign", response_model=AlertDetail, summary="Assign an alert to an analyst (or unassign)")
def assign_alert(alert_id: uuid.UUID, body: AssignmentRequest, request: Request, p: Principal = Depends(require("alerts:triage")),
                 conn: Connection = Depends(request_connection)) -> AlertDetail:
    label = _member(conn, p, body.assignee_id) if body.assignee_id else None
    if conn.execute(text("UPDATE novrsoc.alerts SET assignee_id = :u, updated_at = now() WHERE id = :id RETURNING id"),
                    {"u": body.assignee_id, "id": alert_id}).first() is None:
        raise not_found("Alert not found")
    audit.record("ALERT_ASSIGNED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="alert",
                 resource_id=str(alert_id), request_id=request.state.request_id, ip=client_ip(request), details={"assignee": label})
    return _alert_detail(conn, alert_id)


# ---------------------------------------------------------------- cases
@router.post("/cases", response_model=CasePromotionResult, status_code=201,
             summary="Create a case from stored alerts (deduplicated per source and source id)")
def create_case(body: AlertToCasePromotion, request: Request, p: Principal = Depends(require("cases:write")),
                conn: Connection = Depends(request_connection)) -> CasePromotionResult:
    if body.severity.value == "info":
        raise ApiError(422, "validation_error", "A case severity must be low, medium, high or critical")
    ids = list(dict.fromkeys(body.alert_ids))
    found = conn.execute(text("SELECT id FROM novrsoc.alerts WHERE id = ANY(:ids)"), {"ids": ids}).all()
    if len(found) != len(ids):  # unknown, or another organization's alert: never linked, never revealed
        raise not_found("One or more alerts were not found")
    existing = conn.execute(text("SELECT id FROM novrsoc.cases WHERE source = :s AND source_id = :sid"),
                            {"s": body.source, "sid": body.source_id}).scalar()
    created = existing is None
    if created and body.assignee_id:
        _member(conn, p, body.assignee_id)
    case_id = existing
    if created:
        row = conn.execute(text("""
            INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id, assignee_id, created_by)
            VALUES (:o, :t, :sev, :s, :sid, :a, :u) RETURNING id, created_at"""),
            {"o": p.org_id, "t": body.title, "sev": body.severity.value, "s": body.source, "sid": body.source_id,
             "a": body.assignee_id, "u": p.user_id}).one()
        case_id = row.id
        sla.apply_policy(conn, case_id, body.severity.value, row.created_at)
        _event(conn, p, case_id, "created", body.summary or f"Case created from {len(ids)} alert(s).")
    linked = []
    for aid in ids:
        new = conn.execute(text("""INSERT INTO novrsoc.case_alerts (case_id, alert_id, org_id) VALUES (:c, :a, :o)
                                   ON CONFLICT DO NOTHING RETURNING alert_id"""), {"c": case_id, "a": aid, "o": p.org_id}).first()
        if new:
            linked.append(aid)
            _event(conn, p, case_id, "alert_linked", f"Alert {aid} linked.")
    conn.execute(text("UPDATE novrsoc.alerts SET status = 'in_progress', updated_at = now() WHERE id = ANY(:ids) AND status IN ('new', 'acknowledged')"),
                 {"ids": ids})
    if created:
        audit.record("CASE_CREATED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                     resource_type="case", resource_id=str(case_id), request_id=request.state.request_id,
                     ip=client_ip(request), details={"alerts": len(ids), "source": body.source})
    return CasePromotionResult(case_id=case_id, created=created, linked_alert_ids=linked)


@router.get("/cases", response_model=CaseList, summary="Cases of the active organization (newest first)")
def list_cases(status: Literal["open", "in_progress", "resolved", "closed"] | None = None,
               limit: int = Query(50, ge=1, le=200), offset: int = Query(0, ge=0, le=100_000),
               p: Principal = Depends(require("cases:read")), conn: Connection = Depends(request_connection)) -> CaseList:
    cond, params = ("c.status = :status", {"status": status}) if status else ("true", {})
    params.update(limit=limit, offset=offset)
    total = conn.execute(text(f"SELECT count(*) FROM novrsoc.cases c WHERE {cond}"), params).scalar()
    rows = conn.execute(text(f"SELECT {_CASE_COLS} FROM novrsoc.cases c WHERE {cond} ORDER BY c.created_at DESC LIMIT :limit OFFSET :offset"), params).all()
    return CaseList(items=[_case(r) for r in rows], total=total, limit=limit, offset=offset)


def _case_detail(conn: Connection, case_id: uuid.UUID) -> CaseDetail:
    r = conn.execute(text(f"SELECT {_CASE_COLS} FROM novrsoc.cases c WHERE c.id = :id"), {"id": case_id}).first()
    if not r:
        raise not_found("Case not found")
    base = _case(r)
    alerts = conn.execute(text(f"""SELECT {_ALERT_COLS} FROM novrsoc.alerts a JOIN novrsoc.case_alerts l ON l.alert_id = a.id
                                    WHERE l.case_id = :id ORDER BY a.observed_at"""), {"id": case_id}).all()
    events = conn.execute(text("""SELECT id, occurred_at, kind, actor_label, body FROM novrsoc.case_events
                                  WHERE case_id = :id ORDER BY id"""), {"id": case_id}).all()  # noqa: E501
    return CaseDetail(**base.model_dump(), alerts=[_alert(a) for a in alerts],
                      timeline=[CaseEvent(**dict(e._mapping)) for e in events], closed_at=r.closed_at)


@router.get("/cases/{case_id}", response_model=CaseDetail, summary="One case with its alerts and timeline")
def get_case(case_id: uuid.UUID, p: Principal = Depends(require("cases:read")),
             conn: Connection = Depends(request_connection)) -> CaseDetail:
    return _case_detail(conn, case_id)


@router.post("/cases/{case_id}/notes", response_model=CaseDetail, status_code=201, summary="Add a note to the case timeline")
def add_note(case_id: uuid.UUID, body: CaseNoteCreate, p: Principal = Depends(require("cases:write")),
             conn: Connection = Depends(request_connection)) -> CaseDetail:
    if not conn.execute(text("SELECT 1 FROM novrsoc.cases WHERE id = :id"), {"id": case_id}).first():
        raise not_found("Case not found")
    _event(conn, p, case_id, body.kind, body.body)
    sla.mark_first_response(conn, case_id)
    conn.execute(text("UPDATE novrsoc.cases SET updated_at = now() WHERE id = :id"), {"id": case_id})
    return _case_detail(conn, case_id)


@router.post("/cases/{case_id}/assign", response_model=CaseDetail, summary="Assign a case to an analyst (or unassign)")
def assign_case(case_id: uuid.UUID, body: AssignmentRequest, request: Request, p: Principal = Depends(require("cases:write")),
                conn: Connection = Depends(request_connection)) -> CaseDetail:
    label = _member(conn, p, body.assignee_id) if body.assignee_id else None
    if conn.execute(text("UPDATE novrsoc.cases SET assignee_id = :u, updated_at = now() WHERE id = :id RETURNING id"),
                    {"u": body.assignee_id, "id": case_id}).first() is None:
        raise not_found("Case not found")
    _event(conn, p, case_id, "assigned", (f"Assigned to {label}." if label else "Unassigned.") + (f" {body.note}" if body.note else ""))
    sla.mark_first_response(conn, case_id)
    audit.record("CASE_ASSIGNED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="case",
                 resource_id=str(case_id), request_id=request.state.request_id, ip=client_ip(request), details={"assignee": label})
    return _case_detail(conn, case_id)


@router.post("/cases/{case_id}/status", response_model=CaseDetail, summary="Change a case's status (closing needs cases:close)")
def set_case_status(case_id: uuid.UUID, body: CaseStatusUpdate, request: Request,
                    p: Principal = Depends(require("cases:write")), conn: Connection = Depends(request_connection)) -> CaseDetail:
    if body.status == "closed" and not p.has("cases:close"):
        raise forbidden("Insufficient permissions", {"required": "cases:close"})
    old = conn.execute(text("SELECT status FROM novrsoc.cases WHERE id = :id"), {"id": case_id}).scalar()
    if old is None:
        raise not_found("Case not found")
    if old == body.status:
        raise ApiError(409, "conflict", f"The case is already {body.status}")
    if body.status == "closed" and len(body.note.strip()) < 10:
        raise ApiError(422, "closure_note_required", "Closing a case needs a closure note (at least 10 characters): outcome and remediation")
    conn.execute(text("""UPDATE novrsoc.cases SET status = :s, updated_at = now(),
                         closed_at = CASE WHEN :s = 'closed' THEN now() ELSE NULL END,
                         resolved_at = CASE WHEN :s IN ('resolved', 'closed') THEN coalesce(resolved_at, now()) ELSE NULL END
                         WHERE id = :id"""),
                 {"s": body.status, "id": case_id})
    sla.mark_first_response(conn, case_id)
    _event(conn, p, case_id, "closure" if body.status == "closed" else "status_changed",
           body.note or f"Status changed from {old} to {body.status}.", f'{{"from": "{old}", "to": "{body.status}"}}')
    audit.record("CASE_STATUS_CHANGED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="case", resource_id=str(case_id), request_id=request.state.request_id,
                 ip=client_ip(request), details={"from": old, "to": body.status})
    return _case_detail(conn, case_id)
