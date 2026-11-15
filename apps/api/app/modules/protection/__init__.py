"""Email Security and Brand Protection (workstream D, pilot): organization-scoped, offline adapters only.

Email: register domains (verification stays `pending` until a DNS verification adapter exists), upload DMARC aggregate
reports (parsed safely; the report's policy domain must be one of the organization's domains), read results.
Brand: watch subjects (executive subjects need a consent reference, NDPA), monitoring runs that generate lookalike
candidates and ask the configured resolver which are registered (unconfigured = no lookups, an honest
`source_unconfigured` run), findings with triage. Nothing here sends mail, queries live DNS or contacts a registrar.

Consolidation: email domains reconcile into the shared asset inventory (kind `domain`); a brand finding or a failing
DMARC report can open a case (deduplicated per source record); a lookalike domain can be added to Threat Insights as an
indicator so the organization's alerts are matched against it. Reports cover both modules.
"""
from __future__ import annotations

import json
import secrets
import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy import text
from sqlalchemy.engine import Connection
from sqlalchemy.exc import IntegrityError

from app.assets import reconcile
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.protection import engine
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.protection import (BrandFindingList, BrandFindingTriage, BrandFindingView, DmarcRecord, DmarcReportList,
                                             DmarcReportView, DmarcUpload, EmailDomain, EmailDomainCreate, EmailDomainList,
                                             MonitoringRun, MonitoringRunList, WatchSubject, WatchSubjectCreate, WatchSubjectList)

MODULE = ModuleInfo(name="protection", workstream="D", prefix="/api/v1/protection",
                    summary="Email Security (domains, DMARC) and Brand Protection (watch subjects, lookalikes, findings)")
router = APIRouter(prefix="/api/v1/protection", tags=["protection"], responses=ERRORS)


def _audit(p: Principal, request: Request, action: str, rtype: str, rid: str, details: dict | None = None) -> None:
    audit.record(action, "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type=rtype, resource_id=rid,
                 request_id=request.state.request_id, ip=client_ip(request), details=details or {})


# ---------------------------------------------------------------- Email Security
def _domain(r) -> EmailDomain:
    return EmailDomain(id=r.id, domain=str(r.domain), verification=r.verification,
                       verification_txt_name=f"_novrsoc-verify.{r.domain}", dmarc_policy=r.dmarc_policy)


@router.get("/email/domains", response_model=EmailDomainList, summary="Email domains of the organization")
def list_domains(p: Principal = Depends(require("protection:read")), conn: Connection = Depends(request_connection)) -> EmailDomainList:
    return EmailDomainList(items=[_domain(r) for r in conn.execute(text("SELECT * FROM novrsoc.email_domains ORDER BY domain"))])


@router.post("/email/domains", response_model=EmailDomain, status_code=201, summary="Register an email domain (verification pending)")
def add_domain(body: EmailDomainCreate, request: Request, p: Principal = Depends(require("protection:manage")),
               conn: Connection = Depends(request_connection)) -> EmailDomain:
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.email_domains (org_id, domain, verification_token) VALUES (:o, :d, :t) RETURNING *"""),
                             {"o": p.org_id, "d": body.domain, "t": secrets.token_urlsafe(24)}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "This domain is already registered for the organization")
    _audit(p, request, "EMAIL_DOMAIN_ADDED", "email_domain", body.domain)
    reconcile.upsert(conn, reconcile.Observation(source="email", kind="domain", display_name=str(r.domain),
                                                 identifiers=[("domain", str(r.domain))], attributes={"classification": "domain"}), p.email)
    return _domain(r)


def _report(r) -> DmarcReportView:
    return DmarcReportView(id=r.id, domain_id=r.domain_id, domain=str(r.domain), reporter=r.reporter, report_id=r.report_id,
                           period_start=r.period_start, period_end=r.period_end, messages_total=r.messages_total,
                           messages_failing=r.messages_failing, published_policy=r.published_policy, source=r.source,
                           records=[DmarcRecord(**x) for x in r.records])


_REPORT_SQL = "SELECT r.*, d.domain FROM novrsoc.dmarc_reports r JOIN novrsoc.email_domains d ON d.id = r.domain_id AND d.org_id = r.org_id"


@router.post("/email/dmarc-reports", response_model=DmarcReportView, status_code=201, summary="Upload a DMARC aggregate report (XML)")
def upload_dmarc(body: DmarcUpload, request: Request, p: Principal = Depends(require("protection:manage")),
                 conn: Connection = Depends(request_connection)) -> DmarcReportView:
    try:
        rep = engine.parse_dmarc(body.xml)
    except engine.DmarcError as e:
        raise ApiError(422, "invalid_report", str(e))
    d = conn.execute(text("SELECT id FROM novrsoc.email_domains WHERE domain = :d"), {"d": rep["domain"]}).first()
    if d is None:
        raise ApiError(422, "unknown_domain", "The report's policy domain is not registered for this organization")
    try:
        with conn.begin_nested():
            rid = conn.execute(text("""INSERT INTO novrsoc.dmarc_reports (org_id, domain_id, reporter, report_id, period_start, period_end,
                                         published_policy, messages_total, messages_failing, records, source)
                                       VALUES (:o, :d, :rep, :rid, :ps, :pe, :pol, :t, :f, CAST(:recs AS jsonb), :src) RETURNING id"""),
                               {"o": p.org_id, "d": d.id, "rep": rep["reporter"], "rid": rep["report_id"], "ps": rep["period_start"],
                                "pe": rep["period_end"], "pol": rep["policy"], "t": rep["total"], "f": rep["failing"],
                                "recs": json.dumps(rep["records"]), "src": body.source}).scalar()
    except IntegrityError:
        raise ApiError(409, "conflict", "This report (reporter, report id) was already imported")
    if rep["policy"] in ("none", "quarantine", "reject"):
        conn.execute(text("UPDATE novrsoc.email_domains SET dmarc_policy = :p WHERE id = :d"), {"p": rep["policy"], "d": d.id})
    _audit(p, request, "DMARC_REPORT_IMPORTED", "dmarc_report", rep["report_id"], {"messages": rep["total"], "failing": rep["failing"]})
    return _report(conn.execute(text(_REPORT_SQL + " WHERE r.id = :i"), {"i": rid}).one())


@router.get("/email/dmarc-reports", response_model=DmarcReportList, summary="DMARC aggregate reports (newest first)")
def list_dmarc(p: Principal = Depends(require("protection:read")), conn: Connection = Depends(request_connection)) -> DmarcReportList:
    return DmarcReportList(items=[_report(r) for r in conn.execute(text(_REPORT_SQL + " ORDER BY r.period_end DESC LIMIT 100"))])


# ---------------------------------------------------------------- Brand Protection
def _subject(r) -> WatchSubject:
    return WatchSubject(id=r.id, type=r.type, value=r.value, active=r.active, created_at=r.created_at)


@router.get("/brand/subjects", response_model=WatchSubjectList, summary="Brand Protection watch subjects")
def list_subjects(p: Principal = Depends(require("protection:read")), conn: Connection = Depends(request_connection)) -> WatchSubjectList:
    return WatchSubjectList(items=[_subject(r) for r in conn.execute(text("SELECT * FROM novrsoc.brand_watch_subjects ORDER BY type, value"))])


@router.post("/brand/subjects", response_model=WatchSubject, status_code=201, summary="Add a watch subject")
def add_subject(body: WatchSubjectCreate, request: Request, p: Principal = Depends(require("protection:manage")),
                conn: Connection = Depends(request_connection)) -> WatchSubject:
    if body.type.value == "executive" and not body.consent_reference:
        raise ApiError(422, "validation_error", "An executive watch subject needs a consent reference (NDPA)")
    if body.type.value == "domain" and engine.lookalikes(body.value.lower()) == []:
        raise ApiError(422, "validation_error", "Not a registrable domain")
    try:
        with conn.begin_nested():
            r = conn.execute(text("""INSERT INTO novrsoc.brand_watch_subjects (org_id, type, value, consent_reference)
                                     VALUES (:o, :t, :v, :c) RETURNING *"""),
                             {"o": p.org_id, "t": body.type.value, "v": body.value.lower() if body.type.value == "domain" else body.value,
                              "c": body.consent_reference}).one()
    except IntegrityError:
        raise ApiError(409, "conflict", "This watch subject already exists")
    _audit(p, request, "BRAND_SUBJECT_ADDED", "brand_subject", str(r.id), {"type": body.type.value})
    return _subject(r)


@router.post("/brand/subjects/{subject_id}/runs", response_model=MonitoringRun, status_code=201,
             summary="Run lookalike monitoring for a domain subject (through the configured resolver)")
def run_monitoring(subject_id: uuid.UUID, request: Request, p: Principal = Depends(require("protection:manage")),
                   conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> MonitoringRun:
    s = conn.execute(text("SELECT * FROM novrsoc.brand_watch_subjects WHERE id = :i"), {"i": subject_id}).first()
    if s is None:
        raise not_found("Watch subject not found")
    if s.type != "domain":
        raise ApiError(422, "unsupported_subject", "Only domain subjects have an offline monitoring source in this release")
    source = settings.brand_resolver
    new = 0
    if source == "unconfigured":
        outcome = "source_unconfigured"
    else:
        cands = dict(engine.lookalikes(s.value))
        for cand, info in engine.resolve_test_adapter(list(cands)).items():
            r = conn.execute(text("""INSERT INTO novrsoc.brand_findings (org_id, subject_id, source, value, url, summary, severity, evidence)
                                     VALUES (:o, :s, 'test_adapter', :v, :u, :sum, :sev, CAST(:e AS jsonb))
                                     ON CONFLICT (org_id, subject_id, source, value) DO NOTHING RETURNING id"""),
                             {"o": p.org_id, "s": s.id, "v": cand, "u": f"https://{cand}/",
                              "sum": f"Registered lookalike of {s.value} ({cands[cand]}){' with mail exchanger' if info.get('mx') else ''}",
                              "sev": "high" if info.get("mx") else "medium",
                              "e": json.dumps({**info, "technique": cands[cand], "adapter": "test_adapter (fixture, not live DNS)"})}).first()
            new += 1 if r else 0
        outcome = "completed"
    run = conn.execute(text("""INSERT INTO novrsoc.brand_monitoring_runs (org_id, subject_id, source, finished_at, outcome, new_findings)
                               VALUES (:o, :s, :src, now(), :out, :n) RETURNING *"""),
                       {"o": p.org_id, "s": s.id, "src": source, "out": outcome, "n": new}).one()
    _audit(p, request, "BRAND_MONITORING_RUN", "brand_subject", str(s.id), {"outcome": outcome, "new_findings": new, "source": source})
    return MonitoringRun(id=run.id, subject_id=run.subject_id, started_at=run.started_at, finished_at=run.finished_at, outcome=run.outcome,
                         new_findings=run.new_findings)


@router.get("/brand/runs", response_model=MonitoringRunList, summary="Monitoring runs (newest first)")
def list_runs(p: Principal = Depends(require("protection:read")), conn: Connection = Depends(request_connection)) -> MonitoringRunList:
    rows = conn.execute(text("SELECT * FROM novrsoc.brand_monitoring_runs ORDER BY started_at DESC LIMIT 50")).all()
    return MonitoringRunList(items=[MonitoringRun(id=r.id, subject_id=r.subject_id, started_at=r.started_at, finished_at=r.finished_at,
                                                  outcome=r.outcome, new_findings=r.new_findings) for r in rows])


def _finding(r) -> BrandFindingView:
    return BrandFindingView(id=r.id, subject_id=r.subject_id, source=r.source, url=r.url, summary=r.summary, severity=r.severity,
                            status=r.status, observed_at=r.observed_at, value=r.value, evidence=r.evidence or {})


@router.get("/brand/findings", response_model=BrandFindingList, summary="Brand Protection findings")
def list_findings(p: Principal = Depends(require("protection:read")), conn: Connection = Depends(request_connection)) -> BrandFindingList:
    return BrandFindingList(items=[_finding(r) for r in conn.execute(text("SELECT * FROM novrsoc.brand_findings ORDER BY observed_at DESC LIMIT 200"))])


@router.post("/brand/findings/{finding_id}/triage", response_model=BrandFindingView, summary="Triage a finding")
def triage(finding_id: uuid.UUID, body: BrandFindingTriage, request: Request, p: Principal = Depends(require("protection:manage")),
           conn: Connection = Depends(request_connection)) -> BrandFindingView:
    r = conn.execute(text("UPDATE novrsoc.brand_findings SET status = :s WHERE id = :i RETURNING *"), {"s": body.status, "i": finding_id}).first()
    if r is None:
        raise not_found("Finding not found")
    _audit(p, request, "BRAND_FINDING_TRIAGED", "brand_finding", str(finding_id), {"status": body.status, "note": body.note[:200]})
    return _finding(r)



# ---------------------------------------------------------------- consolidation: cases and Threat Insights from findings
from app.insights import engine as _ti  # noqa: E402
from app.modules.soc import create_case_for  # noqa: E402
from novrsoc_contracts.v1.insights import Indicator, IndicatorImportResult, IndicatorType, Tlp  # noqa: E402
from novrsoc_contracts.v1.soar import CasePromotionResult  # noqa: E402
from datetime import datetime as _dt, timezone as _tz  # noqa: E402

_CASE_SEV = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "low"}


@router.post("/brand/findings/{finding_id}/case", response_model=CasePromotionResult, status_code=201,
             summary="Open a case from a brand finding (one case per finding)")
def brand_case(finding_id: uuid.UUID, request: Request, p: Principal = Depends(require("cases:write")),
               conn: Connection = Depends(request_connection)) -> CasePromotionResult:
    f = conn.execute(text("""SELECT f.*, s.value AS subject FROM novrsoc.brand_findings f JOIN novrsoc.brand_watch_subjects s ON s.id = f.subject_id
                             WHERE f.id = :i"""), {"i": finding_id}).first()
    if f is None:
        raise not_found("Finding not found")
    case_id, created = create_case_for(conn, p, title=f"Brand impersonation: {f.value}", severity=_CASE_SEV.get(f.severity, "medium"),
                                       source="brand_protection", source_id=str(f.id),
                                       summary=f"Brand Protection finding for watch subject '{f.subject}': {f.summary} (source {f.source}).")
    if created:
        _audit(p, request, "CASE_CREATED", "case", str(case_id), {"source": "brand_protection", "finding": str(f.id)})
    return CasePromotionResult(case_id=case_id, created=created, linked_alert_ids=[])


@router.post("/email/dmarc-reports/{report_id}/case", response_model=CasePromotionResult, status_code=201,
             summary="Open a case from a DMARC report with failing messages")
def dmarc_case(report_id: uuid.UUID, request: Request, p: Principal = Depends(require("cases:write")),
               conn: Connection = Depends(request_connection)) -> CasePromotionResult:
    r = conn.execute(text("""SELECT d.*, e.domain FROM novrsoc.dmarc_reports d JOIN novrsoc.email_domains e ON e.id = d.domain_id
                             WHERE d.id = :i"""), {"i": report_id}).first()
    if r is None:
        raise not_found("Report not found")
    if r.messages_failing == 0:
        raise ApiError(409, "conflict", "This report has no failing messages")
    share = r.messages_failing / max(1, r.messages_total)
    case_id, created = create_case_for(conn, p, title=f"DMARC failures for {r.domain}", severity="high" if share >= 0.2 else "medium",
                                       source="email_security", source_id=str(r.id),
                                       summary=f"{r.messages_failing} of {r.messages_total} messages failed DMARC for {r.domain} "
                                               f"({r.period_start:%Y-%m-%d} to {r.period_end:%Y-%m-%d}, reported by {r.reporter}).")
    if created:
        _audit(p, request, "CASE_CREATED", "case", str(case_id), {"source": "email_security", "report": str(r.id)})
    return CasePromotionResult(case_id=case_id, created=created, linked_alert_ids=[])


@router.post("/brand/findings/{finding_id}/indicator", response_model=IndicatorImportResult,
             summary="Add a lookalike domain to Threat Insights (matched against the organization's alerts)")
def brand_indicator(finding_id: uuid.UUID, request: Request, p: Principal = Depends(require("intel:manage")),
                    conn: Connection = Depends(request_connection)) -> IndicatorImportResult:
    f = conn.execute(text("SELECT * FROM novrsoc.brand_findings WHERE id = :i"), {"i": finding_id}).first()
    if f is None:
        raise not_found("Finding not found")
    if _ti.normalize("domain", f.value) is None:
        raise ApiError(422, "validation_error", "Only a domain finding can become an indicator")
    ind = Indicator(type=IndicatorType.DOMAIN, value=f.value, tlp=Tlp.AMBER, source="brand_protection", first_seen_at=f.observed_at or _dt.now(_tz.utc),
                    confidence=50)
    c = _ti.upsert_indicators(conn, p.org_id, [(ind, f"brand_finding:{f.id}", None)], source="brand_protection", tlp="amber",
                              user_id=p.user_id, label=p.email)
    _audit(p, request, "TI_INDICATORS_IMPORTED", "ti_indicators", "brand_protection", {"imported": c.imported, "finding": str(f.id)})
    return IndicatorImportResult(imported=c.imported, unchanged=c.unchanged)
