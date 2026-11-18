"""Reports foundation (Phase 4; ongoing owner: workstream E): organization-scoped report requests and history.

The one report type for now, `organization_summary`, reads only data the API holds or can establish. Every
section records the honest state of its source: available (`ok`/`empty`), `integration_unconfigured`,
`local_fixture` (labelled test data) or `not_permitted` (the requester's role cannot read that source).
Nothing is ever filled in to make a report look complete. PDF is not offered yet.

Consolidation: a platform-wide reporting centre. Every report type reads the organization's actual records for the
period: executive, SECOPS, VMS (executive and technical), Threat Intelligence, Brand Protection, Email Security, CNII
(designated sectors only), compliance (Wazuh SCA), SLA and audit. The browser renders a printable preview.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.connectors import registry
from app.core.config import Settings, get_settings
from app.core.errors import ApiError, not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.modules.endpoints import org_scope
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.governance import ReportArtifact, ReportDetail, ReportList, ReportRequest, ReportSection, ReportType

MODULE = ModuleInfo(name="reports", workstream="E", prefix="/api/v1/reports",
                    summary="Organization-scoped report requests and report history")
router = APIRouter(prefix="/api/v1/reports", tags=["reports"], responses=ERRORS)

OPEN = "('verified', 'risk_accepted')"
SUPPORTED_FORMATS = {"json", "csv"}


def _section(key, title, state, data=None, note="") -> ReportSection:
    return ReportSection(key=key, title=title, state=state, data=data or {}, note=note)


def build_organization_summary(conn: Connection, p: Principal, settings: Settings, start: datetime, end: datetime) -> list[ReportSection]:
    org = conn.execute(text("SELECT name, slug FROM novrsoc.organizations WHERE id = :id"), {"id": p.org_id}).one()
    out = [_section("organization", "Organization", "ok", {"name": org.name, "slug": str(org.slug)})]

    if p.has("sites:read"):
        sites = [r[0] for r in conn.execute(text("SELECT name FROM novrsoc.sites ORDER BY name"))]
        out.append(_section("sites", "Sites", "ok" if sites else "empty", {"count": len(sites), "names": sites}))
    else:
        out.append(_section("sites", "Sites", "not_permitted"))

    if not p.has("endpoints:read"):
        out.append(_section("endpoints", "Endpoints (NovrSIEM)", "not_permitted"))
    else:
        source = registry.wazuh(settings)
        if source is None:
            out.append(_section("endpoints", "Endpoints (NovrSIEM)", "integration_unconfigured",
                                note="No NovrSIEM connection is configured; endpoint figures are unavailable, not zero."))
        else:
            scope = org_scope(conn, p.org_id)
            agents = source.list_agents(scope)
            by_status: dict[str, int] = {}
            vulns = {"critical": 0, "high": 0, "medium": 0, "low": 0}
            with_vuln_data = 0
            for a in agents:
                by_status[a.status] = by_status.get(a.status, 0) + 1
                v = source.vulnerability_counts(scope, a.agent_id)
                if v is not None:
                    with_vuln_data += 1
                    for k in vulns:
                        vulns[k] += v.get(k, 0)
            fixture = registry.wazuh_states(settings)[0].state == "local_fixture"
            out.append(_section("endpoints", "Endpoints (NovrSIEM)", "local_fixture" if fixture else "ok",
                                {"count": len(agents), "by_status": by_status, "vulnerabilities": vulns,
                                 "endpoints_with_vulnerability_data": with_vuln_data},
                                note="Local fixture data for development; not live telemetry." if fixture else ""))

    if p.has("alerts:read"):
        rows = conn.execute(text("""SELECT severity, status, source, count(*) FROM novrsoc.alerts
                                    WHERE observed_at >= :s AND observed_at < :e GROUP BY 1, 2, 3"""), {"s": start, "e": end}).all()
        by_sev: dict[str, int] = {}
        by_status: dict[str, int] = {}
        fixture = 0
        for sev, st, src, n in rows:
            by_sev[sev] = by_sev.get(sev, 0) + n
            by_status[st] = by_status.get(st, 0) + n
            fixture += n if src == "local_fixture" else 0
        total = sum(by_sev.values())
        out.append(_section("alerts", "Alerts in period", "ok" if total else "empty",
                            {"total": total, "by_severity": by_sev, "by_status": by_status},
                            note=f"{fixture} of these are local fixture alerts." if fixture else ""))
    else:
        out.append(_section("alerts", "Alerts in period", "not_permitted"))

    if p.has("cases:read"):
        rows = conn.execute(text("""SELECT status, count(*) FROM novrsoc.cases
                                    WHERE created_at >= :s AND created_at < :e GROUP BY 1"""), {"s": start, "e": end}).all()
        by_status = {st: n for st, n in rows}
        total = sum(by_status.values())
        out.append(_section("cases", "Cases opened in period", "ok" if total else "empty", {"total": total, "by_status": by_status}))
    else:
        out.append(_section("cases", "Cases opened in period", "not_permitted"))
    return out


def _artifact(r) -> ReportArtifact:
    return ReportArtifact(id=r.id, type=r.report_type, status=r.status, period_start=r.period_start, period_end=r.period_end,
                          format=r.format, sha256=r.sha256, created_at=r.requested_at, data_states=r.data_states or {})


_COLS = "id, report_type, status, period_start, period_end, format, sha256, requested_at, data_states, content, failure_reason"


def _group(conn: Connection, sql: str, params: dict) -> dict:
    return {str(r[0]): r[1] for r in conn.execute(text(sql), params)}


def _need(p: Principal, perm: str, key: str, title: str) -> ReportSection | None:
    return None if p.has(perm) else _section(key, title, "not_permitted")


def build_secops(conn, p, settings, start, end) -> list[ReportSection]:
    w = {"s": start, "e": end}
    out = []
    if (x := _need(p, "alerts:read", "alerts", "Alerts")) is None:
        sev = _group(conn, "SELECT severity, count(*) FROM novrsoc.alerts WHERE observed_at >= :s AND observed_at < :e GROUP BY 1", w)
        st = _group(conn, "SELECT status, count(*) FROM novrsoc.alerts WHERE observed_at >= :s AND observed_at < :e GROUP BY 1", w)
        src = _group(conn, "SELECT source, count(*) FROM novrsoc.alerts WHERE observed_at >= :s AND observed_at < :e GROUP BY 1", w)
        top = [{"rule": r[0], "description": r[1], "count": r[2]} for r in conn.execute(text(
            """SELECT rule_id, rule_description, count(*) FROM novrsoc.alerts WHERE observed_at >= :s AND observed_at < :e
               GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 10"""), w)]
        out.append(_section("alerts", "Alerts", "ok" if sev else "empty", {"by_severity": sev, "by_status": st, "by_source": src, "top_rules": top},
                            note=f"{src.get('local_fixture', 0)} local fixture alert(s)." if src.get("local_fixture") else ""))
    else:
        out.append(x)
    if (x := _need(p, "cases:read", "cases", "Cases")) is None:
        opened = _group(conn, "SELECT severity, count(*) FROM novrsoc.cases WHERE created_at >= :s AND created_at < :e GROUP BY 1", w)
        closed = conn.execute(text("SELECT count(*) FROM novrsoc.cases WHERE closed_at >= :s AND closed_at < :e"), w).scalar()
        mttr = conn.execute(text("""SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM first_response_at - created_at) / 60)
                                    FROM novrsoc.cases WHERE created_at >= :s AND created_at < :e AND first_response_at IS NOT NULL"""), w).scalar()
        out.append(_section("cases", "Cases", "ok" if opened or closed else "empty",
                            {"opened_by_severity": opened, "closed": closed,
                             "median_minutes_to_first_response": round(mttr) if mttr is not None else None}))
        runs = _group(conn, "SELECT state, count(*) FROM novrsoc.soar_runs WHERE created_at >= :s AND created_at < :e GROUP BY 1", w)
        steps = _group(conn, """SELECT st.state, count(*) FROM novrsoc.soar_steps st JOIN novrsoc.soar_runs r ON r.id = st.run_id
                                WHERE r.created_at >= :s AND r.created_at < :e GROUP BY 1""", w)
        appr = _group(conn, "SELECT coalesce(decision, 'pending'), count(*) FROM novrsoc.soar_approvals WHERE created_at >= :s AND created_at < :e GROUP BY 1", w)
        out.append(_section("soar", "SOAR runs and approvals", "ok" if runs else "empty", {"runs_by_state": runs, "steps_by_state": steps,
                                                                                       "approvals": appr}))
        ai = _group(conn, "SELECT kind, count(*) FROM novrsoc.ai_activity WHERE occurred_at >= :s AND occurred_at < :e GROUP BY 1", w)
        out.append(_section("ai_activity", "AI activity (analysis only)", "ok" if ai else "empty", {"by_kind": ai}))
    else:
        out.append(x)
    return out


def build_vms(conn, p, settings, start, end, technical: bool) -> list[ReportSection]:
    if (x := _need(p, "vms:read", "vulnerabilities", "Vulnerabilities")) is not None:
        return [x]
    w = {"s": start, "e": end}
    sev = _group(conn, f"SELECT severity, count(*) FROM novrsoc.vms_findings WHERE status NOT IN {OPEN} GROUP BY 1", w)
    pri = _group(conn, f"SELECT priority, count(*) FROM novrsoc.vms_findings WHERE status NOT IN {OPEN} GROUP BY 1", w)
    new = conn.execute(text("SELECT count(*) FROM novrsoc.vms_findings WHERE first_seen_at >= :s AND first_seen_at < :e"), w).scalar()
    fixed = conn.execute(text("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status = 'done' AND updated_at >= :s AND updated_at < :e"), w).scalar()
    overdue = conn.execute(text("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()")).scalar()
    kev = conn.execute(text(f"""SELECT count(*) FROM novrsoc.vms_findings f WHERE f.status NOT IN {OPEN}
                                AND EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)""")).scalar()
    scans = _group(conn, "SELECT state, count(*) FROM novrsoc.vms_scan_jobs WHERE created_at >= :s AND created_at < :e GROUP BY 1", w)
    out = [_section("exposure", "Open findings", "ok" if sev else "empty", {"by_severity": sev, "by_priority": pri, "known_exploited": kev}),
           _section("activity", "Findings and remediation in period", "ok" if new or fixed else "empty",
                    {"new_findings": new, "verified_fixed": fixed, "overdue_now": overdue}),
           _section("scans", "Scans in period", "ok" if scans else "empty", {"by_state": scans,
                                                                              "scanning": settings.vms_scanning})]
    if technical:
        top = [{"title": r.title, "host": r.host, "port": r.port, "severity": r.severity, "priority": r.priority, "risk": r.risk_score,
                "cves": list(r.cves), "status": r.status} for r in conn.execute(text(
                    f"SELECT * FROM novrsoc.vms_findings WHERE status NOT IN {OPEN} ORDER BY risk_score DESC LIMIT 50"))]
        out.append(_section("top_findings", "Highest-risk open findings", "ok" if top else "empty", {"findings": top}))
    return out


def build_intel(conn, p, settings, start, end) -> list[ReportSection]:
    if (x := _need(p, "intel:read", "intel", "Threat intelligence")) is not None:
        return [x]
    w = {"s": start, "e": end}
    ind = _group(conn, "SELECT type, count(*) FROM novrsoc.ti_indicators WHERE imported_at >= :s AND imported_at < :e GROUP BY 1", w)
    m = _group(conn, "SELECT verdict, count(*) FROM novrsoc.ti_matches WHERE matched_at >= :s AND matched_at < :e GROUP BY 1", w)
    actors = _group(conn, "SELECT attribution, count(*) FROM novrsoc.ti_threat_actors GROUP BY 1", w)
    cves = conn.execute(text("SELECT count(DISTINCT cve_id), count(DISTINCT cve_id) FILTER (WHERE kev) FROM novrsoc.ti_cve_records")).one()
    feeds = conn.execute(text("SELECT count(*), coalesce(sum(objects_stored), 0) FROM novrsoc.ti_feed_runs WHERE received_at >= :s AND received_at < :e"), w).one()
    return [_section("indicators", "Indicators imported in period", "ok" if ind else "empty", {"by_type": ind}),
            _section("matches", "Indicator matches in the organization's alerts", "ok" if m else "empty", {"by_verdict": m}),
            _section("actors", "Threat actor profiles", "ok" if actors else "empty", {"by_attribution": actors},
                     note="Profiles are recorded by analysts; attribution states are shown as recorded."),
            _section("cves", "CVE intelligence", "ok" if cves[0] else "empty", {"cves": cves[0], "known_exploited": cves[1]}),
            _section("feeds", "STIX/TAXII feed runs in period", "ok" if feeds[0] else "empty", {"runs": feeds[0], "objects_stored": feeds[1]})]


def build_brand(conn, p, settings, start, end) -> list[ReportSection]:
    if (x := _need(p, "protection:read", "brand", "Brand protection")) is not None:
        return [x]
    w = {"s": start, "e": end}
    subj = _group(conn, "SELECT type, count(*) FROM novrsoc.brand_watch_subjects WHERE active GROUP BY 1", w)
    st = _group(conn, "SELECT status, count(*) FROM novrsoc.brand_findings WHERE observed_at >= :s AND observed_at < :e GROUP BY 1", w)
    runs = _group(conn, "SELECT outcome, count(*) FROM novrsoc.brand_monitoring_runs WHERE started_at >= :s AND started_at < :e GROUP BY 1", w)
    return [_section("subjects", "Watch subjects", "ok" if subj else "empty", {"by_type": subj}),
            _section("findings", "Findings in period", "ok" if st else "empty", {"by_status": st}),
            _section("runs", "Monitoring runs in period", "ok" if runs else "empty", {"by_outcome": runs},
                     note="source_unconfigured runs looked nothing up: no resolver is configured." if runs.get("source_unconfigured") else "")]


def build_email(conn, p, settings, start, end) -> list[ReportSection]:
    if (x := _need(p, "protection:read", "email", "Email security")) is not None:
        return [x]
    w = {"s": start, "e": end}
    doms = conn.execute(text("SELECT domain, verification, coalesce(dmarc_policy, 'unknown') AS dmarc FROM novrsoc.email_domains ORDER BY domain")).all()
    rep_ = conn.execute(text("""SELECT count(*), coalesce(sum(messages_total), 0), coalesce(sum(messages_failing), 0) FROM novrsoc.dmarc_reports
                                WHERE period_end > :s AND period_start < :e"""), w).one()
    return [_section("domains", "Domains", "ok" if doms else "empty", {"domains": [{"domain": str(d.domain), "verification": d.verification,
                                                                                   "dmarc": d.dmarc} for d in doms]},
                     note="Domain verification needs a DNS adapter, which is not configured." if doms else ""),
            _section("dmarc", "DMARC aggregate reports in period", "ok" if rep_[0] else "empty",
                     {"reports": rep_[0], "messages": rep_[1], "failing": rep_[2]})]


def build_cnii(conn, p, settings, start, end) -> list[ReportSection]:
    rows = conn.execute(text("""SELECT sectors FROM novrsoc.cnii_designations WHERE user_id = novrsoc.app_user() AND revoked_at IS NULL
                                AND expires_at > now() AND (scope_org_ids IS NULL OR :o = ANY(scope_org_ids))"""), {"o": p.org_id}).all()
    if not p.has("cnii:read") or not rows:
        return [_section("cnii", "CNII monitoring", "not_permitted", note="Needs cnii:read and an active CNII designation covering this organization.")]
    sectors = sorted({x for r in rows for x in r.sectors})
    by = _group(conn, "SELECT sector, count(*) FROM novrsoc.cnii_monitored_assets WHERE sector = ANY(:sec) AND status = 'active' GROUP BY 1",
                {"sec": sectors})
    checks = _group(conn, """SELECT c.outcome, count(*) FROM novrsoc.cnii_checks c JOIN novrsoc.cnii_monitored_assets m ON m.id = c.monitored_asset_id
                             WHERE m.sector = ANY(:sec) AND c.observed_at >= :s AND c.observed_at < :e GROUP BY 1""",
                    {"sec": sectors, "s": start, "e": end})
    f = conn.execute(text(f"""SELECT count(*) FROM novrsoc.vms_findings f JOIN novrsoc.cnii_monitored_assets m ON m.asset_id = f.asset_id
                              WHERE m.sector = ANY(:sec) AND f.status NOT IN {OPEN}"""), {"sec": sectors}).scalar()
    return [_section("designated_assets", "Designated assets by sector", "ok" if by else "empty", {"by_sector": by, "sectors_in_scope": sectors}),
            _section("checks", "Monitoring checks in period", "ok" if checks else "empty", {"by_outcome": checks},
                     note="not_run checks: no availability probe is configured." if checks.get("not_run") else ""),
            _section("findings", "Open findings on designated assets", "ok", {"open": f})]


def build_compliance(conn, p, settings, start, end) -> list[ReportSection]:
    from app.modules.posture import compliance
    cv = compliance(conn, p, settings)
    if cv.source.state not in ("connected", "local_fixture"):
        return [_section("sca", "Configuration assessment (NovrAgent SCA)", "integration_unconfigured" if cv.source.state == "unconfigured" else "error",
                         note=(cv.note or cv.source.detail or "")[:200])]
    return [_section("sca", "Configuration assessment (NovrAgent SCA)", "local_fixture" if cv.source.state == "local_fixture" else "ok",
                     {"endpoints_assessed": cv.endpoints_assessed, "policies": [x.model_dump() for x in cv.policies]}, note=cv.note[:200])]


def build_sla(conn, p, settings, start, end) -> list[ReportSection]:
    if (x := _need(p, "cases:read", "sla", "SLA performance")) is not None:
        return [x]
    from app.modules.secops import performance
    days = max(7, min(365, (end - start).days or 7))
    perf = performance(conn, days)
    has = any(r.cases - r.without_policy for r in perf.rows)
    return [_section("sla", f"SLA performance (last {days} days)", "ok" if has else "empty",
                     {"by_severity": [r.model_dump() for r in perf.rows]}, note=perf.note[:200])]


def build_audit(conn, p, settings, start, end) -> list[ReportSection]:
    if (x := _need(p, "audit:read", "audit", "Audit events")) is not None:
        return [x]
    w = {"s": start, "e": end}
    out_ = _group(conn, "SELECT outcome, count(*) FROM novrsoc.audit_events WHERE occurred_at >= :s AND occurred_at < :e GROUP BY 1", w)
    acts = [{"action": r[0], "count": r[1]} for r in conn.execute(text("""SELECT action, count(*) FROM novrsoc.audit_events
                                                                          WHERE occurred_at >= :s AND occurred_at < :e GROUP BY 1 ORDER BY 2 DESC LIMIT 40"""), w)]
    denied = [{"action": r[0], "actor": r[1], "count": r[2]} for r in conn.execute(text(
        """SELECT action, actor_label, count(*) FROM novrsoc.audit_events WHERE occurred_at >= :s AND occurred_at < :e AND outcome = 'denied'
           GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 20"""), w)]
    return [_section("outcomes", "Events by outcome", "ok" if out_ else "empty", {"by_outcome": out_}),
            _section("actions", "Most frequent actions", "ok" if acts else "empty", {"actions": acts}),
            _section("denied", "Denied actions", "ok" if denied else "empty", {"denied": denied})]


def build_executive(conn, p, settings, start, end) -> list[ReportSection]:
    from app.modules.posture import measures, score
    ms = measures(conn, p)
    sc = score(ms)
    out = [_section("posture", "Security posture", "ok" if sc.score is not None else "empty",
                    {"score": sc.score, "coverage_percent": sc.coverage_percent, "measures": [
                        {"label": m.label, "state": m.state, "value": m.value, "numerator": m.numerator, "denominator": m.denominator,
                         "formula": m.formula} for m in ms]},
                    note="" if sc.score is not None else "Score withheld: the available measurements cover too little of the posture.")]
    return out + build_secops(conn, p, settings, start, end)[:2] + build_vms(conn, p, settings, start, end, technical=False)[:2]


BUILDERS = {
    ReportType.ORGANIZATION_SUMMARY: build_organization_summary,
    ReportType.EXECUTIVE: build_executive,
    ReportType.SECOPS: build_secops,
    ReportType.SOC_MONTHLY: build_secops,
    ReportType.VMS_EXECUTIVE: lambda c, p, s, a, b: build_vms(c, p, s, a, b, technical=False),
    ReportType.VMS_TECHNICAL: lambda c, p, s, a, b: build_vms(c, p, s, a, b, technical=True),
    ReportType.THREAT_INTEL: build_intel,
    ReportType.BRAND_PROTECTION: build_brand,
    ReportType.EMAIL_SECURITY: build_email,
    ReportType.CNII_SECTOR: build_cnii,
    ReportType.COMPLIANCE_SCA: build_compliance,
    ReportType.SLA: build_sla,
    ReportType.AUDIT: build_audit,
}
SUPPORTED_TYPES = set(BUILDERS)


@router.post("", response_model=ReportDetail, status_code=201, summary="Request a report (idempotent per key)")
def request_report(body: ReportRequest, request: Request, p: Principal = Depends(require("reports:manage")),
                   conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> ReportDetail:
    if body.type not in SUPPORTED_TYPES:
        raise ApiError(422, "report_type_unavailable", f"Report type {body.type.value} is not available yet")
    if body.format not in SUPPORTED_FORMATS:
        raise ApiError(422, "format_unavailable", "Only JSON and CSV reports are available in this release")
    existing = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.report_requests WHERE idempotency_key = :k"),
                            {"k": body.idempotency_key}).first()
    if existing:
        return _detail(existing)
    sections = BUILDERS[body.type](conn, p, settings, body.period_start, body.period_end)
    content = {"type": body.type.value, "period_start": body.period_start.isoformat(), "period_end": body.period_end.isoformat(),
               "generated_at": datetime.now(timezone.utc).isoformat(), "sections": [s.model_dump() for s in sections]}
    canonical = json.dumps(content, sort_keys=True, default=str)
    r = conn.execute(text(f"""
        INSERT INTO novrsoc.report_requests (org_id, report_type, idempotency_key, period_start, period_end, format, status,
                                             requested_by, completed_at, data_states, content, sha256)
        VALUES (:o, :t, :k, :s, :e, :f, 'ready', :u, now(), CAST(:ds AS jsonb), CAST(:c AS jsonb), :h) RETURNING {_COLS}"""),
        {"o": p.org_id, "t": body.type.value, "k": body.idempotency_key, "s": body.period_start, "e": body.period_end,
         "f": body.format, "u": p.user_id, "ds": json.dumps({s.key: s.state for s in sections}), "c": canonical,
         "h": hashlib.sha256(canonical.encode()).hexdigest()}).one()
    audit.record("REPORT_REQUESTED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="report", resource_id=str(r.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"type": body.type.value})
    return _detail(r)


def _detail(r) -> ReportDetail:
    content = r.content or {}
    return ReportDetail(**_artifact(r).model_dump(), failure_reason=r.failure_reason,
                        sections=[ReportSection(**s) for s in content.get("sections", [])])


@router.get("", response_model=ReportList, summary="Report history of the active organization")
def list_reports(limit: int = Query(50, ge=1, le=200), p: Principal = Depends(require("reports:read")),
                 conn: Connection = Depends(request_connection)) -> ReportList:
    rows = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.report_requests ORDER BY requested_at DESC LIMIT :n"), {"n": limit}).all()
    return ReportList(items=[_artifact(r) for r in rows])


@router.get("/{report_id}", response_model=ReportDetail, summary="One report with its sections and source states")
def get_report(report_id: uuid.UUID, p: Principal = Depends(require("reports:read")),
               conn: Connection = Depends(request_connection)) -> ReportDetail:
    r = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.report_requests WHERE id = :id"), {"id": report_id}).first()
    if not r:
        raise not_found("Report not found")
    return _detail(r)


@router.get("/{report_id}/download", summary="Download a report (JSON or CSV)",
            responses={200: {"content": {"application/json": {}, "text/csv": {}}}})
def download(report_id: uuid.UUID, p: Principal = Depends(require("reports:read")),
             conn: Connection = Depends(request_connection)) -> Response:
    r = conn.execute(text(f"SELECT {_COLS} FROM novrsoc.report_requests WHERE id = :id"), {"id": report_id}).first()
    if not r:
        raise not_found("Report not found")
    canonical = json.dumps(r.content, sort_keys=True, default=str)
    if hashlib.sha256(canonical.encode()).hexdigest() != r.sha256:
        raise ApiError(409, "integrity_check_failed", "The stored report does not match its checksum")
    name = f"novrsoc-{r.report_type}-{r.requested_at:%Y%m%d-%H%M%S}"
    if r.format == "json":
        return Response(canonical, media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="{name}.json"', "X-Content-SHA256": r.sha256})
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["section", "state", "metric", "value"])
    for s in r.content.get("sections", []):
        flat = _flatten(s.get("data") or {})
        if not flat:
            w.writerow([s["key"], s["state"], "", ""])
        for k, v in flat:
            w.writerow([s["key"], s["state"], k, v])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": f'attachment; filename="{name}.csv"'})


def _flatten(d: dict, prefix: str = "") -> list[tuple[str, object]]:
    out = []
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out += _flatten(v, key + ".")
        elif isinstance(v, list):
            out.append((key, "; ".join(map(str, v))))
        else:
            out.append((key, v))
    return out
