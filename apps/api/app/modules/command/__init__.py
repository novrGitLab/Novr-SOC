"""NovrSOC Command Center (platform-wide views): every organization's security operations in one place, without copying
a single record and without weakening row-level security.

How a cross-organization view is read: for each organization in the caller's command scope, the request's transaction
switches app.org_id to that organization (transaction-local, exactly as an organization switch does) and runs the
view's query under that organization's RLS policies; every row is labelled with its owner; the per-organization results
are merged and sorted; app.org_id is restored. There is no SECURITY DEFINER shortcut and no table that unions tenants.

Command scope (who may look at what):
  * platform:monitor (platform administrators): every organization (archived ones only on request);
  * soc_manager / analyst whose HOME is the platform organization: home + organizations assigned for operations - the
    same organizations the organization switch already lets them open;
  * anybody else: 403. Each view also requires its own permission (alerts:read, vms:read, cases:read, intel:read,
    nhai:analyze, reports:read, assets:read); export requires exports:manage.
Every view (COMMAND_CENTER_VIEW) and export (COMMAND_CENTER_EXPORT) is audited with its filters and row counts.
"""
from __future__ import annotations

import csv
import io
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable, Literal

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.auth.deps import Principal, client_ip, current_principal
from app.core.errors import ApiError
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.command import CommandList, CommandOrg, CommandOverview, CommandRecord, CommandScope, OrgPosture

MODULE = ModuleInfo(name="command", workstream="A", prefix="/api/v1/command",
                    summary="Command Center: platform-wide, owner-labelled views across organizations (read under each tenant's RLS)")
router = APIRouter(prefix="/api/v1/command", tags=["command"], responses=ERRORS)

EXPORT_MAX = 5000
SEV_RANK = "CASE {c} WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------- scope
@dataclass
class Scope:
    kind: Literal["platform", "assigned"]
    orgs: list[CommandOrg]


def _as(conn: Connection, org_id: uuid.UUID) -> None:
    conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org_id)})


def command_scope(conn: Connection, p: Principal, include_archived: bool = False) -> Scope:
    if p.role == "super_admin" and p.has("platform:monitor"):
        rows = conn.execute(text("""SELECT id, slug::text AS slug, name, kind, status FROM novrsoc.organizations
                                    WHERE (:arch OR status <> 'archived') ORDER BY kind DESC, name"""), {"arch": include_archived}).all()
        return Scope("platform", [CommandOrg(id=r.id, slug=r.slug, name=r.name, kind=r.kind, status=r.status) for r in rows])
    if p.role in ("soc_manager", "analyst"):
        _as(conn, p.home.org_id)
        kind = conn.execute(text("SELECT kind FROM novrsoc.organizations WHERE id = :o"), {"o": p.home.org_id}).scalar()
        _as(conn, p.org_id)
        if kind == "platform":
            orgs = [CommandOrg(id=m.org_id, slug=m.org_slug, name=m.org_name, kind="platform" if m.access_scope == "home" else "client",
                               status="active") for m in p.memberships if m.access_scope in ("home", "operations")]
            return Scope("assigned", orgs)
    raise ApiError(403, "forbidden", "The Command Center is for NovrSOC platform staff",
                   {"required": "platform:monitor, or a platform SOC role with assigned organizations"})


def _pick(scope: Scope, org: list[uuid.UUID] | None) -> list[CommandOrg]:
    if not org:
        return scope.orgs
    allowed = {o.id: o for o in scope.orgs}
    outside = [str(o) for o in org if o not in allowed]
    if outside:
        raise ApiError(403, "forbidden", "One or more organizations are outside your command scope", {"organizations": outside[:20]})
    return [allowed[o] for o in org]


# ---------------------------------------------------------------- views
@dataclass(frozen=True)
class View:
    permission: str
    sql: str                  # SELECT ... columns: id, at, title, severity, status, + view fields; WHERE {filters}
    search: tuple[str, ...]   # expressions matched by q (ILIKE)
    severity: str | None      # column holding the severity (filter + severity sort), if any
    status: str | None        # column holding the status (filter), if any
    at: str                   # the timestamp column (since filter, recent sort)
    fields: tuple[str, ...]
    extra: Callable[[dict], dict] | None = None


VIEWS: dict[str, View] = {
    "alerts": View("alerts:read", """SELECT a.id, a.observed_at AS at, a.rule_description AS title, a.severity, a.status, a.rule_id, a.rule_level,
                                            a.agent_id, a.agent_name, host(a.src_ip) AS src_ip, ls.name AS log_source, a.asset_id
                                     FROM novrsoc.alerts a LEFT JOIN novrsoc.log_sources ls ON ls.id = a.log_source_id""",
                   ("a.rule_description", "a.agent_name", "a.rule_id", "host(a.src_ip)"), "a.severity", "a.status", "a.observed_at",
                   ("rule_id", "rule_level", "agent_id", "agent_name", "src_ip", "log_source", "asset_id")),
    "assets": View("assets:read", """SELECT x.id, x.last_seen_at AS at, x.display_name AS title, x.criticality AS severity, x.status, x.kind,
                                            x.classification, x.exposure, host(x.primary_ip) AS primary_ip, x.hostname::text AS hostname,
                                            x.os_name
                                     FROM novrsoc.assets x""",
                   ("x.display_name", "x.hostname::text", "host(x.primary_ip)", "x.os_name"), "x.criticality", "x.status", "x.last_seen_at",
                   ("kind", "classification", "exposure", "primary_ip", "hostname", "os_name")),
    "vulnerabilities": View("vms:read", """SELECT f.id, f.last_seen_at AS at, f.title, f.severity, f.status, f.host, f.port, f.priority,
                                                  f.risk_score, f.cves, f.asset_id, f.source
                                           FROM novrsoc.vms_findings f""",
                            ("f.title", "f.host", "array_to_string(f.cves, ' ')"), "f.severity", "f.status", "f.last_seen_at",
                            ("host", "port", "priority", "risk_score", "cves", "asset_id", "source")),
    "scans": View("vms:read", """SELECT j.id, j.created_at AS at, CASE j.activity WHEN 'vuln_openvas' THEN 'NovrVMS vulnerability scan'
                                          WHEN 'vuln_nuclei' THEN 'NovrVMS web exposure checks' WHEN 'ports' THEN 'NovrVMS service discovery'
                                          ELSE 'NovrVMS ' || j.activity END || ' of ' || cardinality(j.targets) || ' target(s)' AS title,
                                        NULL::text AS severity, j.state AS status, j.activity, j.origin, cardinality(j.targets) AS targets,
                                        j.progress, j.error, j.finished_at
                                 FROM novrsoc.vms_scan_jobs j""",
                  ("j.activity", "array_to_string(j.targets, ' ')", "coalesce(j.error, '')"), None, "j.state", "j.created_at",
                  ("activity", "origin", "targets", "progress", "error", "finished_at")),
    "cases": View("cases:read", """SELECT c.id, c.updated_at AS at, c.title, c.severity, c.status, c.number, c.source, c.created_at,
                                          c.sla_resolution_due_at, c.assignee_id
                                   FROM novrsoc.cases c""",
                  ("c.title", "'CASE-' || lpad(c.number::text, 6, '0')"), "c.severity", "c.status", "c.updated_at",
                  ("number", "source", "created_at", "sla_resolution_due_at", "assignee_id")),
    "intel": View("intel:read", """SELECT m.id, m.matched_at AS at, i.type || ': ' || i.value AS title, m.confidence_band AS severity,
                                          m.verdict AS status, m.observable_type, m.observable_value, m.confidence, m.alert_id, i.source
                                   FROM novrsoc.ti_matches m JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id""",
                  ("i.value", "m.observable_value", "i.source"), None, "m.verdict", "m.matched_at",
                  ("observable_type", "observable_value", "confidence", "alert_id", "source")),
    "nhai": View("nhai:analyze", """SELECT j.id, coalesce(j.finished_at, j.queued_at) AS at, j.task || ' (' || j.subject_type || ')' AS title,
                                           NULL::text AS severity, j.status, j.task, j.subject_type, j.subject_id, j.error_code,
                                           j.review_decision, j.requested_label
                                    FROM novrsoc.nhai_jobs j""",
                 ("j.task", "j.subject_type", "coalesce(j.error_code, '')"), None, "j.status", "coalesce(j.finished_at, j.queued_at)",
                 ("task", "subject_type", "subject_id", "error_code", "review_decision", "requested_label")),
    "soar_runs": View("cases:read", """SELECT r.id, r.updated_at AS at, coalesce(p.title, p.name) AS title, NULL::text AS severity, r.state AS status,
                                              r.mode, r.case_id, p.name AS playbook, r.playbook_version, r.requested_label
                                       FROM novrsoc.soar_runs r JOIN novrsoc.soar_playbooks p ON p.id = r.playbook_id""",
                      ("p.name", "coalesce(p.title, '')", "r.requested_label"), None, "r.state", "r.updated_at",
                      ("mode", "case_id", "playbook", "playbook_version", "requested_label")),
    "soar_approvals": View("cases:read", """SELECT a.id, a.created_at AS at, a.action || ' on ' || a.target AS title, NULL::text AS severity,
                                                   coalesce(a.decision, CASE WHEN a.expires_at < now() THEN 'expired' ELSE 'pending' END) AS status,
                                                   a.action, a.target, a.justification, a.requested_label, a.decided_label, a.expires_at
                                            FROM novrsoc.soar_approvals a""",
                           ("a.action", "a.target", "a.justification"), None,
                           "coalesce(a.decision, CASE WHEN a.expires_at < now() THEN 'expired' ELSE 'pending' END)", "a.created_at",
                           ("action", "target", "justification", "requested_label", "decided_label", "expires_at")),
    "reports": View("reports:read", """SELECT r.id, r.requested_at AS at, r.report_type AS title, NULL::text AS severity, r.status,
                                              r.period_start, r.period_end, r.format, r.failure_reason, r.completed_at
                                       FROM novrsoc.report_requests r""",
                    ("r.report_type",), None, "r.status", "r.requested_at",
                    ("period_start", "period_end", "format", "failure_reason", "completed_at")),
}


def _views_for(p: Principal) -> list[str]:
    return [k for k, v in VIEWS.items() if p.has(v.permission)]


def _query(v: View, *, q: str | None, severity: str | None, status: str | None, since_hours: int | None, sort: str, limit: int):
    where, params = ["true"], {"n": limit + 1}
    if q:
        where.append("(" + " OR ".join(f"{e} ILIKE :ql" for e in v.search) + ")")
        params["ql"] = f"%{q.replace('%', '').replace('_', '')}%"
    if severity and v.severity:
        where.append(f"{v.severity} = :sev")
        params["sev"] = severity
    if status and v.status:
        where.append(f"{v.status} = :st")
        params["st"] = status
    if since_hours:
        where.append(f"{v.at} > now() - make_interval(hours => :since)")
        params["since"] = since_hours
    order = f"{SEV_RANK.format(c='s.severity')}, s.at DESC NULLS LAST" if sort == "severity" and v.severity else "s.at DESC NULLS LAST"
    return text(f"SELECT * FROM ({v.sql} WHERE {' AND '.join(where)}) s ORDER BY {order} LIMIT :n"), params


def _collect(conn: Connection, p: Principal, orgs: list[CommandOrg], name: str, *, q, severity, status, since_hours, sort, limit):
    v = VIEWS[name]
    stmt, params = _query(v, q=q, severity=severity, status=status, since_hours=since_hours, sort=sort, limit=limit)
    items, per, truncated = [], {}, False
    try:
        for o in orgs:
            _as(conn, o.id)                                   # this organization's RLS context, transaction-local
            rows = conn.execute(stmt, params).mappings().all()
            if len(rows) > limit:
                truncated, rows = True, rows[:limit]
            per[o.slug] = len(rows)
            for r in rows:
                items.append(CommandRecord(org=o, id=str(r["id"]), at=r["at"], title=str(r["title"] or "")[:300], severity=r["severity"],
                                           status=r["status"], fields={f: r[f] for f in v.fields}))
    finally:
        _as(conn, p.org_id)                                   # back to the caller's own context
    sev = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    epoch = datetime.min.replace(tzinfo=timezone.utc)
    if sort == "severity" and v.severity:
        items.sort(key=lambda r: (sev.get(r.severity or "", 4), -(r.at or epoch).timestamp()))
    else:
        items.sort(key=lambda r: r.at or epoch, reverse=True)
    if len(items) > limit:
        truncated = True
    return items[:limit], per, truncated


def _require_view(p: Principal, name: str) -> None:
    if name not in VIEWS:
        raise ApiError(404, "not_found", "Unknown view")
    if not p.has(VIEWS[name].permission):
        raise ApiError(403, "forbidden", "Insufficient permissions", {"required": VIEWS[name].permission})


def _audit(p: Principal, request: Request, action: str, view: str, orgs: list[CommandOrg], rows: int, filters: dict) -> None:
    audit.record(action, "success", org_id=p.home.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="command_view",
                 resource_id=view, request_id=request.state.request_id, ip=client_ip(request),
                 details={"organizations": len(orgs), "rows": rows, "filters": {k: v for k, v in filters.items() if v not in (None, [], "")}})


# ---------------------------------------------------------------- endpoints
@router.get("/scope", response_model=CommandScope, summary="Organizations and views in the caller's command scope")
def scope(include_archived: bool = False, p: Principal = Depends(current_principal),
          conn: Connection = Depends(request_connection)) -> CommandScope:
    s = command_scope(conn, p, include_archived)
    return CommandScope(scope=s.kind, organizations=s.orgs, views=_views_for(p), can_export=p.has("exports:manage"))


_POSTURE_SQL = text("""SELECT
  (SELECT count(*) FROM novrsoc.assets WHERE status = 'active') AS assets,
  (SELECT count(*) FROM novrsoc.alerts WHERE status IN ('new', 'acknowledged', 'in_progress')) AS open_alerts,
  (SELECT count(*) FROM novrsoc.alerts WHERE observed_at > now() - interval '24 hours') AS alerts_24h,
  (SELECT count(*) FROM novrsoc.alerts WHERE observed_at > now() - interval '24 hours' AND severity = 'critical') AS critical_alerts_24h,
  (SELECT count(*) FROM novrsoc.alerts WHERE observed_at > now() - interval '24 hours' AND severity = 'high') AS high_alerts_24h,
  (SELECT max(observed_at) FROM novrsoc.alerts) AS last_alert_at,
  (SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress')) AS open_cases,
  (SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress') AND severity = 'critical') AS critical_cases,
  (SELECT count(*) FROM novrsoc.vms_findings WHERE status NOT IN ('verified', 'risk_accepted')) AS open_findings,
  (SELECT count(*) FROM novrsoc.vms_findings WHERE status NOT IN ('verified', 'risk_accepted') AND severity = 'critical') AS critical_findings,
  (SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()) AS overdue_remediation,
  (SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'running') AS scans_running,
  (SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'failed' AND created_at > now() - interval '7 days') AS scans_failed_7d,
  coalesce((SELECT enabled FROM novrsoc.vms_scan_policies WHERE org_id = novrsoc.app_org()), false) AS scan_policy_enabled,
  (SELECT count(*) FROM novrsoc.ti_matches WHERE matched_at > now() - interval '7 days' AND verdict <> 'false_positive') AS intel_matches_7d,
  (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status IN ('queued', 'running')) AS nhai_queued,
  (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status IN ('failed', 'timed_out') AND finished_at > now() - interval '24 hours') AS nhai_failed_24h,
  (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status = 'succeeded' AND review_decision IS NULL) AS nhai_awaiting_review,
  (SELECT count(*) FROM novrsoc.soar_approvals WHERE decision IS NULL AND expires_at > now()) AS soar_pending_approvals,
  (SELECT count(*) FROM novrsoc.soar_runs WHERE created_at > now() - interval '7 days') AS soar_runs_7d,
  (SELECT count(*) FROM novrsoc.report_requests WHERE requested_at > now() - interval '7 days') AS reports_7d""")


def _posture(o: CommandOrg, r) -> OrgPosture:
    d = dict(r._mapping)
    reasons = []
    if d["critical_alerts_24h"]:
        reasons.append(f"{d['critical_alerts_24h']} critical alert(s) in 24 h")
    if d["critical_cases"]:
        reasons.append(f"{d['critical_cases']} open critical case(s)")
    if d["critical_findings"]:
        reasons.append(f"{d['critical_findings']} open critical finding(s)")
    if d["high_alerts_24h"]:
        reasons.append(f"{d['high_alerts_24h']} high alert(s) in 24 h")
    if d["overdue_remediation"]:
        reasons.append(f"{d['overdue_remediation']} overdue remediation task(s)")
    if d["soar_pending_approvals"]:
        reasons.append(f"{d['soar_pending_approvals']} response approval(s) waiting")
    if not (d["assets"] or d["last_alert_at"] or d["open_findings"]):
        posture = "no_data"
    elif d["critical_alerts_24h"] or d["critical_cases"] or d["critical_findings"]:
        posture = "critical"
    elif d["high_alerts_24h"] or d["overdue_remediation"] or d["soar_pending_approvals"]:
        posture = "elevated"
    else:
        posture = "normal"
    return OrgPosture(org=o, posture=posture, posture_reasons=reasons, **d)


@router.get("/overview", response_model=CommandOverview, summary="Security posture of every organization in the command scope")
def overview(request: Request, org: list[uuid.UUID] | None = Query(None), p: Principal = Depends(current_principal),
             conn: Connection = Depends(request_connection)) -> CommandOverview:
    s = command_scope(conn, p)
    orgs = _pick(s, org)
    rows = []
    try:
        for o in orgs:
            _as(conn, o.id)
            rows.append(_posture(o, conn.execute(_POSTURE_SQL).one()))
    finally:
        _as(conn, p.org_id)
    order = {"critical": 0, "elevated": 1, "normal": 2, "no_data": 3}
    rows.sort(key=lambda r: (order[r.posture], r.org.kind != "platform", r.org.name.lower()))
    keys = [k for k in OrgPosture.model_fields if k not in ("org", "posture", "posture_reasons", "last_alert_at", "scan_policy_enabled")]
    totals = {k: sum(getattr(r, k) for r in rows) for k in keys}
    totals.update(organizations=len(rows), **{f"posture_{k}": sum(1 for r in rows if r.posture == k) for k in order})
    _audit(p, request, "COMMAND_CENTER_VIEW", "overview", orgs, len(rows), {"org": [str(o) for o in org or []]})
    return CommandOverview(generated_at=_now(), scope=s.kind, organizations=rows, totals=totals)


def _filters(org, q, severity, status, since_hours, sort):
    return {"org": [str(o) for o in org or []], "q": q, "severity": severity, "status": status, "since_hours": since_hours, "sort": sort}


@router.get("/views/{view}", response_model=CommandList, summary="One platform-wide view: owner-labelled records from every organization in scope")
def view(view: str, request: Request, org: list[uuid.UUID] | None = Query(None), q: str | None = Query(None, max_length=120),
         severity: str | None = Query(None, pattern=r"^[a-z_]{2,20}$"), status: str | None = Query(None, pattern=r"^[a-z_]{2,40}$"),
         since_hours: int | None = Query(None, ge=1, le=24 * 365), sort: Literal["recent", "severity"] = "recent",
         limit: int = Query(100, ge=1, le=500), p: Principal = Depends(current_principal),
         conn: Connection = Depends(request_connection)) -> CommandList:
    _require_view(p, view)
    s = command_scope(conn, p)
    orgs = _pick(s, org)
    items, per, truncated = _collect(conn, p, orgs, view, q=q, severity=severity, status=status, since_hours=since_hours, sort=sort, limit=limit)
    _audit(p, request, "COMMAND_CENTER_VIEW", view, orgs, len(items), _filters(org, q, severity, status, since_hours, sort))
    return CommandList(view=view, generated_at=_now(), items=items, per_organization=per, truncated=truncated)  # type: ignore[arg-type]


@router.get("/views/{view}/export", summary="Export one platform-wide view as CSV, with the owning organization on every row (exports:manage)",
            response_class=Response, responses={200: {"content": {"text/csv": {}}}})
def export(view: str, request: Request, org: list[uuid.UUID] | None = Query(None), q: str | None = Query(None, max_length=120),
           severity: str | None = Query(None, pattern=r"^[a-z_]{2,20}$"), status: str | None = Query(None, pattern=r"^[a-z_]{2,40}$"),
           since_hours: int | None = Query(None, ge=1, le=24 * 365), sort: Literal["recent", "severity"] = "recent",
           p: Principal = Depends(current_principal), conn: Connection = Depends(request_connection)) -> Response:
    _require_view(p, view)
    if not p.has("exports:manage"):
        raise ApiError(403, "forbidden", "Insufficient permissions", {"required": "exports:manage"})
    s = command_scope(conn, p)
    orgs = _pick(s, org)
    items, _, truncated = _collect(conn, p, orgs, view, q=q, severity=severity, status=status, since_hours=since_hours, sort=sort,
                                   limit=EXPORT_MAX)
    buf = io.StringIO()
    cols = list(VIEWS[view].fields)
    w = csv.writer(buf)
    w.writerow(["organization_slug", "organization_name", "id", "at", "title", "severity", "status", *cols])
    for r in items:
        w.writerow([r.org.slug, r.org.name, r.id, r.at.isoformat() if r.at else "", _cell(r.title), r.severity or "", r.status or "",
                    *[_cell(r.fields.get(c)) for c in cols]])
    _audit(p, request, "COMMAND_CENTER_EXPORT", view, orgs, len(items), {**_filters(org, q, severity, status, since_hours, sort),
                                                                        "truncated": truncated})
    name = f"novrsoc-{view}-{_now():%Y%m%dT%H%M%SZ}.csv"
    return Response(buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{name}"', "Cache-Control": "no-store",
                             "X-NovrSOC-Truncated": "true" if truncated else "false"})


def _cell(v) -> str:
    """CSV cell; a leading formula character is neutralized (spreadsheet formula injection)."""
    if v is None:
        return ""
    s = ", ".join(map(str, v)) if isinstance(v, (list, tuple)) else str(v)
    return "'" + s if s[:1] in ("=", "+", "-", "@", "\t", "\r") else s
