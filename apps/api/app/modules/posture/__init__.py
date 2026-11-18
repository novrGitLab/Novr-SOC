"""Executive overview and security posture (consolidation; workstream E).

Explainable measurements only (contracts v1/posture.py). Each one names its numerator, denominator, formula and the
records behind it. A measurement without data is `unavailable` with the reason; one the role may not read is
`not_permitted`; neither is ever counted as 0 or 100. The posture score is the weighted mean of the AVAILABLE
measurements and is withheld when they carry less than half of the total weight.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.auth.deps import Principal, require
from app.connectors import registry
from app.connectors.base import ConnectorError
from app.core.config import Settings, get_settings
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.modules.endpoints import org_scope
from app.routers._responses import ERRORS
from app.secops import sla
from novrsoc_contracts.v1.posture import (CompliancePolicyRow, ComplianceView, ControlArea, ExecutiveOverview, Measure, PostureAssessment,
                                          PostureGap, PostureScore, Priority, TrendPoint)

MODULE = ModuleInfo(name="posture", workstream="E", prefix="/api/v1/posture",
                    summary="Executive overview and explainable security posture")
router = APIRouter(prefix="/api/v1/posture", tags=["posture"], responses=ERRORS)

OPEN = "('verified', 'risk_accepted')"
METHOD = ("Weighted mean of the available measurements (0-100 each). A measurement without data or permission is excluded, "
          "not scored; the score is withheld when the available weight is below 50%.")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _pct(key, label, num, den, *, weight, formula, href, reason_empty, perm_ok=True, higher=True) -> Measure:
    if not perm_ok:
        return Measure(key=key, label=label, unit="percent", state="not_permitted", reason="Your role cannot read the source records.",
                       weight=weight, formula=formula, evidence_href=href, higher_is_better=higher)
    if not den:
        return Measure(key=key, label=label, unit="percent", state="unavailable", reason=reason_empty, numerator=num, denominator=den,
                       weight=weight, formula=formula, evidence_href=href, higher_is_better=higher)
    return Measure(key=key, label=label, unit="percent", state="ok", value=round(100 * num / den, 1), numerator=num, denominator=den,
                   weight=weight, formula=formula, evidence_href=href, higher_is_better=higher)


def _count(key, label, value, *, href, perm_ok=True, higher=False, reason="") -> Measure:
    if not perm_ok:
        return Measure(key=key, label=label, unit="count", state="not_permitted", reason="Your role cannot read the source records.",
                       evidence_href=href, higher_is_better=higher)
    return Measure(key=key, label=label, unit="count", state="ok", value=float(value), numerator=int(value), evidence_href=href,
                   higher_is_better=higher, reason=reason)


def measures(conn: Connection, p: Principal) -> list[Measure]:
    a, v, c, al, pr = (p.has(x) for x in ("assets:read", "vms:read", "cases:read", "alerts:read", "protection:read"))
    hosts = conn.execute(text("""SELECT count(*) AS n,
            count(*) FILTER (WHERE EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent')) AS agent
            FROM novrsoc.assets a WHERE a.status = 'active' AND a.kind = 'host'""")).one()
    scannable = conn.execute(text("""SELECT count(*) AS n, count(*) FILTER (WHERE EXISTS (
            SELECT 1 FROM novrsoc.vms_scan_jobs j WHERE j.state = 'completed' AND j.finished_at > now() - interval '30 days'
              AND j.targets && ARRAY(SELECT i.value FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id
                                     AND i.kind IN ('ip', 'fqdn', 'domain', 'hostname')))) AS scanned
            FROM novrsoc.assets a WHERE a.status = 'active'""")).one()
    exposed = conn.execute(text(f"""SELECT count(DISTINCT a.id) AS with_findings,
            count(DISTINCT a.id) FILTER (WHERE f.severity IN ('critical', 'high')) AS crit
            FROM novrsoc.assets a JOIN novrsoc.vms_findings f ON f.asset_id = a.id AND f.status NOT IN {OPEN} WHERE a.status = 'active'""")).one()
    scanned_assets = conn.execute(text("SELECT count(DISTINCT asset_id) FROM novrsoc.vms_findings WHERE asset_id IS NOT NULL")).scalar()
    tasks = conn.execute(text("""SELECT count(*) FILTER (WHERE status <> 'cancelled') AS n,
            count(*) FILTER (WHERE status <> 'cancelled' AND NOT (status IN ('open', 'in_progress') AND due_at < now())
                             AND NOT (status = 'done' AND updated_at > due_at)) AS on_time FROM novrsoc.vms_remediation_tasks""")).one()
    cases = conn.execute(text("""SELECT created_at, sla_response_due_at, sla_resolution_due_at, first_response_at, resolved_at, sla_policy_snapshot
                                 FROM novrsoc.cases WHERE created_at > now() - interval '30 days' AND sla_response_due_at IS NOT NULL""")).all()
    decided = [sla.case_states(r)[0] for r in cases]
    decided = [s for s in decided if s in ("met", "breached")]
    triage = conn.execute(text("""SELECT count(*) AS n, count(*) FILTER (WHERE status <> 'new') AS triaged FROM novrsoc.alerts
                                  WHERE severity IN ('critical', 'high') AND observed_at > now() - interval '7 days'
                                  AND observed_at < now() - interval '1 hour'""")).one()
    dmarc = conn.execute(text("""SELECT count(*) AS n, count(*) FILTER (WHERE dmarc_policy IN ('quarantine', 'reject')) AS enf
                                 FROM novrsoc.email_domains""")).one()
    return [
        _pct("endpoint_coverage", "Endpoint agent coverage", hosts.agent, hosts.n, weight=0.15, perm_ok=a, href="/app/assets?monitoring=unmonitored",
             formula="host assets with a NovrAgent / active host assets", reason_empty="No host assets are in the inventory."),
        _pct("scan_coverage", "Vulnerability scan coverage (30 days)", scannable.scanned, scannable.n, weight=0.15, perm_ok=a and v,
             href="/app/vms/scans", formula="active assets in a completed VMS scan in 30 days / active assets",
             reason_empty="No assets are in the inventory."),
        _pct("exposure", "Assets without open critical or high findings", (scanned_assets or 0) - exposed.crit, scanned_assets, weight=0.2,
             perm_ok=v, href="/app/vms/risk", formula="assets with VMS findings and none open at critical/high / assets with VMS findings",
             reason_empty="No asset has VMS scan results yet, so exposure is not measured."),
        _pct("remediation_on_time", "Remediation on time", tasks.on_time, tasks.n, weight=0.15, perm_ok=v, href="/app/vms/remediation",
             formula="remediation tasks neither overdue nor closed late / remediation tasks", reason_empty="No remediation tasks exist."),
        _pct("sla_response", "Case response SLA met (30 days)", sum(1 for s in decided if s == "met"), len(decided), weight=0.15, perm_ok=c,
             href="/app/sla", formula="cases responded to within the SLA / cases with an SLA whose response is decided",
             reason_empty="No case in 30 days had an SLA policy and a decided response."),
        _pct("alert_triage", "Critical and high alerts triaged", triage.triaged, triage.n, weight=0.1, perm_ok=al, href="/app/alerts?severity=critical",
             formula="critical/high alerts of the last 7 days (older than 1 h) no longer new / those alerts",
             reason_empty="No critical or high alerts in the last 7 days."),
        _pct("dmarc_enforcement", "Email domains enforcing DMARC", dmarc.enf, dmarc.n, weight=0.1, perm_ok=pr, href="/app/email",
             formula="domains whose DMARC policy is quarantine or reject / registered domains", reason_empty="No email domains are registered."),
    ]


def score(ms: list[Measure]) -> PostureScore:
    total = sum(m.weight for m in ms)
    avail = [m for m in ms if m.state == "ok" and m.value is not None]
    w = sum(m.weight for m in avail)
    coverage = round(100 * w / total) if total else 0
    contrib, excluded = [m.key for m in avail], [m.key for m in ms if m not in avail]
    if w == 0 or coverage < 50:
        return PostureScore(score=None, state="insufficient_data", coverage_percent=coverage, method=METHOD, contributing=contrib, excluded=excluded)
    val = sum(m.weight * (m.value if m.higher_is_better else 100 - m.value) for m in avail) / w
    return PostureScore(score=round(val), state="ok", coverage_percent=coverage, method=METHOD, contributing=contrib, excluded=excluded)


def _weeks(conn: Connection, sql: str) -> list[TrendPoint]:
    rows = conn.execute(text(f"""SELECT w::date AS wk, {sql}
                                 FROM generate_series(date_trunc('week', now()) - interval '11 weeks', date_trunc('week', now()), interval '7 days') w
                                 ORDER BY w""")).mappings().all()
    return [TrendPoint(period_start=r["wk"], values={k: int(v) for k, v in r.items() if k != "wk"}) for r in rows]


def _priorities(conn: Connection, p: Principal) -> list[Priority]:
    out: list[Priority] = []
    if p.has("cases:read"):
        for r in conn.execute(text("""SELECT id, number, title, severity, created_at, sla_response_due_at, sla_resolution_due_at, first_response_at,
                                             resolved_at, sla_policy_snapshot FROM novrsoc.cases WHERE status IN ('open', 'in_progress')
                                             AND sla_resolution_due_at IS NOT NULL ORDER BY sla_resolution_due_at LIMIT 50""")):
            if "breached" in sla.case_states(r):
                out.append(Priority(kind="sla_breach", title=f"SLA breached: CASE-{r.number:06d}", detail=r.title, severity=r.severity,
                                    href=f"/app/cases/{r.id}"))
        appr = conn.execute(text("SELECT count(*) FROM novrsoc.soar_approvals WHERE decision IS NULL AND expires_at > now()")).scalar()
        if appr:
            out.append(Priority(kind="approvals", title=f"{appr} response approval(s) waiting", detail="Consequential SOAR steps wait for a second person.",
                                severity="high", href="/app/soar/approvals"))
    if p.has("vms:read"):
        n = conn.execute(text("""SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE priority = 'P1' AND status IN ('open', 'in_progress')
                                 AND due_at < now()""")).scalar()
        if n:
            out.append(Priority(kind="p1_overdue", title=f"{n} P1 remediation task(s) overdue", detail="Highest-risk findings past their due date.",
                                severity="critical", href="/app/vms/remediation"))
        k = conn.execute(text(f"""SELECT count(*) FROM novrsoc.vms_findings f WHERE f.status NOT IN {OPEN}
                                  AND EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)""")).scalar()
        if k:
            out.append(Priority(kind="kev", title=f"{k} open finding(s) with a known exploited CVE", detail="Listed in the organization's KEV intelligence.",
                                severity="critical", href="/app/vms/findings?kev=1"))
    if p.has("alerts:read"):
        n = conn.execute(text("SELECT count(*) FROM novrsoc.alerts WHERE severity = 'critical' AND status <> 'closed' AND assignee_id IS NULL")).scalar()
        if n:
            out.append(Priority(kind="unassigned_critical", title=f"{n} critical alert(s) unassigned", detail="Assign an analyst or open a case.",
                                severity="critical", href="/app/alerts?severity=critical"))
    if p.has("assets:read"):
        n = conn.execute(text("""SELECT count(*) FROM novrsoc.assets a WHERE a.status = 'active' AND a.criticality IN ('critical', 'high')
                                 AND NOT EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent')
                                 AND a.kind = 'host'""")).scalar()
        if n:
            out.append(Priority(kind="unmonitored_critical", title=f"{n} critical or high host(s) without an agent",
                                detail="No host telemetry for important assets.", severity="high", href="/app/assets?monitoring=unmonitored"))
    if conn.execute(text("SELECT emergency_stop FROM novrsoc.soar_policies")).scalar():
        out.append(Priority(kind="emergency_stop", title="SOAR emergency stop is on", detail="No run starts and nothing is dispatched.",
                            severity="high", href="/app/soar"))
    if p.has("handover:write"):
        n = conn.execute(text("""SELECT count(*) FROM novrsoc.shift_handovers WHERE status = 'submitted' AND author_id <> :u
                                 AND (incoming_user_id IS NULL OR incoming_user_id = :u)"""), {"u": p.user_id}).scalar()
        if n:
            out.append(Priority(kind="handover", title=f"{n} shift handover(s) to acknowledge", detail="", severity="medium", href="/app/handover"))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(out, key=lambda x: rank[x.severity])[:15]


@router.get("/overview", response_model=ExecutiveOverview, summary="Executive overview: posture, incidents, vulnerabilities, SLA, priorities")
def overview(p: Principal = Depends(require("org:read")), conn: Connection = Depends(request_connection),
             settings: Settings = Depends(get_settings)) -> ExecutiveOverview:
    from app.routers.platform import _nhai
    ms = measures(conn, p)
    by_key = {m.key: m for m in ms}
    a, v, c, al = (p.has(x) for x in ("assets:read", "vms:read", "cases:read", "alerts:read"))
    q = lambda sql: conn.execute(text(sql)).scalar() or 0  # noqa: E731
    kpis = [
        _count("assets", "Monitored assets", q("SELECT count(*) FROM novrsoc.assets WHERE status = 'active'"), href="/app/assets", perm_ok=a, higher=True),
        by_key["endpoint_coverage"],
        _count("open_incidents", "Open incidents", q("SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress')"), href="/app/cases", perm_ok=c),
        _count("critical_vulns", "Open critical vulnerabilities", q(f"SELECT count(*) FROM novrsoc.vms_findings WHERE status NOT IN {OPEN} AND severity = 'critical'"),
               href="/app/vms/findings?severity=critical", perm_ok=v),
        _count("overdue_remediation", "Overdue remediation", q("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()"),
               href="/app/vms/remediation", perm_ok=v),
        by_key["sla_response"],
        _count("critical_alerts_24h", "Critical alerts (24 h)", q("SELECT count(*) FROM novrsoc.alerts WHERE severity = 'critical' AND observed_at > now() - interval '24 hours'"),
               href="/app/alerts?severity=critical", perm_ok=al),
    ]
    vuln = _weeks(conn, f"""(SELECT count(*) FROM novrsoc.vms_findings f WHERE f.first_seen_at >= w AND f.first_seen_at < w + interval '7 days') AS new,
                            (SELECT count(*) FROM novrsoc.vms_remediation_tasks t WHERE t.status = 'done' AND t.updated_at >= w
                               AND t.updated_at < w + interval '7 days') AS resolved""") if v else []
    inc = _weeks(conn, """(SELECT count(*) FROM novrsoc.cases c WHERE c.created_at >= w AND c.created_at < w + interval '7 days') AS opened,
                          (SELECT count(*) FROM novrsoc.cases c WHERE c.resolved_at >= w AND c.resolved_at < w + interval '7 days') AS resolved,
                          (SELECT count(*) FROM novrsoc.alerts a WHERE a.severity IN ('critical', 'high') AND a.observed_at >= w
                             AND a.observed_at < w + interval '7 days') AS critical_high_alerts""") if c and al else []
    group = lambda sql: {r[0]: r[1] for r in conn.execute(text(sql))}  # noqa: E731
    org = conn.execute(text("SELECT name FROM novrsoc.organizations WHERE id = :o"), {"o": p.org_id}).scalar()
    return ExecutiveOverview(
        generated_at=_now(), organization=org, score=score(ms), kpis=kpis, measures=ms, vulnerability_trend=vuln, incident_trend=inc,
        findings_by_severity=group(f"SELECT severity, count(*) FROM novrsoc.vms_findings WHERE status NOT IN {OPEN} GROUP BY 1") if v else {},
        assets_by_criticality=group("SELECT criticality, count(*) FROM novrsoc.assets WHERE status = 'active' GROUP BY 1") if a else {},
        remediation_by_state=group("SELECT status, count(*) FROM novrsoc.vms_remediation_tasks GROUP BY 1") if v else {},
        priorities=_priorities(conn, p), sources=[*registry.wazuh_states(settings), _nhai(conn, settings)[1]])


def compliance(conn: Connection, p: Principal, settings: Settings) -> ComplianceView:
    state = registry.wazuh_states(settings)[0]
    source = registry.wazuh(settings)
    if not p.has("endpoints:read"):
        return ComplianceView(source=state.model_copy(update={"detail": "Your role cannot read endpoint configuration assessments."}),
                              note="Not permitted for your role.")
    if source is None or state.state not in ("connected", "local_fixture"):
        return ComplianceView(source=state, note="Configuration assessment (NovrAgent SCA) is unavailable: " + (state.detail or state.state))
    scope = org_scope(conn, p.org_id)
    agg: dict[str, dict] = {}
    n = 0
    try:
        for ag in source.list_agents(scope)[:200]:
            pols = source.sca_policies(scope, ag.agent_id)
            n += 1 if pols else 0
            for x in pols:
                d = agg.setdefault(x.policy_id, {"name": x.name, "eps": 0, "scores": [], "failed": 0, "passed": 0})
                d["eps"] += 1
                d["scores"].append(x.score_percent)
                d["failed"] += x.failed
                d["passed"] += x.passed
    except ConnectorError as e:
        return ComplianceView(source=state.model_copy(update={"state": "unavailable", "detail": str(e)[:300]}), note="The connector failed.")
    return ComplianceView(source=state, endpoints_assessed=n,
                          note="Local fixture data (development); not live telemetry." if state.state == "local_fixture" else "",
                          policies=[CompliancePolicyRow(policy_id=k, name=d["name"], endpoints=d["eps"],
                                                        average_score=round(sum(d["scores"]) / len(d["scores"])) if d["scores"] else None,
                                                        failed_checks=d["failed"], passed_checks=d["passed"]) for k, d in sorted(agg.items())])


def _gaps(conn: Connection, p: Principal) -> list[PostureGap]:
    g: list[PostureGap] = []
    q = lambda sql: conn.execute(text(sql)).scalar() or 0  # noqa: E731
    if not q("SELECT count(*) FROM novrsoc.sla_policies"):
        g.append(PostureGap(key="no_sla", title="No SLA policies", detail="Cases have no response or resolution targets; SLA cannot be measured.",
                            severity="high", href="/app/sla"))
    if not q("SELECT count(*) FROM novrsoc.wazuh_group_mappings"):
        g.append(PostureGap(key="no_wazuh_mapping", title="No NovrAgent groups mapped",
                            detail="No alert or endpoint can be attributed to this organization.", severity="high", href="/app/admin/wazuh-groups"))
    if not q("SELECT count(*) FROM novrsoc.soar_policies"):
        g.append(PostureGap(key="no_response_policy", title="No response policy", detail="Every consequential SOAR step is refused until one is set.",
                            severity="medium", href="/app/soar"))
    n = q("""SELECT count(*) FROM novrsoc.assets a WHERE a.status = 'active' AND a.kind = 'host'
             AND NOT EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent')""")
    if n:
        g.append(PostureGap(key="hosts_without_agent", title=f"{n} host(s) without a NovrAgent", detail="No host telemetry or configuration assessment.",
                            severity="high", href="/app/assets?monitoring=unmonitored"))
    n = q("""SELECT count(*) FROM novrsoc.assets a WHERE a.status = 'active' AND NOT EXISTS (SELECT 1 FROM novrsoc.vms_scan_jobs j
             WHERE j.state = 'completed' AND j.targets && ARRAY(SELECT i.value FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id))""")
    if n:
        g.append(PostureGap(key="never_scanned", title=f"{n} asset(s) never scanned", detail="Their vulnerability state is unknown, not clean.",
                            severity="medium", href="/app/vms/scans"))
    n = q("SELECT count(*) FROM novrsoc.email_domains WHERE coalesce(dmarc_policy, 'missing') IN ('none', 'missing')")
    if n:
        g.append(PostureGap(key="dmarc_not_enforced", title=f"{n} email domain(s) without DMARC enforcement",
                            detail="Spoofed mail from these domains is not rejected.", severity="medium", href="/app/email"))
    if not q("SELECT count(*) FROM novrsoc.recovery_plans"):
        g.append(PostureGap(key="no_recovery_plan", title="No recovery plan", detail="Data loss has no documented recovery path.", severity="medium",
                            href="/app/recovery"))
    n = q("SELECT count(*) FROM novrsoc.recovery_plans WHERE last_tested_at IS NULL OR last_tested_at < now() - interval '90 days'")
    if n:
        g.append(PostureGap(key="untested_recovery", title=f"{n} recovery plan(s) untested in 90 days", detail="Untested recovery is assumed, not known.",
                            severity="low", href="/app/recovery"))
    n = q(f"SELECT count(*) FROM novrsoc.vms_findings WHERE asset_id IS NULL AND status NOT IN {OPEN}")
    if n:
        g.append(PostureGap(key="unlinked_findings", title=f"{n} open finding(s) not linked to an asset", detail="Their owner and criticality are unknown.",
                            severity="low", href="/app/vms/findings"))
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(g, key=lambda x: rank[x.severity])


@router.get("/assessment", response_model=PostureAssessment, summary="Security posture: control areas, compliance, gaps, remediation trend")
def assessment(p: Principal = Depends(require("org:read")), conn: Connection = Depends(request_connection),
               settings: Settings = Depends(get_settings)) -> PostureAssessment:
    ms = {m.key: m for m in measures(conn, p)}
    v = p.has("vms:read")
    mttr = conn.execute(text("""SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM t.updated_at - f.first_seen_at) / 86400)
                                FROM novrsoc.vms_remediation_tasks t JOIN novrsoc.vms_findings f ON f.id = t.finding_id
                                WHERE t.status = 'done'""")).scalar() if v else None
    mttr_m = (Measure(key="mttr_days", label="Median time to remediate", unit="count", state="ok", value=round(float(mttr), 1),
                      reason="days, from first detection to verified fix", formula="median(verified fix - first seen) over closed tasks",
                      evidence_href="/app/vms/remediation", higher_is_better=False) if mttr is not None else
              Measure(key="mttr_days", label="Median time to remediate", unit="count", state="unavailable" if v else "not_permitted",
                      reason="No remediation task has been verified as fixed." if v else "Your role cannot read the source records.",
                      evidence_href="/app/vms/remediation", higher_is_better=False))
    q = lambda sql: conn.execute(text(sql)).scalar() or 0  # noqa: E731
    stale = _count("stale_cases", "Cases open for more than 30 days",
                   q("SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress') AND created_at < now() - interval '30 days'"),
                   href="/app/cases", perm_ok=p.has("cases:read"))
    kev = _count("kev_findings", "Open findings with a known exploited CVE",
                 q(f"""SELECT count(*) FROM novrsoc.vms_findings f WHERE f.status NOT IN {OPEN}
                       AND EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)"""),
                 href="/app/insights/cves", perm_ok=v)
    areas = [
        ControlArea(key="coverage", title="Asset coverage", description="Whether the platform can see the organization's assets.",
                    measures=[ms["endpoint_coverage"], ms["scan_coverage"]]),
        ControlArea(key="exposure", title="Vulnerability exposure", description="Open critical and high findings, and known exploitation.",
                    measures=[ms["exposure"], kev]),
        ControlArea(key="remediation", title="Remediation", description="Whether findings are fixed within their due dates.",
                    measures=[ms["remediation_on_time"], mttr_m]),
        ControlArea(key="detection_response", title="Detection and response", description="Triage and case handling against targets.",
                    measures=[ms["alert_triage"], ms["sla_response"], stale]),
        ControlArea(key="email", title="Email protection", description="Domain authentication enforcement.", measures=[ms["dmarc_enforcement"]]),
    ]
    trend = _weeks(conn, """(SELECT count(*) FROM novrsoc.vms_remediation_tasks t WHERE t.created_at >= w AND t.created_at < w + interval '7 days') AS opened,
                            (SELECT count(*) FROM novrsoc.vms_remediation_tasks t WHERE t.status = 'done' AND t.updated_at >= w
                               AND t.updated_at < w + interval '7 days') AS closed""") if v else []
    return PostureAssessment(generated_at=_now(), score=score(list(ms.values())), areas=areas, gaps=_gaps(conn, p),
                             compliance=compliance(conn, p, settings), remediation_trend=trend)
