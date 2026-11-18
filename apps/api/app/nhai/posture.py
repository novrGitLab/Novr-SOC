"""NHAI combined analysis bundles: an organization's security picture across SIEM, VMS, assets, cases, Threat Insights,
SOAR, remediation and posture, as cited AGGREGATES (counts and top items), never raw logs.

`aggregates()` reads ONE organization under its own row-level security (the caller sets app.org_id). The organization
bundle cites one evidence item per domain. The platform bundle (platform staff, platform organization active) cites one
item per organization of the caller's command scope, read organization by organization exactly as the Command Center
does, and app.org_id is restored afterwards. No record of one organization is copied into another; the platform job
holds counts only and lives in the platform organization.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

from novrsoc_contracts.v1.common import ResourceRef
from novrsoc_contracts.v1.nhai import ContextBundle, NhaiTask

OPEN_FINDING = "f.status NOT IN ('verified', 'risk_accepted')"


def aggregates(conn: Connection, p, window_days: int) -> dict:
    """Counts and top items of the organization in app.org_id (RLS), over `window_days`."""
    w = {"d": window_days}
    q = lambda sql, **kw: conn.execute(text(sql), {**w, **kw})  # noqa: E731
    out: dict = {"window_days": window_days}
    out["siem_alerts"] = {
        "by_severity": {r.severity: r.n for r in q("""SELECT severity, count(*) AS n FROM novrsoc.alerts
                                                      WHERE observed_at > now() - make_interval(days => :d) GROUP BY 1""")},
        "open_critical_high_unassigned": q("""SELECT count(*) FROM novrsoc.alerts WHERE severity IN ('critical', 'high')
                                              AND status <> 'closed' AND assignee_id IS NULL""").scalar(),
        "top_rules": [f"{r.rule_id} '{r.rule_description[:80]}' x{r.n}" for r in q(
            """SELECT rule_id, rule_description, count(*) AS n FROM novrsoc.alerts WHERE observed_at > now() - make_interval(days => :d)
               GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5""")]}
    out["vms_findings"] = {
        "open_by_severity": {r.severity: r.n for r in q(f"SELECT severity, count(*) AS n FROM novrsoc.vms_findings f WHERE {OPEN_FINDING} GROUP BY 1")},
        "open_p1": q(f"SELECT count(*) FROM novrsoc.vms_findings f WHERE {OPEN_FINDING} AND priority = 'P1'").scalar(),
        "open_kev": q(f"""SELECT count(*) FROM novrsoc.vms_findings f WHERE {OPEN_FINDING}
                          AND EXISTS (SELECT 1 FROM novrsoc.ti_cve_records c WHERE c.cve_id = ANY(f.cves) AND c.kev)""").scalar(),
        "riskiest_open": [f"{r.priority} {r.severity} '{r.title[:80]}' on {r.host} (risk {r.risk_score})" for r in q(
            f"SELECT priority, severity, title, host, risk_score FROM novrsoc.vms_findings f WHERE {OPEN_FINDING} ORDER BY risk_score DESC LIMIT 5")]}
    a = q("""SELECT count(*) AS active,
                    count(*) FILTER (WHERE criticality IN ('critical', 'high')) AS important,
                    count(*) FILTER (WHERE criticality IN ('critical', 'high') AND NOT EXISTS (
                        SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent')) AS important_unmonitored
             FROM novrsoc.assets a WHERE a.status = 'active'""").one()
    out["assets"] = {"active": a.active, "critical_or_high": a.important, "critical_or_high_without_agent": a.important_unmonitored}
    c = q("""SELECT count(*) FILTER (WHERE status = 'open') AS open, count(*) FILTER (WHERE status = 'in_progress') AS in_progress,
                    count(*) FILTER (WHERE created_at > now() - make_interval(days => :d)) AS opened_in_window,
                    count(*) FILTER (WHERE status IN ('open', 'in_progress') AND sla_resolution_due_at < now()) AS sla_breached_open
             FROM novrsoc.cases""").one()
    out["cases"] = dict(c._mapping)
    out["threat_insights"] = {
        "matches_in_window": q("""SELECT count(*) FROM novrsoc.ti_matches WHERE verdict <> 'false_positive'
                                  AND matched_at > now() - make_interval(days => :d)""").scalar(),
        "by_indicator_type": {r.type: r.n for r in q("""SELECT i.type, count(*) AS n FROM novrsoc.ti_matches m
                                                         JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id
                                                         WHERE m.verdict <> 'false_positive' AND m.matched_at > now() - make_interval(days => :d)
                                                         GROUP BY 1 ORDER BY 2 DESC LIMIT 5""")}}
    s = q("""SELECT count(*) AS runs, count(*) FILTER (WHERE origin = 'automatic') AS automatic,
                    count(*) FILTER (WHERE state = 'failed') AS failed, count(*) FILTER (WHERE state = 'awaiting_approval') AS awaiting
             FROM novrsoc.soar_runs WHERE created_at > now() - make_interval(days => :d)""").one()
    out["soar"] = {**dict(s._mapping), "pending_approvals": q(
        "SELECT count(*) FROM novrsoc.soar_approvals WHERE decision IS NULL AND expires_at > now()").scalar(),
        "emergency_stop": bool(q("SELECT emergency_stop FROM novrsoc.soar_policies").scalar())}
    r = q("""SELECT count(*) FILTER (WHERE status IN ('open', 'in_progress')) AS open,
                    count(*) FILTER (WHERE status IN ('open', 'in_progress') AND due_at < now()) AS overdue,
                    count(*) FILTER (WHERE status IN ('open', 'in_progress') AND priority = 'P1') AS open_p1
             FROM novrsoc.vms_remediation_tasks""").one()
    out["remediation"] = dict(r._mapping)
    from app.modules.posture import measures, score
    ms = measures(conn, p)
    sc = score(ms)
    out["posture"] = {"score": sc.score, "state": sc.state, "coverage_percent": sc.coverage_percent,
                      "measures": {m.key: (round(m.value, 1) if m.value is not None else None) for m in ms if m.state == "ok"},
                      "unavailable": [m.key for m in ms if m.state != "ok"]}
    return out


DOMAINS = [("siem_alerts", "SIEM alerts"), ("vms_findings", "VMS findings"), ("assets", "Asset inventory"), ("cases", "Cases"),
           ("threat_insights", "Threat Insights"), ("soar", "NovrSOAR"), ("remediation", "Remediation"), ("posture", "Posture")]


def organization_bundle(conn: Connection, p, window_days: int, *, max_chars: int) -> ContextBundle:
    from app.nhai.evidence import _Builder, _bounded
    agg = aggregates(conn, p, window_days)
    b = _Builder()
    now = datetime.now(timezone.utc)
    b.add("analysis_scope", p.org_id, {"scope": "organization", "window_days": window_days,
                                        "note": "aggregates of this organization only; counts are exact at assembly time"}, now)
    for key, label in DOMAINS:
        b.add(key, p.org_id, {"domain": label, **agg[key]}, now)
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=p.org_id, task=NhaiTask.POSTURE_ANALYSIS,
                         subject=ResourceRef(type="organization", id=str(p.org_id)), evidence=_bounded(b.items, max_chars),
                         assembled_at=now, assembled_for=p.user_id)


def platform_bundle(conn: Connection, p, orgs: list, window_days: int, *, max_chars: int) -> ContextBundle:
    """One evidence item per organization of the command scope, each read under that organization's RLS."""
    from app.nhai.evidence import _Builder, _bounded
    b = _Builder()
    now = datetime.now(timezone.utc)
    b.add("analysis_scope", p.org_id, {"scope": "platform", "window_days": window_days, "organizations": len(orgs),
                                        "note": "per-organization aggregates read under each organization's own access rules"}, now)
    try:
        for o in orgs:
            conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(o.id)})
            agg = aggregates(conn, p, window_days)
            b.add("organization_summary", o.id, {
                "organization": o.name,
                "alerts_by_severity": agg["siem_alerts"]["by_severity"],
                "open_critical_high_unassigned": agg["siem_alerts"]["open_critical_high_unassigned"],
                "open_findings_by_severity": agg["vms_findings"]["open_by_severity"], "open_kev": agg["vms_findings"]["open_kev"],
                "important_assets_without_agent": agg["assets"]["critical_or_high_without_agent"],
                "cases_open": agg["cases"]["open"], "cases_sla_breached": agg["cases"]["sla_breached_open"],
                "remediation_overdue": agg["remediation"]["overdue"], "soar_pending_approvals": agg["soar"]["pending_approvals"],
                "posture_score": agg["posture"]["score"]}, now)
    finally:
        conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(p.org_id)})
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=p.org_id, task=NhaiTask.POSTURE_ANALYSIS,
                         subject=ResourceRef(type="platform", id=str(p.org_id)), evidence=_bounded(b.items, max_chars),
                         assembled_at=now, assembled_for=p.user_id)
