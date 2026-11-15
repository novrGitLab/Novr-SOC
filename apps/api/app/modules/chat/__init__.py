"""NovrChat (consolidation; workstream F): questions over the active organization's own records.

Read-only tools, chosen deterministically from the question (contracts v1/chat.py). Each tool checks its permission
and runs under the organization's row-level security; retrieved records become citations C1..Cn. The immediate answer
restates the records only. When NHAI is configured and the caller holds nhai:analyze, a `chat_answer` NHAI job drafts
prose from the same citations through the shared worker, gateway and validator (never a second AI engine).
Requests to act (block, isolate, disable, approve, delete, run) are refused: NovrChat never changes a record, except
a report it generates on request for a caller with reports:manage. Every exchange is audited and in ai_activity.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request, Response
from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import activity
from app.audit import service as audit
from app.auth.deps import Principal, client_ip, require
from app.core.config import Settings, get_settings
from app.core.errors import not_found
from app.db.session import request_connection
from app.modules import ModuleInfo
from app.routers._responses import ERRORS
from novrsoc_contracts.v1.chat import (ChatCitation, ChatConversationCreate, ChatConversationList, ChatConversationView, ChatMessageCreate,
                                       ChatMessageView, ChatToolCall, ChatExchange)
from novrsoc_contracts.v1.common import ResourceRef

MODULE = ModuleInfo(name="chat", workstream="F", prefix="/api/v1/chat",
                    summary="NovrChat: read-only, tenant-scoped questions over alerts, cases, assets, vulnerabilities, posture and intelligence")
router = APIRouter(prefix="/api/v1/chat", tags=["chat"], responses=ERRORS)

OPEN = "('verified', 'risk_accepted')"
ACTION = re.compile(r"\b(block|isolate|quarantine|disable|delete|remove|approve|reject|execute|run (the )?playbook|shut ?down|kill|wipe|"
                    r"reset (the )?password|contain)\b", re.I)
IP = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
CVE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.I)
DOMAIN = re.compile(r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.I)
SHA256 = re.compile(r"\b[a-f0-9]{64}\b", re.I)
REPORT_KIND = [("executive", "executive"), ("secops", "secops"), ("soc", "secops"), ("vulnerab", "vms_executive"), ("vms", "vms_executive"),
               ("threat", "threat_intel"), ("intel", "threat_intel"), ("brand", "brand_protection"), ("email", "email_security"),
               ("sla", "sla"), ("audit", "audit"), ("compliance", "compliance_sca")]


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Ctx:
    def __init__(self, conn: Connection, p: Principal, q: str, settings: Settings, request: Request):
        self.conn, self.p, self.q, self.settings, self.request = conn, p, q, settings, request
        self.low = q.lower()
        self.cites: list[ChatCitation] = []
        self.lines: list[str] = []
        self.tools: list[ChatToolCall] = []

    def cite(self, ref_type: str, ref_id, label: str, excerpt: str, href: str = "") -> str:
        cid = f"C{len(self.cites) + 1}"
        self.cites.append(ChatCitation(citation_id=cid, ref=ResourceRef(type=ref_type, id=str(ref_id)[:200]), label=label[:200],
                                       excerpt=excerpt[:1000], href=href))
        return cid

    def tool(self, name: str, perm: str, state: str, detail: str = "", records: int = 0) -> None:
        self.tools.append(ChatToolCall(tool=name, permission=perm, state=state, detail=detail, records=records))


def _window(low: str) -> tuple[timedelta, str]:
    if "today" in low or "24 h" in low or "24h" in low or "last day" in low:
        return timedelta(hours=24), "the last 24 hours"
    if "month" in low or "30 day" in low:
        return timedelta(days=30), "the last 30 days"
    return timedelta(days=7), "the last 7 days"


def t_alerts(c: Ctx) -> None:
    span, label = _window(c.low)
    sev = [s for s in ("critical", "high", "medium", "low") if s in c.low] or ["critical", "high", "medium", "low"]
    rows = c.conn.execute(text("""SELECT id, rule_description, severity, status, agent_name, observed_at, source FROM novrsoc.alerts
                                  WHERE observed_at > :since AND severity = ANY(:sev) ORDER BY
                                  CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, observed_at DESC LIMIT 8"""),
                          {"since": _now() - span, "sev": sev}).all()
    counts = {r[0]: r[1] for r in c.conn.execute(text("""SELECT severity, count(*) FROM novrsoc.alerts WHERE observed_at > :since
                                                         AND severity = ANY(:sev) GROUP BY 1"""), {"since": _now() - span, "sev": sev})}
    if not counts:
        older = c.conn.execute(text("""SELECT id, rule_description, severity, status, agent_name, observed_at, source FROM novrsoc.alerts
                                       WHERE severity = ANY(:sev) ORDER BY observed_at DESC LIMIT 5"""), {"sev": sev}).all()
        c.tool("alerts", "alerts:read", "empty" if not older else "ok", f"No {'/'.join(sev)} alerts in {label}.", len(older))
        c.lines.append(f"Alerts: none at {'/'.join(sev)} severity in {label}." +
                       (" The most recent ones were:" if older else ""))
        for r in older:
            cid = c.cite("alert", r.id, f"{r.severity} alert on {r.agent_name or 'unknown agent'}",
                         f"{r.rule_description} | status {r.status} | {r.observed_at:%Y-%m-%d %H:%M} UTC" + (" | local fixture" if r.source == "local_fixture" else ""),
                         f"/app/alerts/{r.id}")
            c.lines.append(f"  - {r.observed_at:%Y-%m-%d}: {r.severity} {r.rule_description} ({r.status}) [{cid}]")
        return
    c.tool("alerts", "alerts:read", "ok", f"{sum(counts.values())} alerts in {label}", len(rows))
    parts = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low") if s in counts)
    c.lines.append(f"Alerts in {label}: {parts}.")
    for r in rows:
        cid = c.cite("alert", r.id, f"{r.severity} alert on {r.agent_name or 'unknown agent'}",
                     f"{r.rule_description} | status {r.status} | {r.observed_at:%Y-%m-%d %H:%M} UTC" + (" | local fixture" if r.source == "local_fixture" else ""),
                     f"/app/alerts/{r.id}")
        c.lines.append(f"  - {r.severity}: {r.rule_description} on {r.agent_name or 'unknown agent'} ({r.status}) [{cid}]")


def t_cases(c: Ctx) -> None:
    rows = c.conn.execute(text("""SELECT id, number, title, severity, status, created_at FROM novrsoc.cases WHERE status IN ('open', 'in_progress')
                                  ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END, created_at LIMIT 8""")).all()
    n = c.conn.execute(text("SELECT count(*) FROM novrsoc.cases WHERE status IN ('open', 'in_progress')")).scalar()
    if not n:
        c.tool("cases", "cases:read", "empty", "No open cases.")
        c.lines.append("Cases: no open cases.")
        return
    c.tool("cases", "cases:read", "ok", f"{n} open cases", len(rows))
    c.lines.append(f"Open cases: {n}.")
    for r in rows:
        cid = c.cite("case", r.id, f"CASE-{r.number:06d}", f"{r.title} | {r.severity} | {r.status} | opened {r.created_at:%Y-%m-%d}", f"/app/cases/{r.id}")
        c.lines.append(f"  - CASE-{r.number:06d} ({r.severity}, {r.status}): {r.title} [{cid}]")


def t_sla(c: Ctx) -> None:
    from app.modules.secops import open_case_slas
    from app.secops import sla
    items = open_case_slas(c.conn)
    if not items:
        c.tool("sla", "cases:read", "empty", "No open cases.")
        c.lines.append("SLA: no open cases to track.")
        return
    states = [sla.overall(i.response_state, i.resolution_state) for i in items]
    counts = {s: states.count(s) for s in set(states)}
    c.tool("sla", "cases:read", "ok", ", ".join(f"{v} {k}" for k, v in counts.items()), len(items))
    c.lines.append("SLA of open cases: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in sorted(counts.items())) + ".")
    for i, s in zip(items, states):
        if s in ("breached", "at_risk"):
            cid = c.cite("case", i.case_id, i.reference, f"{i.title} | SLA {s} | resolution due {i.resolution_due_at}", f"/app/cases/{i.case_id}")
            c.lines.append(f"  - {i.reference}: SLA {s.replace('_', ' ')} [{cid}]")


def t_assets(c: Ctx) -> None:
    needles = IP.findall(c.q) + [d for d in DOMAIN.findall(c.q) if not CVE.match(d)]
    words = [w for w in re.findall(r"[A-Za-z0-9][A-Za-z0-9._-]{2,62}", c.q) if w.lower() not in {
        "asset", "assets", "host", "hosts", "server", "servers", "endpoint", "endpoints", "the", "what", "which", "show", "about", "inventory",
        "tell", "list", "device", "devices", "machine", "machines", "with", "have", "has", "are", "our", "and", "for", "unmonitored", "critical"}]
    rows = []
    for n in needles + words[:5]:
        rows += c.conn.execute(text("""SELECT DISTINCT a.id, a.display_name, a.kind, a.criticality, a.classification, a.status FROM novrsoc.assets a
                                       LEFT JOIN novrsoc.asset_identifiers i ON i.asset_id = a.id
                                       WHERE a.display_name ILIKE :q OR i.value = lower(:x) LIMIT 5"""), {"q": f"%{n}%", "x": n}).all()
    if not rows:
        stats = c.conn.execute(text("""SELECT count(*) AS n, count(*) FILTER (WHERE criticality IN ('critical', 'high')) AS crit,
            count(*) FILTER (WHERE kind = 'host' AND NOT EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id
                             AND i.kind = 'wazuh_agent')) AS no_agent FROM novrsoc.assets a WHERE status = 'active'""")).one()
        c.tool("assets", "assets:read", "ok" if stats.n else "empty", f"{stats.n} active assets", 0)
        c.lines.append(f"Asset inventory: {stats.n} active assets, {stats.crit} critical or high, {stats.no_agent} host(s) without a Wazuh agent."
                       if stats.n else "Asset inventory: no assets are recorded.")
        return
    seen = {}
    for r in rows:
        seen.setdefault(r.id, r)
    c.tool("assets", "assets:read", "ok", f"{len(seen)} matching asset(s)", len(seen))
    for r in list(seen.values())[:6]:
        f = c.conn.execute(text(f"""SELECT count(*) FILTER (WHERE true) AS n, count(*) FILTER (WHERE severity = 'critical') AS crit
                                    FROM novrsoc.vms_findings WHERE asset_id = :a AND status NOT IN {OPEN}"""), {"a": r.id}).one()
        al = c.conn.execute(text("SELECT count(*) FROM novrsoc.alerts WHERE asset_id = :a AND status <> 'closed'"), {"a": r.id}).scalar()
        cid = c.cite("asset", r.id, r.display_name, f"{r.kind}, {r.classification}, criticality {r.criticality}, {r.status}; "
                                                    f"{f.n} open findings ({f.crit} critical); {al} open alerts", f"/app/assets/{r.id}")
        c.lines.append(f"  - {r.display_name} ({r.kind}, criticality {r.criticality}): {f.n} open findings, {al} open alerts [{cid}]")


def t_vulns(c: Ctx) -> None:
    cves = sorted({x.upper() for x in CVE.findall(c.q)})
    if cves:
        rows = c.conn.execute(text(f"""SELECT id, title, host, severity, status, priority FROM novrsoc.vms_findings WHERE cves && :c
                                       AND status NOT IN {OPEN} ORDER BY risk_score DESC LIMIT 10"""), {"c": cves}).all()
        from app.insights.cve import merged
        intel = c.conn.execute(text(f"SELECT * FROM ({merged('WHERE cve_id = ANY(:c)')}) m ORDER BY cve_id"), {"c": cves}).all()
        c.tool("vulnerabilities", "vms:read", "ok" if rows or intel else "empty", f"{len(rows)} open finding(s) for {', '.join(cves)}", len(rows))
        for i in intel:
            cid = c.cite("cve_intel", i.cve_id, i.cve_id, f"CVSS {i.cvss_v3 if i.cvss_v3 is not None else 'unknown'}; EPSS "
                                                          f"{i.epss if i.epss is not None else 'unknown'}; KEV {'yes' if i.kev else 'no'}; {i.description[:300]}",
                         "/app/insights/cves")
            c.lines.append(f"{i.cve_id}: CVSS {i.cvss_v3 if i.cvss_v3 is not None else 'unknown'}, {'known exploited (KEV)' if i.kev else 'not in KEV'} [{cid}]")
        missing = set(cves) - {i.cve_id for i in intel}
        if missing:
            c.lines.append(f"No CVE intelligence is recorded for {', '.join(sorted(missing))}.")
        c.lines.append(f"Open findings naming {', '.join(cves)}: {len(rows)}." if rows else f"No open finding names {', '.join(cves)}.")
        for r in rows:
            cid = c.cite("vms_finding", r.id, r.title, f"{r.host} | {r.severity} | {r.priority} | {r.status}", f"/app/vms/findings?finding={r.id}")
            c.lines.append(f"  - {r.priority} {r.title} on {r.host} ({r.status}) [{cid}]")
        return
    stats = c.conn.execute(text(f"""SELECT count(*) AS n, count(*) FILTER (WHERE severity = 'critical') AS crit,
                                    count(*) FILTER (WHERE priority = 'P1') AS p1 FROM novrsoc.vms_findings WHERE status NOT IN {OPEN}""")).one()
    overdue = c.conn.execute(text("SELECT count(*) FROM novrsoc.vms_remediation_tasks WHERE status IN ('open', 'in_progress') AND due_at < now()")).scalar()
    if not stats.n:
        c.tool("vulnerabilities", "vms:read", "empty", "No open findings.")
        c.lines.append("Vulnerabilities: no open findings are recorded (this does not mean every asset was scanned).")
        return
    rows = c.conn.execute(text(f"""SELECT id, title, host, severity, priority, status, cves FROM novrsoc.vms_findings WHERE status NOT IN {OPEN}
                                   ORDER BY risk_score DESC LIMIT 6""")).all()
    c.tool("vulnerabilities", "vms:read", "ok", f"{stats.n} open findings", len(rows))
    c.lines.append(f"Vulnerabilities: {stats.n} open findings, {stats.crit} critical, {stats.p1} P1; {overdue} remediation task(s) overdue.")
    for r in rows:
        cid = c.cite("vms_finding", r.id, r.title, f"{r.host} | {r.severity} | {r.priority} | CVEs {', '.join(r.cves) or 'none'}",
                     f"/app/vms/findings?finding={r.id}")
        c.lines.append(f"  - {r.priority} {r.title} on {r.host} [{cid}]")


def t_posture(c: Ctx) -> None:
    from app.modules.posture import measures, score
    ms = measures(c.conn, c.p)
    sc = score(ms)
    c.tool("posture", "org:read", "ok", f"score {sc.score if sc.score is not None else 'withheld'}", len(ms))
    c.lines.append(f"Security posture score: {sc.score} (measurements covering {sc.coverage_percent}% of the weight)." if sc.score is not None
                   else f"Security posture score: withheld; the available measurements cover only {sc.coverage_percent}% of the weight.")
    for m in ms:
        if m.state == "ok":
            cid = c.cite("posture_measure", m.key, m.label, f"{m.value}% = {m.numerator}/{m.denominator} ({m.formula})", m.evidence_href)
            c.lines.append(f"  - {m.label}: {m.value}% ({m.numerator}/{m.denominator}) [{cid}]")
        else:
            c.lines.append(f"  - {m.label}: {m.state.replace('_', ' ')} ({m.reason})")


def t_intel(c: Ctx) -> None:
    obs = IP.findall(c.q) + [d for d in DOMAIN.findall(c.q) if "." in d and not CVE.match(d)] + SHA256.findall(c.q)
    if obs:
        rows = c.conn.execute(text("""SELECT i.id, i.type, i.value, i.source, i.confidence, i.tlp,
                                             (SELECT count(*) FROM novrsoc.ti_matches m WHERE m.indicator_id = i.id) AS matches
                                      FROM novrsoc.ti_indicators i WHERE lower(i.value) = ANY(:v)"""), {"v": [o.lower() for o in obs]}).all()
        c.tool("threat_intel", "intel:read", "ok" if rows else "empty", f"{len(rows)} indicator(s) for {', '.join(obs[:3])}", len(rows))
        if not rows:
            c.lines.append(f"Threat intelligence: {', '.join(obs[:3])} is not among the organization's indicators (absence is not evidence of benign).")
        for r in rows:
            cid = c.cite("ti_indicator", r.id, f"{r.type} {r.value}", f"source {r.source}, confidence {r.confidence}, TLP {r.tlp}, "
                                                                   f"{r.matches} match(es) in this organization's alerts", "/app/insights")
            c.lines.append(f"  - {r.type} {r.value}: from {r.source}, {r.matches} match(es) in your alerts [{cid}]")
        return
    if "actor" in c.low or "apt" in c.low or "group" in c.low:
        rows = c.conn.execute(text("""SELECT id, name, attribution, confidence, target_sectors FROM novrsoc.ti_threat_actors ORDER BY
                                      CASE attribution WHEN 'verified' THEN 0 WHEN 'suspected' THEN 1 ELSE 2 END, name LIMIT 8""")).all()
        c.tool("threat_actors", "intel:read", "ok" if rows else "empty", f"{len(rows)} actor profile(s)", len(rows))
        if not rows:
            c.lines.append("Threat actors: no actor profiles are recorded. NovrSOC does not name actors on its own.")
        for r in rows:
            cid = c.cite("ti_actor", r.id, r.name, f"attribution {r.attribution}, confidence {r.confidence}; sectors {', '.join(r.target_sectors) or 'n/a'}",
                         "/app/insights/actors")
            c.lines.append(f"  - {r.name}: attribution {r.attribution} (confidence {r.confidence}) [{cid}]")
        return
    rows = c.conn.execute(text("""SELECT m.id, i.type, i.value, m.confidence, m.verdict, m.matched_at FROM novrsoc.ti_matches m
                                  JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id WHERE m.verdict <> 'false_positive'
                                  ORDER BY m.matched_at DESC LIMIT 8""")).all()
    c.tool("threat_intel", "intel:read", "ok" if rows else "empty", f"{len(rows)} recent match(es)", len(rows))
    if not rows:
        c.lines.append("Threat intelligence: no indicator has matched the organization's alerts.")
    for r in rows:
        cid = c.cite("ti_match", r.id, f"{r.type} {r.value}", f"confidence {r.confidence}, verdict {r.verdict}, matched {r.matched_at:%Y-%m-%d}",
                     "/app/insights")
        c.lines.append(f"  - {r.type} {r.value} matched (confidence {r.confidence}, {r.verdict}) [{cid}]")


def t_soar(c: Ctx) -> None:
    pend = c.conn.execute(text("""SELECT id, action, target, requested_label, expires_at FROM novrsoc.soar_approvals
                                  WHERE decision IS NULL AND expires_at > now() ORDER BY expires_at LIMIT 8""")).all()
    runs = {r[0]: r[1] for r in c.conn.execute(text("""SELECT state, count(*) FROM novrsoc.soar_runs WHERE created_at > now() - interval '7 days'
                                                       GROUP BY 1"""))}
    stop = c.conn.execute(text("SELECT emergency_stop FROM novrsoc.soar_policies")).scalar()
    c.tool("soar", "cases:read", "ok", f"{len(pend)} pending approval(s)", len(pend))
    c.lines.append(("SOAR emergency stop is ON. " if stop else "") + "SOAR runs in 7 days: " +
                   (", ".join(f"{v} {k.replace('_', ' ')}" for k, v in runs.items()) or "none") + f"; {len(pend)} approval(s) pending.")
    for a in pend:
        cid = c.cite("soar_approval", a.id, f"{a.action} {a.target}", f"requested by {a.requested_label}, expires {a.expires_at:%Y-%m-%d %H:%M} UTC",
                     "/app/soar/approvals")
        c.lines.append(f"  - {a.action} on {a.target}, waiting for a second person [{cid}]")


def t_reports(c: Ctx) -> None:
    wants = re.search(r"\b(generate|create|make|produce|prepare)\b", c.low) and "report" in c.low
    if wants:
        if not c.p.has("reports:manage"):
            c.tool("generate_report", "reports:manage", "not_permitted", "Your role cannot generate reports.")
            c.lines.append("Report generation: not permitted for your role.")
            return
        from app.modules.reports import BUILDERS
        from novrsoc_contracts.v1.governance import ReportType
        kind = next((v for k, v in REPORT_KIND if k in c.low), "executive")
        rt = ReportType(kind)
        end = _now()
        start = end - timedelta(days=30)
        sections = BUILDERS[rt](c.conn, c.p, c.settings, start, end)
        content = {"type": kind, "period_start": start.isoformat(), "period_end": end.isoformat(), "generated_at": end.isoformat(),
                   "sections": [s.model_dump() for s in sections], "requested_through": "novrchat"}
        canonical = json.dumps(content, sort_keys=True, default=str)
        rid = c.conn.execute(text("""INSERT INTO novrsoc.report_requests (org_id, report_type, idempotency_key, period_start, period_end, format,
                                       status, requested_by, completed_at, data_states, content, sha256)
                                     VALUES (:o, :t, :k, :s, :e, 'json', 'ready', :u, now(), CAST(:ds AS jsonb), CAST(:c AS jsonb), :h) RETURNING id"""),
                             {"o": c.p.org_id, "t": kind, "k": f"novrchat-{uuid.uuid4().hex}", "s": start, "e": end, "u": c.p.user_id,
                              "ds": json.dumps({s.key: s.state for s in sections}), "c": canonical,
                              "h": hashlib.sha256(canonical.encode()).hexdigest()}).scalar()
        audit.record("REPORT_REQUESTED", "success", org_id=c.p.org_id, actor_id=c.p.user_id, actor_label=c.p.email, resource_type="report",
                     resource_id=str(rid), request_id=c.request.state.request_id, ip=client_ip(c.request), details={"type": kind, "via": "novrchat"})
        cid = c.cite("report", rid, f"{kind} report (last 30 days)", ", ".join(f"{s.title}: {s.state}" for s in sections)[:900], f"/app/reports/{rid}")
        c.tool("generate_report", "reports:manage", "ok", f"{kind} report generated", 1)
        c.lines.append(f"Generated a {kind.replace('_', ' ')} report for the last 30 days [{cid}].")
        return
    rows = c.conn.execute(text("SELECT id, report_type, requested_at, data_states FROM novrsoc.report_requests ORDER BY requested_at DESC LIMIT 6")).all()
    c.tool("reports", "reports:read", "ok" if rows else "empty", f"{len(rows)} recent report(s)", len(rows))
    if not rows:
        c.lines.append("Reports: none generated yet. Ask me to 'generate an executive report'.")
    for r in rows:
        cid = c.cite("report", r.id, r.report_type, f"generated {r.requested_at:%Y-%m-%d %H:%M} UTC; sections {json.dumps(r.data_states)[:300]}",
                     f"/app/reports/{r.id}")
        c.lines.append(f"  - {r.report_type.replace('_', ' ')} report, {r.requested_at:%Y-%m-%d} [{cid}]")


TOOLS = [  # (name, permission, trigger, function)
    ("posture", "org:read", re.compile(r"posture|score|how secure|overall|security status|risk level", re.I), t_posture),
    ("sla", "cases:read", re.compile(r"\bsla\b|breach|response time|resolution time", re.I), t_sla),
    ("alerts", "alerts:read", re.compile(r"alert|detection|wazuh|siem|event", re.I), t_alerts),
    ("cases", "cases:read", re.compile(r"\bcase|incident", re.I), t_cases),
    ("vulnerabilities", "vms:read", re.compile(r"vulnerab|\bcve|finding|patch|remediat|exposure|\bvms\b", re.I), t_vulns),
    ("assets", "assets:read", re.compile(r"asset|host|server|endpoint|device|machine|inventory|\b(?:\d{1,3}\.){3}\d{1,3}\b", re.I), t_assets),
    ("threat_intel", "intel:read", re.compile(r"threat|indicator|\bioc|actor|\bapt|intel|malicious|reputation|[a-f0-9]{64}", re.I), t_intel),
    ("soar", "cases:read", re.compile(r"soar|playbook|approval|response action|automation", re.I), t_soar),
    ("reports", "reports:read", re.compile(r"report", re.I), t_reports),
]
CAPABILITIES = ("I can answer questions about your organization's alerts, cases, SLA, assets, vulnerabilities and CVEs, security posture, "
                "threat intelligence (indicators, matches, actors), SOAR approvals and reports, and generate a report when your role allows it. "
                "Try: \"What critical alerts came in today?\", \"Which cases are breaching SLA?\", \"Tell me about CVE-2024-3400\", "
                "\"What is our security posture?\".")


def answer(conn: Connection, p: Principal, q: str, settings: Settings, request: Request) -> tuple[str, list[ChatCitation], list[ChatToolCall], str]:
    c = Ctx(conn, p, q, settings, request)
    if ACTION.search(q) and not re.search(r"\b(how many|which|what|show|list|were|was)\b", q, re.I):
        return ("NovrChat is read-only. It cannot block, isolate, disable, approve, delete or run anything. Response actions go through "
                "SOAR, where every consequential step needs a second person's approval.", [], [], "refused")
    chosen = [t for t in TOOLS if t[2].search(q)]
    if not chosen:
        return CAPABILITIES, [], [], "complete"
    for name, perm, _, fn in chosen[:4]:
        if not p.has(perm):
            c.tool(name, perm, "not_permitted", "Your role cannot read this source.")
            c.lines.append(f"{name.replace('_', ' ').title()}: not available to your role.")
            continue
        try:
            with conn.begin_nested():
                fn(c)
        except Exception as e:  # a failing tool is reported, never hidden
            c.tool(name, perm, "unavailable", type(e).__name__)
            c.lines.append(f"{name.replace('_', ' ').title()}: the source could not be read.")
    head = "From your organization's records" + (" (citations in brackets):" if c.cites else ":")
    return head + "\n" + "\n".join(c.lines), c.cites, c.tools, "complete"


# ---------------------------------------------------------------- conversations
def _message(conn: Connection, r) -> ChatMessageView:
    nhai = None
    if r.nhai_job_id:
        from app.modules.nhai import jobs_for_subject
        nhai = next((j for j in jobs_for_subject(conn, "chat_message", str(r.id), limit=1)), None)
    return ChatMessageView(id=r.id, role=r.role, content=r.content, tools=[ChatToolCall(**t) for t in (r.tools or [])],
                           citations=[ChatCitation(**x) for x in (r.citations or [])], state=r.state, nhai=nhai, created_at=r.created_at)


def _conversation(conn: Connection, r, messages: bool) -> ChatConversationView:
    msgs = [_message(conn, m) for m in conn.execute(text("SELECT * FROM novrsoc.chat_messages WHERE conversation_id = :c ORDER BY created_at"),
                                                    {"c": r.id})] if messages else []
    return ChatConversationView(id=r.id, title=r.title, created_at=r.created_at, updated_at=r.updated_at, messages=msgs)


@router.get("/conversations", response_model=ChatConversationList, summary="The signed-in user's NovrChat conversations")
def conversations(p: Principal = Depends(require("chat:use")), conn: Connection = Depends(request_connection)) -> ChatConversationList:
    return ChatConversationList(items=[_conversation(conn, r, False) for r in conn.execute(text(
        "SELECT * FROM novrsoc.chat_conversations ORDER BY updated_at DESC LIMIT 100"))])


@router.post("/conversations", response_model=ChatConversationView, status_code=201, summary="Start a conversation")
def start(body: ChatConversationCreate, p: Principal = Depends(require("chat:use")), conn: Connection = Depends(request_connection)) -> ChatConversationView:
    r = conn.execute(text("INSERT INTO novrsoc.chat_conversations (org_id, user_id, title) VALUES (:o, :u, :t) RETURNING *"),
                     {"o": p.org_id, "u": p.user_id, "t": body.title}).one()
    return _conversation(conn, r, True)


def _own(conn: Connection, conversation_id: uuid.UUID):
    r = conn.execute(text("SELECT * FROM novrsoc.chat_conversations WHERE id = :i"), {"i": conversation_id}).first()
    if r is None:
        raise not_found("Conversation not found")
    return r


@router.get("/conversations/{conversation_id}", response_model=ChatConversationView, summary="One conversation with its messages")
def get_conversation(conversation_id: uuid.UUID, p: Principal = Depends(require("chat:use")),
                     conn: Connection = Depends(request_connection)) -> ChatConversationView:
    return _conversation(conn, _own(conn, conversation_id), True)


@router.delete("/conversations/{conversation_id}", status_code=204, summary="Delete a conversation (audited)")
def delete_conversation(conversation_id: uuid.UUID, request: Request, p: Principal = Depends(require("chat:use")),
                        conn: Connection = Depends(request_connection)) -> Response:
    _own(conn, conversation_id)
    conn.execute(text("DELETE FROM novrsoc.chat_conversations WHERE id = :i"), {"i": conversation_id})
    audit.record("CHAT_CONVERSATION_DELETED", "success", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email, resource_type="chat_conversation",
                 resource_id=str(conversation_id), request_id=request.state.request_id, ip=client_ip(request))
    return Response(status_code=204)


@router.post("/conversations/{conversation_id}/messages", response_model=ChatExchange, status_code=201,
             summary="Ask a question; the answer cites the records it used")
def ask(conversation_id: uuid.UUID, body: ChatMessageCreate, request: Request, p: Principal = Depends(require("chat:use")),
        conn: Connection = Depends(request_connection), settings: Settings = Depends(get_settings)) -> ChatExchange:
    conv = _own(conn, conversation_id)
    q = body.content.strip()
    qid = conn.execute(text("""INSERT INTO novrsoc.chat_messages (org_id, conversation_id, user_id, role, content)
                               VALUES (:o, :c, :u, 'user', :t) RETURNING id"""), {"o": p.org_id, "c": conv.id, "u": p.user_id, "t": q}).scalar()
    content, cites, tools, state = answer(conn, p, q, settings, request)
    aid, job_id = uuid.uuid4(), None
    if cites and state == "complete" and settings.nhai_backend != "unconfigured" and p.has("nhai:analyze"):
        from app.modules.nhai import queue_job
        from app.nhai.evidence import chat_bundle
        bundle = chat_bundle(p.org_id, p.user_id, aid, q, [x.model_dump(mode="json") for x in cites], max_chars=settings.nhai_max_prompt_chars)
        job_id = queue_job(conn, p, settings, request, bundle)[0].id
    conn.execute(text("""INSERT INTO novrsoc.chat_messages (id, org_id, conversation_id, user_id, role, content, tools, citations, state, nhai_job_id)
                           VALUES (:id, :o, :c, :u, 'assistant', :t, CAST(:tl AS jsonb), CAST(:ci AS jsonb), :s, :j)"""),
                 {"id": aid, "o": p.org_id, "c": conv.id, "u": p.user_id, "t": content[:16000], "s": state, "j": job_id,
                  "tl": json.dumps([t.model_dump() for t in tools]), "ci": json.dumps([x.model_dump(mode="json") for x in cites])})
    if conv.title == "New conversation":
        conn.execute(text("UPDATE novrsoc.chat_conversations SET title = :t WHERE id = :i"), {"t": q[:80], "i": conv.id})
    conn.execute(text("UPDATE novrsoc.chat_conversations SET updated_at = now() WHERE id = :i"), {"i": conv.id})
    activity.ai(conn, "chat_question", "chat", task="chat", subject_type="chat_message", subject_id=str(qid), actor_id=p.user_id, actor_label=p.email,
                outcome="success", summary=q[:300], details={"tools": [t.tool for t in tools]})
    activity.ai(conn, "chat_refused" if state == "refused" else "chat_answer", "chat", task="chat", subject_type="chat_message",
                subject_id=str(aid), actor_id=p.user_id, actor_label=p.email, outcome="refused" if state == "refused" else "success",
                summary=f"{len(cites)} citation(s); tools: {', '.join(f'{t.tool}={t.state}' for t in tools) or 'none'}"[:500],
                details={"citations": len(cites)})
    audit.record("CHAT_MESSAGE", "success" if state == "complete" else "denied", org_id=p.org_id, actor_id=p.user_id, actor_label=p.email,
                 resource_type="chat_conversation", resource_id=str(conv.id), request_id=request.state.request_id, ip=client_ip(request),
                 details={"tools": [f"{t.tool}:{t.state}" for t in tools], "citations": len(cites), "state": state})
    rows = {r.id: r for r in conn.execute(text("SELECT * FROM novrsoc.chat_messages WHERE id = ANY(:i)"), {"i": [qid, aid]})}
    return ChatExchange(question=_message(conn, rows[qid]), answer=_message(conn, rows[aid]))
