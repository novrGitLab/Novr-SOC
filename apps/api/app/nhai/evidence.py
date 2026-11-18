"""NHAI context bundles (Phase 5, workstream F): assembled server-side, from ONE organization, redacted, bounded.

The bundle for an alert explanation holds only facts NovrSOC already has, each with a citation id:
  E1  the stored alert (rule, level, AUTHORITATIVE Wazuh severity, agent, groups, time)
  E2  the redacted original log line (bounded)
  E3  the observables the Threat Insights engine extracted (deterministic)
  E4+ Threat Insights indicator matches for this alert (with their deterministic confidence)
  En  correlation: other alerts of the same agent and rule in the last 24 h (count only)
`missing_evidence()` lists, deterministically, what an analyst would need and the bundle does not contain.
Everything runs under the caller's organization context (RLS).
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta, timezone

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app import correlation
from app.core.errors import not_found
from app.core.redact import redact_string
from app.insights import stix_store
from app.insights.engine import extract_observables
from novrsoc_contracts.v1.common import ResourceRef
from novrsoc_contracts.v1.nhai import ContextBundle, EvidenceItem, NhaiTask

EXCERPT_MAX = 4000


def _excerpt(s: str, limit: int = EXCERPT_MAX) -> tuple[str, bool]:
    red = redact_string(s)
    if red is None:
        return "[content withheld: redaction failed]", True
    return red[:limit], red != s


def alert_bundle(conn: Connection, org_id: uuid.UUID, user_id: uuid.UUID, alert_id: uuid.UUID, *, max_chars: int,
                 include_findings: bool = False) -> ContextBundle:
    a = conn.execute(text("""SELECT id, rule_id, rule_level, rule_description, severity, agent_id, agent_name, agent_groups,
                                    host(src_ip) AS src_ip, mitre_techniques, observed_at, raw, asset_id
                             FROM novrsoc.alerts WHERE id = :id"""), {"id": alert_id}).first()
    if a is None:
        raise not_found("Alert not found")
    raw = a.raw if isinstance(a.raw, dict) else {}
    items: list[EvidenceItem] = []

    def add(ref_type: str, ref_id: str, excerpt: str, observed_at=None, redacted=False) -> None:
        items.append(EvidenceItem(citation_id=f"E{len(items) + 1}", ref=ResourceRef(type=ref_type, id=ref_id),
                                  observed_at=observed_at, excerpt=excerpt, redacted=redacted))

    summary = {"rule_id": a.rule_id, "rule_level": a.rule_level, "rule_description": a.rule_description,
               "siem_severity_authoritative": a.severity, "agent_id": a.agent_id, "agent_name": a.agent_name,
               "agent_groups": list(a.agent_groups or []), "source_ip": a.src_ip, "mitre_techniques": list(a.mitre_techniques or []),
               "observed_at": a.observed_at.isoformat()}
    text_, red = _excerpt(json.dumps(summary))
    add("alert", str(a.id), text_, a.observed_at, red)
    log = raw.get("full_log")
    if isinstance(log, str) and log.strip():
        text_, red = _excerpt(log, 2000)
        add("alert_log", str(a.id), text_, a.observed_at, red)
    obs = extract_observables(raw, src_ip=a.src_ip)
    if obs:
        add("observables", str(a.id), "; ".join(f"{o.type.value}={o.value} (from {o.source_field})" for o in obs[:50]))
    for m in conn.execute(text("""SELECT m.id, i.type, i.value, i.source, m.confidence, m.confidence_band, m.verdict
                                  FROM novrsoc.ti_matches m JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id AND i.org_id = m.org_id
                                  WHERE m.alert_id = :a AND m.verdict <> 'false_positive' ORDER BY m.confidence DESC LIMIT 10"""),
                          {"a": a.id}):
        ctx = [f"{x['relationship_type']} {x['type']} '{x['name']}'" for sid in stix_store.indicator_stix_ids(conn, m.type, m.value)
               for x in stix_store.related(conn, sid)][:5]
        add("ti_match", str(m.id), f"Indicator match: {m.type}={m.value} from source {m.source}; match confidence {m.confidence} "
                                   f"({m.confidence_band}); analyst verdict {m.verdict}"
                                   + (f"; STIX context: {'; '.join(ctx)}" if ctx else ""))
    since = a.observed_at - timedelta(hours=24)
    same = conn.execute(text("""SELECT count(*) FROM novrsoc.alerts WHERE agent_id = :g AND rule_id = :r
                                AND observed_at BETWEEN :s AND :t AND id <> :id"""),
                        {"g": a.agent_id, "r": a.rule_id, "s": since, "t": a.observed_at, "id": a.id}).scalar()
    add("correlation", f"{a.agent_id}:{a.rule_id}", f"{same} other alert(s) of the same rule on the same agent in the 24 h "
                                                    f"before this alert.")
    # Combined SIEM + VMS evidence: the open vulnerability findings of the alert's canonical asset (vms:read callers only).
    if include_findings and a.asset_id:
        rows, total = correlation.open_findings(conn, [a.asset_id], per_asset=5).get(a.asset_id, ([], 0))
        add("vms_findings", str(a.asset_id), (f"Open vulnerability findings on the alert's asset: {correlation.findings_line(rows)}"
                                              + (f" (+{total - len(rows)} more open)" if total > len(rows) else ""))
            if rows else "The alert's asset has no open vulnerability finding.")
    # Bound the prompt: drop the largest optional items (never E1) until the bundle fits.
    while sum(len(i.excerpt) for i in items) > max_chars and len(items) > 1:
        idx = max(range(1, len(items)), key=lambda k: len(items[k].excerpt))
        items[idx] = items[idx].model_copy(update={"excerpt": items[idx].excerpt[: max(200, len(items[idx].excerpt) // 2)]})
        if all(len(i.excerpt) <= 200 for i in items[1:]):
            break
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=org_id, task=NhaiTask.ALERT_EXPLANATION,
                         subject=ResourceRef(type="alert", id=str(a.id)), evidence=items,
                         assembled_at=datetime.now(timezone.utc), assembled_for=user_id)


def missing_evidence(bundle: ContextBundle) -> list[str]:
    """Deterministic gaps, independent of the model. Used to complete (never replace) the model's own list."""
    kinds = {e.ref.type for e in bundle.evidence}
    summary = json.loads(bundle.evidence[0].excerpt) if bundle.evidence and bundle.evidence[0].ref.type == "alert" else {}
    gaps = []
    if "alert_log" not in kinds:
        gaps.append("The original log line is not available, so the event cannot be read directly.")
    if not summary.get("source_ip"):
        gaps.append("No source address is recorded for this alert.")
    if "ti_match" not in kinds:
        gaps.append("No Threat Insights indicator matched this alert (absence of a match is not evidence of benign activity).")
    if not summary.get("mitre_techniques"):
        gaps.append("No MITRE ATT&CK technique is mapped to the rule.")
    gaps.append("Endpoint context (running processes, user sessions, vulnerability state at the time) is not in the bundle.")
    gaps.append("No analyst has confirmed the activity; outcome (success or failure of the attempt) is not established.")
    return gaps


# ---------------------------------------------------------------- consolidation: findings, assets, NovrChat
def _bounded(items: list[EvidenceItem], max_chars: int) -> list[EvidenceItem]:
    while sum(len(i.excerpt) for i in items) > max_chars and len(items) > 1:
        idx = max(range(1, len(items)), key=lambda k: len(items[k].excerpt))
        if len(items[idx].excerpt) <= 200:
            break
        items[idx] = items[idx].model_copy(update={"excerpt": items[idx].excerpt[: max(200, len(items[idx].excerpt) // 2)]})
    return items


class _Builder:
    def __init__(self):
        self.items: list[EvidenceItem] = []

    def add(self, ref_type: str, ref_id, payload, observed_at=None) -> None:
        raw = payload if isinstance(payload, str) else json.dumps(payload, default=str)
        text_, red = _excerpt(raw)
        self.items.append(EvidenceItem(citation_id=f"E{len(self.items) + 1}", ref=ResourceRef(type=ref_type, id=str(ref_id)[:200]),
                                       observed_at=observed_at, excerpt=text_, redacted=red))


def finding_bundle(conn: Connection, org_id: uuid.UUID, user_id: uuid.UUID, finding_id: uuid.UUID, *, max_chars: int) -> ContextBundle:
    f = conn.execute(text("SELECT * FROM novrsoc.vms_findings WHERE id = :i"), {"i": finding_id}).first()
    if f is None:
        raise not_found("Finding not found")
    b = _Builder()
    b.add("vms_finding", f.id, {"title": f.title, "host": f.host, "port": f.port, "protocol": f.protocol, "check_id": f.check_id,
                                "severity_authoritative": f.severity, "cvss": float(f.cvss) if f.cvss is not None else None,
                                "cves": list(f.cves), "status": f.status, "priority": f.priority, "risk_score": f.risk_score,
                                "source": f.source, "occurrences": f.occurrences, "first_seen": f.first_seen_at,
                                "last_seen": f.last_seen_at}, f.last_seen_at)
    from app.insights.cve import merged
    for c in conn.execute(text(f"SELECT * FROM ({merged('WHERE cve_id = ANY(:c)')}) m ORDER BY cve_id"), {"c": list(f.cves)}):
        b.add("cve_intel", c.cve_id, {"cve": c.cve_id, "cvss_v3": float(c.cvss_v3) if c.cvss_v3 is not None else None,
                                      "epss": float(c.epss) if c.epss is not None else None, "kev": c.kev,
                                      "description": c.description[:600], "source": c.source, "captured_at": c.captured_at})
    if f.asset_id:
        a = conn.execute(text("""SELECT a.display_name, a.kind, a.criticality, a.exposure, a.classification,
                                        (SELECT count(*) FROM novrsoc.asset_services s WHERE s.asset_id = a.id) AS services,
                                        EXISTS (SELECT 1 FROM novrsoc.asset_identifiers i WHERE i.asset_id = a.id AND i.kind = 'wazuh_agent') AS agent
                                 FROM novrsoc.assets a WHERE a.id = :a"""), {"a": f.asset_id}).first()
        if a is not None:
            b.add("asset", f.asset_id, {"name": a.display_name, "kind": a.kind, "criticality": a.criticality, "exposure": a.exposure,
                                        "classification": a.classification, "services_recorded": a.services, "wazuh_agent": a.agent})
    t = conn.execute(text("SELECT status, due_at FROM novrsoc.vms_remediation_tasks WHERE finding_id = :f"), {"f": f.id}).first()
    if t is not None:
        b.add("remediation_task", f.id, {"status": t.status, "due_at": t.due_at, "overdue": t.due_at < datetime.now(timezone.utc)})
    actors = conn.execute(text("""SELECT a.name, l.association, l.ref_id FROM novrsoc.ti_actor_links l
                                  JOIN novrsoc.ti_threat_actors a ON a.id = l.actor_id WHERE l.link_type = 'cve' AND l.ref_id = ANY(:c)"""),
                          {"c": list(f.cves)}).all()
    if actors:
        b.add("actor_links", f.id, "; ".join(f"{x.ref_id}: {x.association} association with actor '{x.name}'" for x in actors))
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=org_id, task=NhaiTask.FINDING_EXPLANATION,
                         subject=ResourceRef(type="vms_finding", id=str(f.id)), evidence=_bounded(b.items, max_chars),
                         assembled_at=datetime.now(timezone.utc), assembled_for=user_id)


def asset_bundle(conn: Connection, org_id: uuid.UUID, user_id: uuid.UUID, asset_id: uuid.UUID, *, max_chars: int) -> ContextBundle:
    a = conn.execute(text("SELECT a.*, host(a.primary_ip) AS ip FROM novrsoc.assets a WHERE a.id = :i"), {"i": asset_id}).first()
    if a is None:
        raise not_found("Asset not found")
    b = _Builder()
    b.add("asset", a.id, {"name": a.display_name, "kind": a.kind, "classification": a.classification, "criticality": a.criticality,
                          "exposure": a.exposure, "os": " ".join(x for x in (a.os_name, a.os_version) if x) or None,
                          "primary_ip": a.ip, "status": a.status, "first_seen": a.first_seen_at, "last_seen": a.last_seen_at})
    ids = conn.execute(text("SELECT kind, value, sources FROM novrsoc.asset_identifiers WHERE asset_id = :a ORDER BY kind"), {"a": asset_id}).all()
    b.add("asset_identifiers", a.id, "; ".join(f"{r.kind}={r.value} (sources: {', '.join(r.sources)})" for r in ids) or "none")
    svc = conn.execute(text("SELECT port, protocol, name, product, version FROM novrsoc.asset_services WHERE asset_id = :a ORDER BY port LIMIT 30"),
                       {"a": asset_id}).all()
    if svc:
        b.add("asset_services", a.id, "; ".join(f"{r.port}/{r.protocol or '-'} {r.name} {r.product} {r.version}".strip() for r in svc))
    fnd = conn.execute(text("""SELECT id, title, severity, priority, status, cves FROM novrsoc.vms_findings WHERE asset_id = :a
                               AND status NOT IN ('verified', 'risk_accepted') ORDER BY risk_score DESC LIMIT 10"""), {"a": asset_id}).all()
    if fnd:
        b.add("vms_findings", a.id, "; ".join(f"{r.priority} {r.severity} '{r.title}' ({r.status}; CVEs: {', '.join(r.cves) or 'none'})" for r in fnd))
    al = conn.execute(text("""SELECT severity, count(*) AS n FROM novrsoc.alerts WHERE asset_id = :a
                              AND observed_at > now() - interval '30 days' GROUP BY severity"""), {"a": asset_id}).all()
    if al:
        rules = conn.execute(text("""SELECT rule_id, rule_description, count(*) AS n FROM novrsoc.alerts WHERE asset_id = :a
                                     AND observed_at > now() - interval '30 days' GROUP BY 1, 2 ORDER BY 3 DESC LIMIT 5"""), {"a": asset_id}).all()
        b.add("alerts_30d", a.id, "By severity: " + ", ".join(f"{r.severity} {r.n}" for r in al) + ". Top rules: " +
              "; ".join(f"{r.rule_id} '{r.rule_description}' x{r.n}" for r in rules))
    cs = conn.execute(text("""SELECT DISTINCT c.number, c.title, c.status, c.severity FROM novrsoc.cases c JOIN novrsoc.case_alerts ca ON ca.case_id = c.id
                              JOIN novrsoc.alerts al ON al.id = ca.alert_id WHERE al.asset_id = :a LIMIT 10"""), {"a": asset_id}).all()
    if cs:
        b.add("cases", a.id, "; ".join(f"CASE-{r.number:06d} {r.severity} '{r.title}' ({r.status})" for r in cs))
    ti = conn.execute(text("""SELECT i.type, i.value, m.confidence, m.verdict FROM novrsoc.ti_matches m JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id
                              JOIN novrsoc.alerts al ON al.id = m.alert_id WHERE al.asset_id = :a AND m.verdict <> 'false_positive' LIMIT 10"""),
                      {"a": asset_id}).all()
    if ti:
        b.add("ti_matches", a.id, "; ".join(f"{r.type}={r.value} (confidence {r.confidence}, verdict {r.verdict})" for r in ti))
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=org_id, task=NhaiTask.ASSET_SUMMARY, subject=ResourceRef(type="asset", id=str(a.id)),
                         evidence=_bounded(b.items, max_chars), assembled_at=datetime.now(timezone.utc), assembled_for=user_id)


def case_bundle(conn: Connection, org_id: uuid.UUID, user_id: uuid.UUID, case_id: uuid.UUID, *, max_chars: int,
                include_findings: bool = False) -> ContextBundle:
    """Investigation assistance: the case, its linked alerts (with the SIEM's authoritative severity), the analysts' notes
    and timeline, Threat Insights matches of the linked alerts, the assets involved and (when the caller may read VMS
    findings) the open vulnerability findings on those assets. Active organization only (RLS)."""
    c = conn.execute(text("SELECT * FROM novrsoc.cases WHERE id = :i"), {"i": case_id}).first()
    if c is None:
        raise not_found("Case not found")
    b = _Builder()
    b.add("case", c.id, {"number": f"CASE-{c.number:06d}", "title": c.title, "severity": c.severity, "status": c.status,
                         "source": c.source, "opened_at": c.created_at, "updated_at": c.updated_at}, c.created_at)
    alerts = conn.execute(text("""SELECT a.id, a.rule_id, a.rule_description, a.severity, a.agent_name, host(a.src_ip) AS src_ip,
                                         a.mitre_techniques, a.observed_at, a.asset_id
                                  FROM novrsoc.case_alerts ca JOIN novrsoc.alerts a ON a.id = ca.alert_id
                                  WHERE ca.case_id = :c ORDER BY a.observed_at LIMIT 20"""), {"c": case_id}).all()
    for a in alerts:
        b.add("alert", a.id, {"rule_id": a.rule_id, "rule_description": a.rule_description, "siem_severity_authoritative": a.severity,
                              "agent_name": a.agent_name, "source_ip": a.src_ip, "mitre_techniques": list(a.mitre_techniques or []),
                              "observed_at": a.observed_at}, a.observed_at)
    notes = conn.execute(text("""SELECT kind, body, actor_label, occurred_at FROM novrsoc.case_events WHERE case_id = :c
                                 ORDER BY occurred_at DESC LIMIT 15"""), {"c": case_id}).all()
    if notes:
        b.add("case_timeline", c.id, "; ".join(f"{n.occurred_at:%Y-%m-%d %H:%M} {n.kind}" + (f": {n.body[:400]}" if n.body else "")
                                               for n in reversed(notes)))
    ids = [a.id for a in alerts]
    if ids:
        ti = conn.execute(text("""SELECT i.type, i.value, m.confidence, m.verdict FROM novrsoc.ti_matches m
                                  JOIN novrsoc.ti_indicators i ON i.id = m.indicator_id
                                  WHERE m.alert_id = ANY(:ids) AND m.verdict <> 'false_positive' LIMIT 15"""), {"ids": ids}).all()
        if ti:
            b.add("ti_matches", c.id, "; ".join(f"{r.type}={r.value} (confidence {r.confidence}, verdict {r.verdict})" for r in ti))
        assets = conn.execute(text("""SELECT DISTINCT x.id, x.display_name, x.criticality, x.exposure FROM novrsoc.assets x
                                      WHERE x.id = ANY(:a)"""), {"a": [a.asset_id for a in alerts if a.asset_id]}).all()
        if assets:
            b.add("assets", c.id, "; ".join(f"{r.display_name} (criticality {r.criticality}, exposure {r.exposure})" for r in assets))
        # Combined SIEM + VMS evidence: open vulnerability findings on the same canonical assets (vms:read callers only).
        if include_findings and assets:
            names = {r.id: r.display_name for r in assets}
            for asset_id, (rows, total) in correlation.open_findings(conn, list(names), per_asset=5).items():
                more = f" (+{total - len(rows)} more open)" if total > len(rows) else ""
                b.add("vms_findings", asset_id, f"Open findings on {names[asset_id]}: {correlation.findings_line(rows)}{more}")
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=org_id, task=NhaiTask.INVESTIGATION_ASSISTANCE, subject=ResourceRef(type="case", id=str(c.id)),
                         evidence=_bounded(b.items, max_chars), assembled_at=datetime.now(timezone.utc), assembled_for=user_id)


def chat_bundle(org_id: uuid.UUID, user_id: uuid.UUID, message_id: uuid.UUID, question: str, citations: list[dict], *,
                max_chars: int) -> ContextBundle:
    b = _Builder()
    b.add("chat_question", message_id, question)
    for c in citations[:40]:
        b.add(c["ref"]["type"], c["ref"]["id"], f"[{c['citation_id']}] {c['label']}: {c['excerpt']}")
    return ContextBundle(bundle_id=uuid.uuid4(), org_id=org_id, task=NhaiTask.CHAT_ANSWER,
                         subject=ResourceRef(type="chat_message", id=str(message_id)), evidence=_bounded(b.items, max_chars),
                         assembled_at=datetime.now(timezone.utc), assembled_for=user_id)


def missing_evidence_for(bundle: ContextBundle) -> list[str]:
    """Deterministic gaps for every task (the alert task keeps its original checker)."""
    kinds = {e.ref.type for e in bundle.evidence}
    if bundle.task == NhaiTask.ALERT_EXPLANATION:
        return missing_evidence(bundle)
    if bundle.task == NhaiTask.FINDING_EXPLANATION:
        gaps = []
        if "cve_intel" not in kinds:
            gaps.append("No CVE intelligence (CVSS, EPSS, KEV) is recorded for this finding's CVEs.")
        if "asset" not in kinds:
            gaps.append("The host is not linked to a canonical asset, so its criticality and exposure are unknown.")
        gaps.append("The scanner's raw output is not in the bundle; the detection itself is not re-verified here.")
        gaps.append("Exploitability in this environment (reachability, compensating controls) is not established.")
        return gaps
    if bundle.task == NhaiTask.ASSET_SUMMARY:
        gaps = []
        if "vms_findings" not in kinds:
            gaps.append("No open VMS findings are recorded (this does not mean the asset was scanned or is free of vulnerabilities).")
        if "alerts_30d" not in kinds:
            gaps.append("No alerts in 30 days are recorded for this asset.")
        if "wazuh_agent" not in " ".join(e.excerpt for e in bundle.evidence if e.ref.type == "asset_identifiers"):
            gaps.append("No NovrAgent is linked: host telemetry and configuration assessment are not available.")
        gaps.append("Business context (data held, owners' risk appetite) is not in the bundle.")
        return gaps
    if bundle.task == NhaiTask.POSTURE_ANALYSIS:
        gaps = ["These are aggregates (counts and top items): individual events were not read, so causes are not established.",
                "Assets without a NovrAgent or never scanned are under-represented in alert and finding counts."]
        posture = next((e.excerpt for e in bundle.evidence if e.ref.type == "posture"), "")
        if '"score": null' in posture:
            gaps.append("The posture score has insufficient data in this window.")
        return gaps
    if bundle.task == NhaiTask.INVESTIGATION_ASSISTANCE:
        gaps = []
        if "assets" not in kinds:
            gaps.append("The linked alerts are not attributed to inventory assets, so vulnerability context cannot be joined.")
        elif "vms_findings" not in kinds:
            gaps.append("No open vulnerability finding is included for the case's assets (none is recorded, or the requester "
                        "may not read VMS findings); this does not mean the assets were scanned.")
        gaps.append("Only the case's linked alerts were used; related activity not linked to the case is not in the bundle.")
        return gaps
    return ["Only the records retrieved for this question were used; other records may exist that the tools did not return."]
