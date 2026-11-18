"""NovrSOAR policy-driven orchestration: what happens to each NEW alert of an organization without a person.

Called by the jobs worker inside the organization's own transaction (RLS applies). Per cycle it reads, in order, the
alerts received after the organization's cursor (and never before automation was switched on), at most `limit`, and
for each one:
  1. computes a deterministic detection confidence (rule level, Threat Insights match confidence, repetition), with
     the factors recorded;
  2. when case creation is on and the alert is severe enough, or when an automatic playbook matches: joins the open
     automation case of the same agent and rule from the last 24 hours, or opens a new case (SLA policy applied);
  3. for each approved, enabled playbook version marked `automatic` whose triggers match: applies the same run gate as
     a person (emergency stop, mode, minimum case severity, run limits) and starts an automatic run. Consequential steps
     are dispatched only under the pre-authorization policy (see modules.soar.start_run); otherwise they wait for a
     human approval;
  4. records each decision in soar_automation_events (UNIQUE per alert and playbook: a retry never repeats it) and
     advances the cursor.
Each alert is processed in a SAVEPOINT: a failure is recorded as `failed` for that alert and never blocks the next.
The mode is live only when the organization's policy enables live mode AND the playbook allows it; otherwise dry run.
Execution itself stays with the bridge, which refuses live execution unless its own configuration allows it.
"""
from __future__ import annotations

import logging
import uuid

from sqlalchemy import text
from sqlalchemy.engine import Connection

from app.audit import service as audit
from app.core.config import Settings
from app.secops import sla

log = logging.getLogger("novrsoc.soar.automation")

SEV = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
ZERO = uuid.UUID(int=0)


def confidence(conn: Connection, a) -> tuple[int, list[str]]:
    """Deterministic detection confidence 0..100 and its factors. No model is involved."""
    lvl = a.rule_level or 0
    base = 75 if lvl >= 13 else 70 if lvl >= 12 else 60 if lvl >= 10 else 45 if lvl >= 7 else 30
    factors = [f"rule level {lvl}: base {base}"]
    score = base
    ti = conn.execute(text("""SELECT max(confidence) FROM novrsoc.ti_matches WHERE alert_id = :a AND verdict <> 'false_positive'"""),
                      {"a": a.id}).scalar()
    if ti:
        add = round(int(ti) * 0.25)
        score += add
        factors.append(f"Threat Insights match confidence {ti}: +{add}")
    rep = conn.execute(text("""SELECT count(*) FROM novrsoc.alerts WHERE rule_id = :r AND agent_id IS NOT DISTINCT FROM :g
                               AND id <> :a AND observed_at BETWEEN :t - interval '1 hour' AND :t"""),
                       {"r": a.rule_id, "g": a.agent_id, "a": a.id, "t": a.observed_at}).scalar()
    if rep >= 2:
        score += 10
        factors.append(f"same rule on the same agent {rep} more time(s) in the hour before: +10")
    return min(100, score), factors


def _event(conn, org_id, alert_id, playbook, decision, conf, factors, *, case_id=None, run_id=None, detail="") -> bool:
    r = conn.execute(text("""INSERT INTO novrsoc.soar_automation_events (org_id, alert_id, playbook_name, decision, confidence, factors,
                                                                       case_id, run_id, detail)
                             VALUES (:o, :a, :p, :d, :c, :f, :case, :run, :detail) ON CONFLICT DO NOTHING RETURNING id"""),
                     {"o": org_id, "a": alert_id, "p": playbook, "d": decision, "c": conf, "f": factors, "case": case_id, "run": run_id,
                      "detail": detail[:500]}).first()
    return r is not None


def _case_of(conn, alert_id):
    return conn.execute(text("SELECT case_id FROM novrsoc.case_alerts WHERE alert_id = :a LIMIT 1"), {"a": alert_id}).scalar()


def _open_or_join_case(conn: Connection, org_id: uuid.UUID, a, label: str) -> tuple[uuid.UUID, bool]:
    from app.modules.soar import AUTOMATION_LABEL
    case_id = conn.execute(text("""
        SELECT c.id FROM novrsoc.cases c JOIN novrsoc.case_alerts ca ON ca.case_id = c.id JOIN novrsoc.alerts x ON x.id = ca.alert_id
        WHERE c.source = 'automation' AND c.status IN ('open', 'in_progress') AND c.created_at > now() - interval '24 hours'
          AND x.rule_id = :r AND x.agent_id IS NOT DISTINCT FROM :g
        ORDER BY c.created_at DESC LIMIT 1"""), {"r": a.rule_id, "g": a.agent_id}).scalar()
    created = case_id is None
    if created:
        sev = a.severity if a.severity in ("low", "medium", "high", "critical") else "low"
        title = (a.rule_description or f"Rule {a.rule_id}").strip()[:200]
        title = title if len(title) >= 3 else f"Rule {a.rule_id}"
        row = conn.execute(text("""INSERT INTO novrsoc.cases (org_id, title, severity, source, source_id)
                                   VALUES (:o, :t, :s, 'automation', :sid) RETURNING id, created_at"""),
                           {"o": org_id, "t": title, "s": sev, "sid": str(a.id)}).one()
        case_id = row.id
        sla.apply_policy(conn, case_id, sev, row.created_at)
        conn.execute(text("""INSERT INTO novrsoc.case_events (case_id, org_id, actor_label, kind, body)
                             VALUES (:c, :o, :l, 'created', :b)"""),
                     {"c": case_id, "o": org_id, "l": AUTOMATION_LABEL, "b": f"Case opened automatically ({label})."})
        audit.record("SOAR_AUTOMATIC_CASE", "success", org_id=org_id, actor_type="system", actor_label=AUTOMATION_LABEL,
                     resource_type="case", resource_id=str(case_id), details={"alert_id": str(a.id), "reason": label})
    conn.execute(text("""INSERT INTO novrsoc.case_alerts (case_id, alert_id, org_id) VALUES (:c, :a, :o) ON CONFLICT DO NOTHING"""),
                 {"c": case_id, "a": a.id, "o": org_id})
    conn.execute(text("""INSERT INTO novrsoc.case_events (case_id, org_id, actor_label, kind, body)
                         VALUES (:c, :o, :l, 'alert_linked', :b)"""),
                 {"c": case_id, "o": org_id, "l": AUTOMATION_LABEL, "b": f"Alert {a.id} linked automatically."})
    conn.execute(text("UPDATE novrsoc.alerts SET status = 'in_progress', updated_at = now() WHERE id = :a AND status IN ('new', 'acknowledged')"),
                 {"a": a.id})
    return case_id, created


def process(conn: Connection, settings: Settings, org_id: uuid.UUID, *, limit: int = 200) -> dict:
    from app.modules.soar import (approved_playbooks, automation_actor, _policy, run_gate, start_run, trigger_match)
    from novrsoc_contracts.v1.soar import PlaybookExecutionPolicy
    out = {"alerts": 0, "cases": 0, "runs": 0, "skipped": 0, "failed": 0}
    row = conn.execute(text("""SELECT automation_enabled, case_creation, case_min_severity, automation_since, automation_cursor_at,
                                      automation_cursor_id FROM novrsoc.soar_policies FOR UPDATE""")).first()
    if row is None or not (row.automation_enabled or row.case_creation) or row.automation_since is None:
        return out
    alerts = conn.execute(text("""
        SELECT id, rule_id, rule_level, rule_description, severity, agent_id, agent_groups, mitre_techniques, observed_at, received_at,
               host(src_ip) AS src_ip, raw
        FROM novrsoc.alerts
        WHERE received_at >= :since AND (received_at, id) > (:cat, :cid)
        ORDER BY received_at, id LIMIT :n"""),
        {"since": row.automation_since, "cat": row.automation_cursor_at or row.automation_since, "cid": row.automation_cursor_id or ZERO,
         "n": limit}).all()
    if not alerts:
        return out
    policy = _policy(conn)
    actor = automation_actor(org_id)
    playbooks = []
    if row.automation_enabled:
        playbooks = [pb for pb in approved_playbooks(conn) if pb.execution_policy.automatic]
    for a in alerts:
        out["alerts"] += 1
        conf, factors = confidence(conn, a)
        try:
            with conn.begin_nested():
                matched = [(pb, why) for pb in playbooks for why in [trigger_match(pb.triggers, [a])] if why is not None]
                case_id = _case_of(conn, a.id)
                severe = row.case_creation and SEV.get(a.severity, 0) >= SEV[row.case_min_severity]
                if case_id is None and (severe or matched):
                    label = (f"severity {a.severity} >= {row.case_min_severity}" if severe
                             else f"automatic playbook {matched[0][0].name} matched")
                    case_id, created = _open_or_join_case(conn, org_id, a, label)
                    _event(conn, org_id, a.id, "", "case_created" if created else "case_joined", conf, factors, case_id=case_id,
                           detail=label)
                    out["cases"] += int(created)
                for pb, why in matched:
                    raw_pb = conn.execute(text("SELECT * FROM novrsoc.soar_playbooks WHERE id = :i"), {"i": pb.id}).one()
                    ep = PlaybookExecutionPolicy(**(raw_pb.execution_policy or {}))
                    modes = [m.value for m in ep.modes]
                    mode = "live" if policy.live_enabled and "live" in modes else "dry_run" if "dry_run" in modes else None
                    case_sev = conn.execute(text("SELECT severity FROM novrsoc.cases WHERE id = :c"), {"c": case_id}).scalar()
                    refusal = (409, "mode_not_allowed", "the playbook allows only live mode and live mode is not enabled") \
                        if mode is None else run_gate(conn, raw_pb, case_sev, mode, policy)
                    if refusal is not None:
                        _, code, message = refusal
                        decision = {"emergency_stop": "skipped_emergency_stop", "severity_below_policy": "skipped_severity"}.get(code, "skipped_limit")
                        _event(conn, org_id, a.id, pb.name, decision, conf, factors, case_id=case_id, detail=message)
                        out["skipped"] += 1
                        continue
                    if not _event(conn, org_id, a.id, pb.name, "run_started", conf, factors, case_id=case_id,
                                  detail=f"matched on {'; '.join(why)}; mode {mode}"):
                        continue   # already decided for this alert and playbook
                    just = (f"Automatic run: {pb.name} matched alert {a.rule_id} ({'; '.join(why)}); detection confidence {conf}")
                    run_id = start_run(conn, settings, actor, raw_pb, case_id, mode, just, f"auto-{a.id}-{pb.name}", policy=policy,
                                       origin="automatic", confidence=conf, trigger_alert_id=a.id)
                    conn.execute(text("""UPDATE novrsoc.soar_automation_events SET run_id = :r
                                         WHERE alert_id = :a AND playbook_name = :p"""), {"r": run_id, "a": a.id, "p": pb.name})
                    out["runs"] += 1
        except Exception as e:   # one alert's failure never blocks the others; it is recorded and visible
            log.exception("automation failed for an alert")
            _event(conn, org_id, a.id, "", "failed", conf, factors, detail=f"{type(e).__name__}: {str(e)[:300]}")
            out["failed"] += 1
        conn.execute(text("UPDATE novrsoc.soar_policies SET automation_cursor_at = :t, automation_cursor_id = :i"),
                     {"t": a.received_at, "i": a.id})
    return out
