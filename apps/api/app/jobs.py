"""Background jobs worker (Server 2, next to the API; consolidation).

  python -m app.jobs            loop (every NOVRSOC_JOBS_INTERVAL_SECONDS, default 60)
  python -m app.jobs --once     one cycle and exit

Per cycle, for every active organization, in its own transaction and organization context (RLS applies):
  * SLA escalation: open cases at risk or breached are marked once and the policy's role is notified;
  * VMS schedules: due, enabled schedules create scan jobs ONLY where scanning is enabled (disabled by default);
  * CNII schedules: due checks are recorded honestly (no probe is configured: `not_run` with the reason);
  * SOAR approvals: expired approvals expire their step and settle the run;
  * asset links: stored alerts and VMS findings without a canonical asset are reconciled (bounded per cycle);
  * asset sync: when due (Settings.asset_sync_interval_minutes, or the organization's own wazuh_sync collector), the
    organization's agents are read (read-only) from the agent data source and reconciled into the canonical inventory
    shared with VMS. Each organization syncs in its OWN transaction; a failure is recorded as that organization's failed
    sync run (visible on its onboarding page) and never affects another organization.
  * SOAR orchestration (app.soar.automation; off unless the organization's automation policy is on): new alerts open
    or join automation cases and start approved automatic playbooks. A consequential step is dispatched to the
    NovrSOAR bridge only under the organization's pre-authorization policy (otherwise it waits for a person); the
    bridge applies its own tenant authorization, target guards and live-execution switch.
It never contacts a scanner, and runs as the API's database role.
A heartbeat in platform_heartbeats lets Platform Health show whether it is running.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import time
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.engine import Engine

from app.core.config import Settings
from app.db import session as db_session

log = logging.getLogger("novrsoc.jobs")


def _expire_approvals(conn) -> int:
    from app.modules.soar import _settle_run, _step
    rows = conn.execute(text("""SELECT a.step_id, s.run_id FROM novrsoc.soar_approvals a JOIN novrsoc.soar_steps s ON s.id = a.step_id
                                WHERE a.decision IS NULL AND a.expires_at <= now() AND s.state = 'awaiting_approval'
                                FOR UPDATE OF s SKIP LOCKED""")).all()
    for r in rows:
        _step(conn, r.step_id, "expired", "The approval expired before a decision")
        _settle_run(conn, r.run_id)
    return len(rows)


def run_cycle(engine: Engine, settings: Settings) -> dict:
    from app.modules.cnii import run_due_checks
    from app.modules.secops import escalate
    from app.modules.vms import run_due_schedules
    from app.assets.reconcile import link_unlinked
    totals = {"orgs": 0, "escalated": 0, "scan_jobs": 0, "cnii_checks": 0, "approvals_expired": 0, "assets_linked": 0, "errors": 0,
              "asset_syncs": 0, "asset_sync_errors": 0, "soar_alerts": 0, "soar_cases": 0, "soar_runs": 0, "soar_errors": 0}
    with engine.connect() as c:
        orgs = [r[0] for r in c.execute(text("SELECT * FROM novrsoc.jobs_org_ids()"))]
    for org in orgs:
        try:
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
                totals["escalated"] += escalate(conn, "jobs-worker").escalated
                totals["scan_jobs"] += run_due_schedules(conn, settings)
                totals["cnii_checks"] += run_due_checks(conn)
                totals["approvals_expired"] += _expire_approvals(conn)
                totals["assets_linked"] += link_unlinked(conn)
                conn.execute(text("DELETE FROM novrsoc.user_presence WHERE last_seen_at < now() - interval '30 days'"))
            totals["orgs"] += 1
        except Exception:  # one organization's failure never stops the others
            totals["errors"] += 1
            log.exception("jobs cycle failed for an organization")
        sync_assets_if_due(engine, settings, org, totals)
        orchestrate(engine, settings, org, totals)
    return totals


def orchestrate(engine: Engine, settings: Settings, org, totals: dict) -> None:
    """NovrSOAR policy-driven orchestration for one organization, in its OWN transaction (after the asset links of this
    cycle, so new alerts carry their canonical asset). Off unless the organization switched it on."""
    from app.soar import automation
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
            r = automation.process(conn, settings, org)
        totals["soar_alerts"] += r["alerts"]
        totals["soar_cases"] += r["cases"]
        totals["soar_runs"] += r["runs"]
        totals["soar_errors"] += r["failed"]
    except Exception:
        totals["soar_errors"] += 1
        log.exception("SOAR automation failed for an organization")


def _sync_due(conn, settings: Settings) -> bool:
    from app.modules.onboarding import asset_sync_status
    st = asset_sync_status(conn, settings)
    return bool(st.interval_minutes) and st.next_due_at is not None and st.next_due_at <= datetime.now(timezone.utc)


def sync_assets_if_due(engine: Engine, settings: Settings, org, totals: dict) -> None:
    """The scheduled agent -> inventory sync of ONE organization, isolated from every other organization."""
    from app.connectors import registry
    from app.modules.assets import sync_wazuh
    from app.modules.endpoints import org_scope
    if registry.wazuh(settings) is None:
        return
    try:
        with engine.begin() as conn:
            conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
            if not org_scope(conn, org, settings.collection_groups).wazuh_agent_groups or not _sync_due(conn, settings):
                return
            r = sync_wazuh(conn, settings, org, "scheduled sync")
            conn.execute(text("UPDATE novrsoc.collectors SET last_run_at = now(), last_outcome = :o WHERE kind = 'wazuh_sync'"), {"o": r.outcome})
            totals["asset_syncs"] += 1
            totals["asset_sync_errors"] += r.outcome != "completed"
    except Exception as e:  # recorded for THIS organization only; the next organization still syncs
        totals["asset_sync_errors"] += 1
        log.exception("scheduled asset sync failed for an organization")
        try:
            with engine.begin() as conn:
                conn.execute(text("SELECT set_config('app.org_id', :v, true)"), {"v": str(org)})
                conn.execute(text("""INSERT INTO novrsoc.asset_sync_runs (org_id, source, source_state, finished_at, outcome, detail, requested_label)
                                     VALUES (:o, 'wazuh', 'error', now(), 'failed', :d, 'scheduled sync')"""),
                             {"o": org, "d": f"The scheduled sync failed ({type(e).__name__}); it is retried at the next interval."})
        except Exception:
            log.exception("could not record the failed asset sync")


def heartbeat(engine: Engine, instance: str, totals: dict) -> None:
    state = "ok" if not totals.get("errors") else "degraded"
    detail = ", ".join(f"{k} {v}" for k, v in totals.items())
    with engine.begin() as conn:
        conn.execute(text("SELECT novrsoc.platform_heartbeat('jobs_worker', :i, :s, :d)"), {"i": instance, "s": state, "d": detail[:500]})


def main(argv=None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    logging.basicConfig(level=logging.INFO, format='{"ts":"%(asctime)s","level":"%(levelname)s","event":"%(message)s"}')
    settings = Settings()  # type: ignore[call-arg]
    engine = db_session.init_engine(settings.database_url.get_secret_value())
    instance = f"{socket.gethostname()[:40]}:{os.getpid()}"
    interval = max(15, int(os.environ.get("NOVRSOC_JOBS_INTERVAL_SECONDS", "60")))
    stopping = {"flag": False}
    signal.signal(signal.SIGTERM, lambda *_: stopping.__setitem__("flag", True))
    while True:
        try:
            totals = run_cycle(engine, settings)
            heartbeat(engine, instance, totals)
            log.info("jobs cycle %s", totals)
        except Exception:
            log.exception("jobs cycle failed")
        if "--once" in argv or stopping["flag"]:
            return 0
        for _ in range(interval):
            if stopping["flag"]:
                return 0
            time.sleep(1)


if __name__ == "__main__":
    raise SystemExit(main())
