"""Background jobs worker (Server 2, next to the API; consolidation).

  python -m app.jobs            loop (every NOVRSOC_JOBS_INTERVAL_SECONDS, default 60)
  python -m app.jobs --once     one cycle and exit

Per cycle, for every active organization, in its own transaction and organization context (RLS applies):
  * SLA escalation: open cases at risk or breached are marked once and the policy's role is notified;
  * VMS schedules: due, enabled schedules create scan jobs ONLY where scanning is enabled (disabled by default);
  * CNII schedules: due checks are recorded honestly (no probe is configured: `not_run` with the reason);
  * SOAR approvals: expired approvals expire their step and settle the run;
  * asset links: stored alerts and VMS findings without a canonical asset are reconciled (bounded per cycle).
It never executes a response action, never contacts Wazuh, a scanner or a server, and runs as the API's database role.
A heartbeat in platform_heartbeats lets Platform Health show whether it is running.
"""
from __future__ import annotations

import logging
import os
import signal
import socket
import sys
import time

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
    totals = {"orgs": 0, "escalated": 0, "scan_jobs": 0, "cnii_checks": 0, "approvals_expired": 0, "assets_linked": 0, "errors": 0}
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
            totals["orgs"] += 1
        except Exception:  # one organization's failure never stops the others
            totals["errors"] += 1
            log.exception("jobs cycle failed for an organization")
    return totals


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
