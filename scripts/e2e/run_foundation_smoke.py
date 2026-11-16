"""Frontend-to-backend smoke test orchestrator (Phase 2, extended in Phase 4) (local, disposable, non-destructive).

  apps/api/.venv/Scripts/python scripts/e2e/run_foundation_smoke.py --out <dir>

1. creates a throwaway database in the LOCAL disposable cluster (deploy/dev/compose.yaml) and migrates it;
2. seeds two disposable organizations, each with one soc_manager (random passwords, never written to the repo),
   maps the LOCAL FIXTURE Wazuh agent groups to them and ingests the labelled fixture alerts through the real
   ingest service (no Wazuh is contacted);
3. starts the API (uvicorn, port 8000, NOVRSOC_ENV=test, NOVRSOC_WAZUH_MODE=local_fixture) and the production
   web build (`next start`, port 3011);
4. runs apps/web/scripts/e2e-foundation.mjs in a headless browser (desktop + mobile), then stops the API
   and runs the API-down phase against the still-running web server;
5. stops both servers and drops the database, whatever the outcome.
Prerequisite: `next build` with NOVRSOC_API_ORIGIN=http://127.0.0.1:8000.
"""
from __future__ import annotations

import argparse
import json
import tempfile
import os
import secrets
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
API_DIR = ROOT / "apps" / "api"
WEB_DIR = ROOT / "apps" / "web"
sys.path.insert(0, str(API_DIR))

from alembic import command  # noqa: E402
from novrsoc_contracts.v1.soc import WazuhAlertIn  # noqa: E402
from sqlalchemy import create_engine, text  # noqa: E402

from app import devseed  # noqa: E402
from app.connectors.wazuh_fixture import load_fixture  # noqa: E402
from app.modules.soc.service import ingest_alerts  # noqa: E402
from tests.conftest import _with_db, alembic_config, drop_database, make_database  # noqa: E402


def env_file(key: str) -> str:
    if os.environ.get(key):  # CI provides the URLs as environment variables
        return os.environ[key]
    for line in (API_DIR / ".env").read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    raise SystemExit(f"{key} missing from apps/api/.env (run scripts/dev/bootstrap_env.py)")


def port_free(port: int) -> bool:
    with socket.socket() as s:
        return s.connect_ex(("127.0.0.1", port)) != 0


def wait_http(url: str, timeout: float = 90) -> bool:
    end = time.time() + timeout
    while time.time() < end:
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                if r.status < 500:
                    return True
        except Exception:
            time.sleep(0.5)
    return False


def summary(out: Path, rcs: dict[str, int]) -> None:
    """The last lines of the log name every failed step (or the phase that stopped early), so a CI log tail is enough."""
    lines = ["", "== e2e summary"]
    for phase, fname in (("main", "e2e-result.json"), ("api_down", "e2e-api-down-result.json")):
        lines.append(f"{phase} phase: exit {rcs.get(phase, 'not run')}")
        f = out / fname
        if not f.exists():
            lines.append(f"  no {fname}: the phase stopped before writing its result (see the error above)")
            continue
        failed = [r for r in json.loads(f.read_text(encoding="utf-8"))["results"] if not r["ok"]]
        lines += [f"  FAIL  {r['name']}  ({r['detail'][:200]})" for r in failed] or ["  every step passed"]
    print(chr(10).join(lines), flush=True)


def main() -> int:
    sys.stdout.reconfigure(line_buffering=True)   # keep this script's lines in order with the servers' output
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True, type=Path)
    args = ap.parse_args()
    args.out = args.out.resolve()   # the browser script runs in apps/web: hand it an absolute path
    for p in (8000, 3011, 8651):
        if not port_free(p):
            raise SystemExit(f"port {p} is in use; stop whatever is listening there first")

    admin, owner, app_url = (env_file(k) for k in ("NOVRSOC_TEST_ADMIN_DATABASE_URL", "NOVRSOC_MIGRATION_DATABASE_URL", "NOVRSOC_DATABASE_URL"))
    name = f"novrsoc_e2e_{secrets.token_hex(4)}"
    make_database(admin, name)
    procs: list[subprocess.Popen] = []
    try:
        owner_db, app_db = _with_db(owner, name), _with_db(app_url, name)
        command.upgrade(alembic_config(owner_db), "head")
        pa, pb = secrets.token_urlsafe(18), secrets.token_urlsafe(18)
        eng = create_engine(owner_db)
        with eng.begin() as c:
            org_a = devseed.create_org(c, "e2e-alpha", "E2E Alpha (disposable)")
            org_b = devseed.create_org(c, "e2e-beta", "E2E Beta (disposable)")
            devseed.create_user(c, "manager.alpha@e2e.novrsoc.invalid", pa, "soc_manager", org_a)
            devseed.create_user(c, "manager.beta@e2e.novrsoc.invalid", pb, "soc_manager", org_b)
            pa2 = secrets.token_urlsafe(18)
            devseed.create_user(c, "analyst.alpha@e2e.novrsoc.invalid", pa2, "analyst", org_a)
            pa3 = secrets.token_urlsafe(18)   # a second manager: playbook versions are approved by someone other than their author
            devseed.create_user(c, "manager2.alpha@e2e.novrsoc.invalid", pa3, "soc_manager", org_a)
            pp = secrets.token_urlsafe(18)   # a platform administrator (organization management)
            org_p = devseed.create_org(c, "e2e-platform", "E2E Platform (disposable)", "platform")
            devseed.create_user(c, "admin@e2e.novrsoc.invalid", pp, "super_admin", org_p)
            pt = secrets.token_urlsafe(18)   # an account with a temporary password (as created by Tenants and users)
            ut = devseed.create_user(c, "exec.alpha@e2e.novrsoc.invalid", pt, "executive", org_a)
            c.execute(text("UPDATE novrsoc.users SET password_change_required = true WHERE id = :u"), {"u": ut})
            for org, groups in ((org_a, ("nv-alpha-servers", "nv-alpha-workstations")), (org_b, ("nv-beta-servers",))):
                for g in groups:
                    c.execute(text("INSERT INTO novrsoc.wazuh_group_mappings (org_id, group_name) VALUES (:o, :g)"), {"o": org, "g": g})
            counts = ingest_alerts(c, [WazuhAlertIn.model_validate(a) for a in load_fixture()["alerts"]], source="local_fixture")
            print(f"fixture alerts: accepted={counts.accepted} quarantined={counts.quarantined}")
        eng.dispose()

        # Pilot: a loopback Server 1 bridge with the SIMULATED adapter (nothing executes), authorizing only org A's servers.
        tmp = Path(tempfile.mkdtemp(prefix="novrsoc-e2e-"))
        (tmp / "bridge.key").write_text(secrets.token_hex(32), encoding="ascii")
        (tmp / "bridge.json").write_text(json.dumps({
            "listen": "127.0.0.1", "port": 8651, "keys": {"server2-soar": str(tmp / "bridge.key")}, "adapter": "simulated",
            "state_db": str(tmp / "receipts.sqlite3"), "actions": ["block_ip", "isolate_agent"], "never_block": [],
            "simulated_agents": {"001": ["nv-alpha-servers"], "002": ["nv-alpha-servers"], "004": ["nv-beta-servers"]},
            "tenants": {str(org_a): {"actions": ["block_ip", "isolate_agent"], "agent_groups": ["nv-alpha-servers"]}}}), encoding="utf-8")
        procs.append(subprocess.Popen([sys.executable, "-m", "novrsoc_bridge", "--config", str(tmp / "bridge.json")],
                                      cwd=ROOT / "services" / "edge" / "response_bridge"))
        api_env = {**os.environ, "NOVRSOC_ENV": "test", "NOVRSOC_DATABASE_URL": app_db, "NOVRSOC_SESSION_COOKIE_SECURE": "false",
                   "NOVRSOC_SOAR_BRIDGE_URL": "http://127.0.0.1:8651", "NOVRSOC_SOAR_BRIDGE_KEY_FILE": str(tmp / "bridge.key"),
                   "NOVRSOC_NHAI_BACKEND": "test_adapter", "NOVRSOC_VMS_SCANNING": "local_test_targets", "NOVRSOC_BRAND_RESOLVER": "test_adapter",
                   "NOVRSOC_WAZUH_MODE": "local_fixture"}
        procs.append(subprocess.Popen([sys.executable, "-m", "uvicorn", "app.main:app",
                                       "--host", "127.0.0.1", "--port", "8000", "--log-level", "warning"],
                                      cwd=API_DIR, env=api_env))
        if not wait_http("http://127.0.0.1:8000/readyz"):
            raise SystemExit("API did not become ready")
        procs.append(subprocess.Popen([sys.executable, "-m", "app.nhai.worker"], cwd=API_DIR, env=api_env))  # NHAI worker (test adapter)
        web_env = {**os.environ, "NEXT_TELEMETRY_DISABLED": "1", "PORT": "3011", "NOVRSOC_API_ORIGIN": "http://127.0.0.1:8000"}
        npx = "npx.cmd" if os.name == "nt" else "npx"
        procs.append(subprocess.Popen([npx, "next", "start", "-H", "127.0.0.1", "-p", "3011"], cwd=WEB_DIR, env=web_env))
        if not wait_http("http://127.0.0.1:3011/login"):
            raise SystemExit("web server did not start")

        run_env = {**os.environ, "E2E_WEB": "http://127.0.0.1:3011", "E2E_OUT": str(args.out),
                   "E2E_USER_A": "manager.alpha@e2e.novrsoc.invalid", "E2E_PASS_A": pa,
                   "E2E_USER_B": "manager.beta@e2e.novrsoc.invalid", "E2E_PASS_B": pb, "E2E_ORG_A": str(org_a),
                   "E2E_ORG_A_NAME": "E2E Alpha (disposable)",
                   "E2E_USER_A2": "analyst.alpha@e2e.novrsoc.invalid", "E2E_PASS_A2": pa2,
                   "E2E_USER_A3": "manager2.alpha@e2e.novrsoc.invalid", "E2E_PASS_A3": pa3,
                   "E2E_USER_T": "exec.alpha@e2e.novrsoc.invalid", "E2E_PASS_T": pt,
                   "E2E_USER_P": "admin@e2e.novrsoc.invalid", "E2E_PASS_P": pp, "E2E_ORG_B": str(org_b)}
        args.out.mkdir(parents=True, exist_ok=True)
        for stale in ("e2e-result.json", "e2e-api-down-result.json"):
            (args.out / stale).unlink(missing_ok=True)
        rcs: dict[str, int] = {}
        main_rc = rcs["main"] = subprocess.call(["node", "scripts/e2e-foundation.mjs"], cwd=WEB_DIR, env=run_env)
        # Phase 2: stop the API only, keep the web server: the UI must report it honestly.
        api = next(pr for pr in procs if "uvicorn" in " ".join(pr.args))
        procs.remove(api)
        if os.name == "nt":
            subprocess.call(["taskkill", "/PID", str(api.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            api.terminate()
        time.sleep(1)
        down_rc = rcs["api_down"] = subprocess.call(["node", "scripts/e2e-foundation.mjs"], cwd=WEB_DIR, env={**run_env, "E2E_PHASE": "api_down"})
        summary(args.out, rcs)
        return 1 if (main_rc or down_rc) else 0
    finally:
        for p in procs:
            if os.name == "nt":
                subprocess.call(["taskkill", "/PID", str(p.pid), "/T", "/F"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            else:
                p.terminate()
        time.sleep(1)
        drop_database(admin, name)
        print(f"dropped disposable database {name}")


if __name__ == "__main__":
    raise SystemExit(main())
