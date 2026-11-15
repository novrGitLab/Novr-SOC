# Local development

This guide runs NovrSOC on your own machine. Everything binds to `127.0.0.1`. No production system, Wazuh manager,
scanner, model host or external feed is contacted.

## Prerequisites

- Docker Desktop or Docker Engine, running
- Python 3.12
- Node.js 22 or later, with npm
- On Windows, PowerShell 5.1 or 7

## Start (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\Start-NovrSOC.ps1
```

Then open **http://127.0.0.1:3210**.

The script:

1. Writes local env files with random passwords if they are missing (`deploy/dev/.env` and `apps/api/.env`, both
   ignored).
2. Starts a disposable PostgreSQL on `127.0.0.1:55432`. Its data lives in memory and is lost when it stops.
3. Creates the API virtualenv.
4. Runs the migrations.
5. Seeds development organizations and users, only if the database is empty.
6. Runs `python -m app.cli check-env`.
7. Starts the API on `127.0.0.1:8000`, the jobs worker, the web app and, in the default `pilot` setup, a loopback
   response bridge with the **simulated** adapter and the NHAI worker with the **test** adapter.
8. Seeds synthetic demonstrations through the API when a demo seeder (`scripts/dev/seed_demo.py`) is present. The
   public repository does not include one, so a fresh clone starts with only the development accounts and the
   labelled fixture alerts. Skip the demonstrations with `-NoDemo`.

Sign-in accounts are written outside the repository, to `%LOCALAPPDATA%\NovrSOC\dev-credentials.json`. There is one
account for each role, in two client organizations, so tenant isolation can be tried.

| Option | Effect |
|---|---|
| `-Production` | serve the production web build instead of the dev server |
| `-Setup foundation` | no bridge or workers; every adapter `unconfigured` |
| `-WazuhMode unconfigured` | what an installation without Wazuh shows |
| `-NoDemo` | skip the synthetic demonstrations |

All demonstration and fixture data is synthetic, and the interface labels it as fixture, simulated or test adapter
data. It is never shown as live telemetry.

## Status and stop

```powershell
.\scripts\dev\Get-NovrSOCStatus.ps1
.\scripts\dev\Stop-NovrSOC.ps1             # web, workers, API, bridge
.\scripts\dev\Stop-NovrSOC.ps1 -Database   # also the database (its data is destroyed)
```

## Other platforms (manual)

```sh
python3.12 scripts/dev/bootstrap_env.py          # writes deploy/dev/.env and apps/api/.env with random passwords
docker compose -f deploy/dev/compose.yaml --env-file deploy/dev/.env up -d
python3.12 -m venv apps/api/.venv && . apps/api/.venv/bin/activate
pip install -r apps/api/requirements.lock && pip install -e packages/contracts
set -a; . apps/api/.env; set +a
(cd packages/db && alembic upgrade head)
cd apps/api
python -m app.cli seed-dev --out ~/.novrsoc-dev-credentials.json --if-empty
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
python -m app.jobs &
cd ../web && npm ci && NOVRSOC_API_ORIGIN=http://127.0.0.1:8000 npm run dev
```

## Tests and checks

| Area | Command |
|---|---|
| API (needs the dev database) | `cd apps/api && python -m pytest -q` |
| Contracts | `python scripts/contracts/export.py --check && python scripts/contracts/compat.py` |
| Web | `cd apps/web && npm run typecheck && npm run lint && npm test && npm run check:nav && npm run build` |
| Browser end-to-end | `python scripts/e2e/run_foundation_smoke.py` |
| Edge services | `cd services/edge/<forwarder, response_bridge or threat_intel> && python -m unittest discover -s tests` |
| VMS worker | `cd services/vms-worker && python -m pytest -q` |
| Release preflight | `python scripts/release/preflight.py` |

Tests never contact production. The API tests create and drop their own databases on the local PostgreSQL.
