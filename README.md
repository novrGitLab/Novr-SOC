# NovrSOC

NovrSOC is a multi-tenant security operations platform for managed security providers and their client
organizations. It brings the following together in one interface:

- alert triage and case management with SLA tracking;
- human-approved response orchestration (SOAR);
- vulnerability management;
- threat intelligence (STIX 2.1 / TAXII 2.1);
- CNII monitoring, email security and brand protection;
- a reconciled asset inventory;
- an evidence-grounded AI assistant (NHAI and NovrChat).

Tenant isolation is enforced by PostgreSQL row-level security. Permissions are enforced by the API on every route.
Response actions always need a second person's approval. AI output is a draft: it never authorizes or executes
anything.

## Modules

| Area | Pages |
|---|---|
| Workspace | Executive overview, Security posture, Reports |
| Security operations | Alerts, Cases, Playbooks, SOAR (operations, runs, approvals, AI activity, policy), Shift handover, SLA management |
| Vulnerability management | Overview, Attack surface, Findings, Scans and schedules, Risk prioritization, Remediation, Reporting and audit |
| NHAI threat intelligence | Threat Insights (indicators, STIX/TAXII, snapshots), Threat actors, CVE intelligence, NHAI analyses |
| Protection | CNII monitoring, Email security, Brand protection |
| Assets | Asset inventory, Endpoints, Sites, Collectors and discovery |
| Assistant and continuity | NovrChat, Data loss recovery |
| Clients and administration | Organization directory and per-organization management (overview, users and teams, assets and networks, integrations including syslog and agentless sources, security policies, billing, audit, settings), Users and teams, Billing, Platform analytics, Data exports, Wazuh groups and log sources, Platform health, Audit log |

A fresh installation contains no organizations, users, playbooks or security data. When an integration is not
connected, the interface says so instead of showing placeholder figures.

## Repository layout

```
apps/api/            FastAPI service, background jobs worker, NHAI worker, operator CLI
apps/web/            Next.js web application
packages/contracts/  v1 API contracts (Pydantic → OpenAPI / JSON Schema → TypeScript)
packages/db/         Alembic migrations (PostgreSQL 16, row-level security)
services/edge/       Server 1 services: alert forwarder, Threat Insights feeder, response bridge
services/vms-worker/ VMS worker (Server 2, own image; scanning disabled by default)
deploy/              Docker images, Server 2 Compose, Server 1 systemd units, configuration templates
scripts/             development, contract, end-to-end and release tooling
docs/public/         documentation
```

## Documentation

- [Local development](docs/public/LOCAL_DEVELOPMENT.md): run the platform and its tests on your machine.
- [Architecture](docs/public/ARCHITECTURE.md): components, tenancy, asset reconciliation and AI boundaries.
- [Deployment](docs/public/DEPLOYMENT.md): Server 2 (Docker Compose), Server 1 (systemd), first administrator,
  approval gates, security checks and rollback.
- [SOAR policy](docs/public/SOAR_POLICY.md): authorization, approvals, limits, emergency stop and audit.

## Quick start (Windows)

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev\Start-NovrSOC.ps1
```

Then open http://127.0.0.1:3210. Development sign-in accounts are written to
`%LOCALAPPDATA%\NovrSOC\dev-credentials.json`. All development data is synthetic and labelled as such.

## Security

Never put credentials, tokens, keys or environment files in the repository. Configuration templates (`*.example`)
hold placeholders only. Run `python scripts/release/preflight.py` before every release.
