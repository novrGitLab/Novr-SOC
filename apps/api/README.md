# apps/api: NovrSOC API (FastAPI)

The API serves every module under `/api/v1/<module>`. Each module lives in `app/modules/<name>` and exports `MODULE`
and `router`; they are discovered at startup.

| Area | Where |
|---|---|
| Settings (validated at boot; errors name settings, never values) | `app/core/config.py` |
| Sessions (opaque httpOnly cookie, CSRF header, lockout), machine identities (`nsk_` tokens) | `app/auth/`, `app/routers/auth.py` |
| Organization context, permissions, CNII designations | `app/authz/` |
| Row-level security context per request | `app/db/session.py` |
| Audit log, AI activity log, notifications | `app/audit/` |
| Connectors (Wazuh read-only, inference, Threat Insights): `unconfigured` by default | `app/connectors/` |
| Asset reconciliation | `app/assets/reconcile.py` |
| SLA policies and states | `app/secops/sla.py` |
| SOAR engine and bridge client | `app/soar/`, `app/modules/soar/` |
| NHAI evidence bundles, validator and worker | `app/nhai/` |
| Threat Insights and STIX store, CVE intelligence | `app/insights/` |
| Email and brand protection engines | `app/protection/` |
| Background jobs (SLA, schedules, CNII checks, approval expiry, asset links, heartbeat) | `app/jobs.py` |
| Encrypted backups and restore drill | `app/backup.py` |
| Operator CLI (`check-env`, `bootstrap-platform`, `create-service-identity`, `backup`, `restore-drill`; dev seeding in development and test only) | `app/cli.py` |

Modules: `admin`, `assets`, `chat`, `cnii`, `continuity`, `endpoints`, `insights`, `nhai`, `posture`, `protection`,
`reports`, `secops`, `soar`, `soc`, `vms`.

Errors use one shape, `{"error": {code, message, request_id, details?}}`, and never include stack traces. If the
database is unreachable, the API returns 503 `database_unavailable`. The OpenAPI document is
`packages/contracts/openapi/novrsoc-api.v1.json`. In production `/api/docs` is disabled.

To run and test: [`docs/public/LOCAL_DEVELOPMENT.md`](../../docs/public/LOCAL_DEVELOPMENT.md). Locks:
`requirements.lock` (development and test) and `requirements.runtime.lock` (images and Server 1).
