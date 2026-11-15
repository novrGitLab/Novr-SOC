# packages/db: PostgreSQL schema and migrations (Alembic)

`alembic.ini` and `migrations/env.py` take the URL from `NOVRSOC_MIGRATION_DATABASE_URL` (the schema owner) or from
`-x url=...`. Outside production, a guard refuses hosts listed in `NOVRSOC_PRODUCTION_DATABASE_HOSTS`.

| Migrations | Content |
|---|---|
| 0001–0011 | foundation: organizations, users, roles and permissions, sessions, sites, machine identities, audit; endpoints, alerts and cases; reports; NHAI jobs; Threat Insights; VMS; SOAR; protection; CNII; backups; account security |
| 0012 | asset inventory: assets, identifiers, services, events, sync runs, collectors |
| 0013 | SLA policies, shift handovers, notifications, playbook lifecycle, SOAR limits and emergency stop, AI activity log |
| 0014 | threat actors, CVE intelligence, snapshots; CNII authorizations, monitored assets, schedules and checks; data loss recovery; VMS schedules and verification |
| 0015 | billing plans and subscriptions, data exports, teams, NovrChat, platform analytics and health |

Migrations seed only the role and permission catalogues. A fresh database contains no tenant or demonstration
records.

Every migration has a tested downgrade. `apps/api/tests/test_migrations.py` runs upgrade → downgrade → upgrade on a
throwaway database and checks that every SECURITY DEFINER function pins its `search_path`.

Rules for new migrations:

- Keep one linear history.
- Every tenant table needs `org_id uuid NOT NULL`, a row-level security policy on `org_id = novrsoc.app_org()`,
  grants to `novrsoc_app` only, and an isolation test.
- History tables (`case_events`, `asset_events` and similar) get no UPDATE or DELETE grant for the runtime role.
  `audit_events` and `ai_activity` also have triggers that refuse UPDATE, DELETE and TRUNCATE, including for the
  schema owner.
