"""Least-privilege grants for the dedicated NHAI worker role (`novrsoc_nhai`, Server 1, gate G-F2).

The worker (app/nhai/worker.py) handles every consolidated NHAI task: alert explanation, finding explanation, asset
summary and NovrChat answer. The evidence bundle is built by the API when a job is queued and stored in the job, so
the worker reads no evidence table. It needs exactly:
  * the two SECURITY DEFINER queue functions (claim with a bounded lease; expiry);
  * nhai_jobs: SELECT of the job columns it reads, UPDATE of the columns it finishes (status, result, error_code,
    finished_at, lease_until, worker_id); never the bundle, the requester or the review;
  * alerts, vms_findings: SELECT (id, org_id, severity) to take the authoritative severity and check the subject
    still exists; assets: SELECT (id, org_id) for the same existence check. No other column, no other table;
  * ai_activity and audit_events: INSERT only (both are append-only; no SELECT, no UPDATE);
  * novrsoc.app_org() for row-level security, which applies to this role exactly as to the API's role.
It has no access to users, sessions, identities, cases, chat messages or any other table, and cannot bypass RLS.
Also: the ai_activity trigger function (0013) kept the default EXECUTE for PUBLIC; it is revoked here, as for every
other function in the schema (a trigger function cannot be called directly, so this is hygiene, not a fix).

The role itself is created NOLOGIN by the cluster init scripts (it is a cluster object; the schema owner that runs
migrations cannot create roles). The platform owner enables login at gate G-F2 (docs/public/DEPLOYMENT.md).
"""
from alembic import op

revision = "0016_nhai_worker_role"
down_revision = "0015_admin_exports_chat"
branch_labels = None
depends_on = None

ROLE = "novrsoc_nhai"


def upgrade() -> None:
    op.execute(f"""
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
        RAISE EXCEPTION 'role {ROLE} is missing: create it NOLOGIN as the superuser first (deploy/server2/postgres-init/01-roles.sh)';
      END IF;
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}' AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb)) THEN
        RAISE EXCEPTION 'role {ROLE} must be NOSUPERUSER NOBYPASSRLS NOCREATEROLE NOCREATEDB';
      END IF;
    END $$;
    REVOKE ALL ON FUNCTION novrsoc.ai_activity_immutable() FROM PUBLIC;
    GRANT USAGE ON SCHEMA novrsoc TO {ROLE};
    GRANT EXECUTE ON FUNCTION novrsoc.app_org() TO {ROLE};
    GRANT EXECUTE ON FUNCTION novrsoc.nhai_claim_job(text, integer), novrsoc.nhai_expire_jobs() TO {ROLE};
    GRANT SELECT (id, org_id, task, subject_type, subject_id, requested_by, status, attempts, max_attempts, worker_id, bundle)
      ON novrsoc.nhai_jobs TO {ROLE};
    GRANT UPDATE (status, error_code, result, finished_at, lease_until, worker_id) ON novrsoc.nhai_jobs TO {ROLE};
    GRANT SELECT (id, org_id, severity) ON novrsoc.alerts TO {ROLE};
    GRANT SELECT (id, org_id, severity) ON novrsoc.vms_findings TO {ROLE};
    GRANT SELECT (id, org_id) ON novrsoc.assets TO {ROLE};
    GRANT INSERT (org_id, kind, module, task, subject_type, subject_id, actor_type, actor_id, actor_label, model, outcome,
                  summary, details, nhai_job_id) ON novrsoc.ai_activity TO {ROLE};
    GRANT INSERT (org_id, actor_type, actor_id, actor_label, action, outcome, resource_type, resource_id, request_id, ip,
                  details) ON novrsoc.audit_events TO {ROLE};
    """)


def downgrade() -> None:
    op.execute(f"""
    GRANT EXECUTE ON FUNCTION novrsoc.ai_activity_immutable() TO PUBLIC;
    DO $$ BEGIN
      IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{ROLE}') THEN
        REVOKE ALL ON ALL TABLES IN SCHEMA novrsoc FROM {ROLE};
        REVOKE ALL ON FUNCTION novrsoc.app_org(), novrsoc.nhai_claim_job(text, integer), novrsoc.nhai_expire_jobs() FROM {ROLE};
        REVOKE USAGE ON SCHEMA novrsoc FROM {ROLE};
      END IF;
    END $$;
    """)
