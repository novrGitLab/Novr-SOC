"""Novr Human-Assisted Intelligence (NHAI) asynchronous jobs (Phase 5, workstream F).

  * nhai_jobs: one row per NHAI request. Tenant table (RLS on novrsoc.app_org()). The context bundle stored with
    the job is assembled server-side from the requesting organization only, and is redacted before storage.
  * Inference runs in a separate worker. The worker claims the oldest queued job across organizations only
    through novrsoc.nhai_claim_job() (SECURITY DEFINER, FOR UPDATE SKIP LOCKED, bounded lease), then switches to
    that job's organization context for every other statement, so RLS still applies to its reads and writes.
  * novrsoc.nhai_expire_jobs() ends jobs past their deadline (timed_out) and re-queues a running job whose lease
    expired while attempts remain.
  * Review: decision, reviewer identity and time are stored on the job. A result is never applied automatically.
  * At most one queued or running job per (organization, task, subject): repeated clicks return the same job.

Revision ID: 0008_nhai_jobs
Revises: 0007_vms_worker_heartbeats
"""
from alembic import op

revision = "0008_nhai_jobs"
down_revision = "0007_vms_worker_heartbeats"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.nhai_jobs (
      id               uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id           uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      task             text NOT NULL CHECK (task IN ('alert_explanation', 'behavioural_insight_summary',
                                                     'investigation_assistance', 'case_note_draft')),
      subject_type     text NOT NULL CHECK (subject_type ~ '^[a-z_]{2,40}$'),
      subject_id       text NOT NULL CHECK (length(subject_id) BETWEEN 1 AND 200),
      requested_by     uuid NOT NULL REFERENCES novrsoc.users(id),
      requested_label  text NOT NULL DEFAULT '',
      status           text NOT NULL DEFAULT 'queued'
                         CHECK (status IN ('queued', 'running', 'succeeded', 'failed', 'timed_out')),
      attempts         integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
      max_attempts     integer NOT NULL DEFAULT 2 CHECK (max_attempts BETWEEN 1 AND 5),
      queued_at        timestamptz NOT NULL DEFAULT now(),
      started_at       timestamptz,
      finished_at      timestamptz,
      deadline_at      timestamptz NOT NULL,
      lease_until      timestamptz,
      worker_id        text CHECK (worker_id IS NULL OR worker_id ~ '^[A-Za-z0-9_.:-]{1,80}$'),
      bundle           jsonb NOT NULL,
      result           jsonb,
      error_code       text CHECK (error_code IS NULL OR error_code ~ '^[a-z_]{2,40}$'),
      review_decision  text CHECK (review_decision IN ('accept', 'accept_with_edits', 'reject')),
      reviewer_id      uuid REFERENCES novrsoc.users(id),
      reviewer_label   text,
      review_note      text NOT NULL DEFAULT '',
      reviewed_at      timestamptz,
      UNIQUE (id, org_id),
      CHECK ((status = 'succeeded') = (result IS NOT NULL)),
      CHECK (review_decision IS NULL OR (status = 'succeeded' AND reviewer_id IS NOT NULL AND reviewed_at IS NOT NULL))
    );
    CREATE UNIQUE INDEX nhai_jobs_one_active ON novrsoc.nhai_jobs (org_id, task, subject_type, subject_id)
      WHERE status IN ('queued', 'running');
    CREATE INDEX nhai_jobs_queue ON novrsoc.nhai_jobs (queued_at) WHERE status = 'queued';
    ALTER TABLE novrsoc.nhai_jobs ENABLE ROW LEVEL SECURITY;
    CREATE POLICY nhai_jobs_tenant ON novrsoc.nhai_jobs FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.nhai_jobs TO novrsoc_app;

    CREATE FUNCTION novrsoc.nhai_claim_job(p_worker text, p_lease_seconds integer)
      RETURNS TABLE (job_id uuid, org_id uuid)
      LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        UPDATE novrsoc.nhai_jobs j
           SET status = 'running', attempts = j.attempts + 1, started_at = now(), worker_id = p_worker,
               lease_until = now() + make_interval(secs => greatest(30, least(p_lease_seconds, 3600)))
         WHERE j.id = (SELECT q.id FROM novrsoc.nhai_jobs q
                        WHERE q.status = 'queued' AND q.deadline_at > now()
                        ORDER BY q.queued_at FOR UPDATE SKIP LOCKED LIMIT 1)
        RETURNING j.id, j.org_id $$;

    CREATE FUNCTION novrsoc.nhai_expire_jobs() RETURNS integer
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE n integer; m integer;
      BEGIN
        UPDATE novrsoc.nhai_jobs SET status = 'timed_out', error_code = 'deadline_exceeded', finished_at = now(),
               lease_until = NULL
         WHERE status IN ('queued', 'running') AND deadline_at <= now();
        GET DIAGNOSTICS n = ROW_COUNT;
        UPDATE novrsoc.nhai_jobs
           SET status = CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'timed_out' END,
               error_code = CASE WHEN attempts < max_attempts THEN error_code ELSE 'lease_expired' END,
               finished_at = CASE WHEN attempts < max_attempts THEN NULL ELSE now() END,
               lease_until = NULL, worker_id = NULL
         WHERE status = 'running' AND lease_until < now();
        GET DIAGNOSTICS m = ROW_COUNT;
        RETURN n + m;
      END $$;

    REVOKE ALL ON FUNCTION novrsoc.nhai_claim_job(text, integer) FROM PUBLIC;
    REVOKE ALL ON FUNCTION novrsoc.nhai_expire_jobs() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.nhai_claim_job(text, integer) TO novrsoc_app;
    GRANT EXECUTE ON FUNCTION novrsoc.nhai_expire_jobs() TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.nhai_expire_jobs();
    DROP FUNCTION IF EXISTS novrsoc.nhai_claim_job(text, integer);
    DROP TABLE IF EXISTS novrsoc.nhai_jobs;
    """)
