"""NHAI combined analysis (posture analysis over SIEM, VMS, assets, cases, Threat Insights, SOAR, remediation and
posture) and the NHAI worker's own heartbeat.

  * nhai_jobs: task posture_analysis. Its subject is the organization itself (subject_type organization) or, for
    platform staff with the platform organization active, the platform (subject_type platform: per-organization
    aggregates only, stored in the platform organization's tenant).
  * nhai_heartbeat(instance, state, detail): the NHAI worker (role novrsoc_nhai) reports its liveness. It can write ONLY
    the nhai_worker row; the general platform_heartbeat stays the API's.
  * nhai_worker_status(): the worker's last heartbeat (state, detail, time) for the NHAI readiness view of any
    organization. No tenant data is in it.

Revision ID: 0021_nhai_analysis
Revises: 0020_soar_automation
"""
from alembic import op

revision = "0021_nhai_analysis"
down_revision = "0020_soar_automation"
branch_labels = None
depends_on = None

TASKS_OLD = ("'alert_explanation', 'behavioural_insight_summary', 'investigation_assistance', 'case_note_draft', "
             "'finding_explanation', 'asset_summary', 'chat_answer'")


def upgrade() -> None:
    op.execute(f"""
    ALTER TABLE novrsoc.nhai_jobs DROP CONSTRAINT nhai_jobs_task_check;
    ALTER TABLE novrsoc.nhai_jobs ADD CONSTRAINT nhai_jobs_task_check CHECK (task IN ({TASKS_OLD}, 'posture_analysis'));

    CREATE FUNCTION novrsoc.nhai_heartbeat(p_instance text, p_state text, p_detail text) RETURNS void
      LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        INSERT INTO novrsoc.platform_heartbeats (component, instance, state, detail)
        VALUES ('nhai_worker', left(p_instance, 120), p_state, left(p_detail, 500))
        ON CONFLICT (component) DO UPDATE SET instance = EXCLUDED.instance, state = EXCLUDED.state, detail = EXCLUDED.detail,
          last_seen_at = now() $$;
    REVOKE ALL ON FUNCTION novrsoc.nhai_heartbeat(text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.nhai_heartbeat(text, text, text) TO novrsoc_nhai, novrsoc_app;

    CREATE FUNCTION novrsoc.nhai_worker_status() RETURNS TABLE (instance text, state text, detail text, last_seen_at timestamptz)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT instance, state, detail, last_seen_at FROM novrsoc.platform_heartbeats WHERE component = 'nhai_worker' $$;
    REVOKE ALL ON FUNCTION novrsoc.nhai_worker_status() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.nhai_worker_status() TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute(f"""
    DROP FUNCTION IF EXISTS novrsoc.nhai_worker_status();
    DROP FUNCTION IF EXISTS novrsoc.nhai_heartbeat(text, text, text);
    DELETE FROM novrsoc.platform_heartbeats WHERE component = 'nhai_worker';
    DELETE FROM novrsoc.nhai_jobs WHERE task = 'posture_analysis';
    ALTER TABLE novrsoc.nhai_jobs DROP CONSTRAINT nhai_jobs_task_check;
    ALTER TABLE novrsoc.nhai_jobs ADD CONSTRAINT nhai_jobs_task_check CHECK (task IN ({TASKS_OLD}));
    """)
