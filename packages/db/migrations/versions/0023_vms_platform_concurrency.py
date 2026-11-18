"""Platform-wide VMS scan concurrency: vms_running_scans(activity) counts the scan jobs running in EVERY organization
(an unexpired lease), optionally for one activity. It returns a number only, never a row, so the claim endpoint (which
runs under the claiming organization's row-level security) can hold the platform caps NOVRSOC_VMS_MAX_RUNNING_SCANS and
NOVRSOC_VMS_MAX_RUNNING_GREENBONE without seeing another organization's jobs.

Revision ID: 0023_vms_platform_concurrency
Revises: 0022_presence
"""
from alembic import op

revision = "0023_vms_platform_concurrency"
down_revision = "0022_presence"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE FUNCTION novrsoc.vms_running_scans(p_activity text DEFAULT NULL) RETURNS integer
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT count(*)::integer FROM novrsoc.vms_scan_jobs
        WHERE state = 'running' AND lease_until > now() AND (p_activity IS NULL OR activity = p_activity) $$;
    REVOKE ALL ON FUNCTION novrsoc.vms_running_scans(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.vms_running_scans(text) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS novrsoc.vms_running_scans(text);")
