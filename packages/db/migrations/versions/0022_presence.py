"""Presence: who is actually working an organization right now, from a heartbeat the web application sends while a
NovrSOC tab is open and visible (every 60 seconds). Nothing is inferred from sessions or sign-ins.

  * user_presence (user_id, org_id, last_seen_at): one row per person and organization they have open. Row-level
    security: members of the active organization see its rows; a person can write ONLY their own row, in the active
    organization. "Online" means a heartbeat within the last two minutes (the API decides; the table keeps times only).
    Rows older than 30 days are deleted by the jobs worker.

Revision ID: 0022_presence
Revises: 0021_nhai_analysis
"""
from alembic import op

revision = "0022_presence"
down_revision = "0021_nhai_analysis"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.user_presence (
      user_id      uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      org_id       uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      last_seen_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (user_id, org_id));
    CREATE INDEX user_presence_recent ON novrsoc.user_presence (org_id, last_seen_at DESC);
    ALTER TABLE novrsoc.user_presence ENABLE ROW LEVEL SECURITY;
    CREATE POLICY user_presence_read ON novrsoc.user_presence FOR SELECT USING (org_id = novrsoc.app_org());
    CREATE POLICY user_presence_insert ON novrsoc.user_presence FOR INSERT
      WITH CHECK (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user());
    CREATE POLICY user_presence_update ON novrsoc.user_presence FOR UPDATE
      USING (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user())
      WITH CHECK (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user());
    CREATE POLICY user_presence_prune ON novrsoc.user_presence FOR DELETE
      USING (org_id = novrsoc.app_org() AND last_seen_at < now() - interval '30 days');
    GRANT SELECT, INSERT, UPDATE, DELETE ON novrsoc.user_presence TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS novrsoc.user_presence;")
