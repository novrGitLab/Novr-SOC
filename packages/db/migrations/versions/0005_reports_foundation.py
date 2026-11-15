"""Reports foundation: organisation-scoped report requests and history.

  reports:read    read the organisation's report history and report content (super_admin, soc_manager, analyst, executive)
  reports:manage  request reports (super_admin, soc_manager, analyst)

A report stores, per section, the honest state of its data source (data_states) next to the content, so an
unavailable source can never be mistaken for "no findings". Idempotent per (org_id, idempotency_key).

Revision ID: 0005_reports_foundation
Revises: 0004_soc_foundation
"""
from alembic import op

revision = "0005_reports_foundation"
down_revision = "0004_soc_foundation"
branch_labels = None
depends_on = None

PERMS = [("reports:read", "Read the organization's report history and reports"),
         ("reports:manage", "Request reports for the organization")]
GRANTS = {"reports:read": ["super_admin", "soc_manager", "analyst", "executive"],
          "reports:manage": ["super_admin", "soc_manager", "analyst"]}


def _q(s):
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " + ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMS))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for p, rs in GRANTS.items() for r in rs))
    op.execute("""
    CREATE TABLE novrsoc.report_requests (
      id              uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id          uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      report_type     text NOT NULL CHECK (report_type ~ '^[a-z_]{3,40}$'),
      idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
      period_start    timestamptz NOT NULL,
      period_end      timestamptz NOT NULL CHECK (period_end > period_start),
      format          text NOT NULL CHECK (format IN ('json', 'csv')),
      status          text NOT NULL CHECK (status IN ('queued', 'generating', 'ready', 'failed')),
      requested_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      requested_at    timestamptz NOT NULL DEFAULT now(),
      completed_at    timestamptz,
      data_states     jsonb NOT NULL DEFAULT '{}'::jsonb,
      content         jsonb,
      sha256          text CHECK (sha256 ~ '^[0-9a-f]{64}$'),
      failure_reason  text NOT NULL DEFAULT '',
      UNIQUE (org_id, idempotency_key)
    );
    CREATE INDEX report_requests_org ON novrsoc.report_requests (org_id, requested_at DESC);
    ALTER TABLE novrsoc.report_requests ENABLE ROW LEVEL SECURITY;
    CREATE POLICY report_requests_tenant ON novrsoc.report_requests FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.report_requests TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS novrsoc.report_requests;")
    keys = ", ".join(_q(k) for k, _ in PERMS)
    op.execute(f"DELETE FROM novrsoc.role_permissions WHERE permission_key IN ({keys}); DELETE FROM novrsoc.permissions WHERE key IN ({keys});")
