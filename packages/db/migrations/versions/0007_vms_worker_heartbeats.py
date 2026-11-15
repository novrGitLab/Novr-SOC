"""VMS worker heartbeats (Phase 5, workstream B slot): the first table of the V2 worker protocol.

  * vms_worker_heartbeats keeps the latest heartbeat per vms_worker service identity. The organization (and site)
    come from the authenticated identity, never from the heartbeat body. Tenant table: RLS on novrsoc.app_org().
  * No scan-job table exists yet: scanning stays disabled in this release, so the claim endpoint never hands out
    work (contracts v1/vms.ScanClaimResult `scanning_disabled`).

Revision ID: 0007_vms_worker_heartbeats
Revises: 0006_soc_ingest_receipts
"""
from alembic import op

revision = "0007_vms_worker_heartbeats"
down_revision = "0006_soc_ingest_receipts"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.vms_worker_heartbeats (
      id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id             uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      identity_id        uuid NOT NULL UNIQUE REFERENCES novrsoc.service_identities(id),
      site_id            uuid REFERENCES novrsoc.sites(id),
      sent_at            timestamptz NOT NULL,
      received_at        timestamptz NOT NULL DEFAULT now(),
      component_version  text NOT NULL CHECK (component_version ~ '^[0-9]+\\.[0-9]+\\.[0-9]+([-+][0-9A-Za-z.-]+)?$'),
      state              text NOT NULL CHECK (state IN ('ok', 'degraded', 'failing', 'unconfigured')),
      queue_depth        integer NOT NULL DEFAULT 0 CHECK (queue_depth >= 0),
      in_flight          integer NOT NULL DEFAULT 0 CHECK (in_flight >= 0),
      dependencies       jsonb NOT NULL DEFAULT '[]'::jsonb
    );
    ALTER TABLE novrsoc.vms_worker_heartbeats ENABLE ROW LEVEL SECURITY;
    CREATE POLICY vms_worker_heartbeats_tenant ON novrsoc.vms_worker_heartbeats FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.vms_worker_heartbeats TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS novrsoc.vms_worker_heartbeats;")
