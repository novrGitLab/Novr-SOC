"""VMS organization scan policy and asset enrollment; collection-group attribution.

  * vms_scan_policies: ONE policy per organization, the standing authorization that replaces per-endpoint approvals.
    Disabled by default. Enabling it requires an authorization reference and at least one scan window. It carries the
    controls every scan of the organization is held to: protected networks (never scanned, whatever a scope says),
    scan windows (in the organization's timezone), a packet-rate ceiling handed to the worker, a per-scan target cap,
    a concurrency cap, how fresh an endpoint-reported address must be, and whether imported assets are enrolled
    automatically (auto_enroll) and rescanned on an interval.
  * vms_enrollments: the VMS view of the canonical asset inventory. One row per asset with the decision and its
    reason: enrolled (inside an approved scope, private, fresh, unique in the organization, from a monitoring source),
    eligible (the same, while automatic enrollment is off), or why not (public address, shared address, stale address, protected network, outside every scope, ...).
    Nothing here copies an asset: it references novrsoc.assets (same organization, composite key).
  * vms_scan_jobs: origin (manual | schedule | rescan | enrollment), progress (per-target outcomes reported by the
    worker), asset_ids (the canonical assets an enrollment scan covers) and max_rate_pps (the policy ceiling at
    queue time).
  * novrsoc_nhai (the NHAI worker role, migration 0016): SELECT (id, org_id) on cases, to check that the subject of an
    investigation-assistance job still exists. No other column of a case is readable by the worker.
  * alert_quarantine: reason collection_group_only. An agent that carries ONLY collection groups (Wazuh `default`,
    configured with NOVRSOC_WAZUH_COLLECTION_GROUPS) has no verified owner: its alerts are quarantined, never given
    to whichever organization maps such a group.

Revision ID: 0018_vms_policy_attribution
Revises: 0017_org_management_log_sources
"""
from alembic import op

revision = "0018_vms_policy_attribution"
down_revision = "0017_org_management_log_sources"
branch_labels = None
depends_on = None

QUARANTINE_OLD = ("('no_organization_for_groups', 'ambiguous_organization', 'unknown_log_source', 'log_source_disabled', "
                  "'manager_local_event')")
QUARANTINE_NEW = ("('no_organization_for_groups', 'ambiguous_organization', 'unknown_log_source', 'log_source_disabled', "
                  "'manager_local_event', 'collection_group_only')")
ENROLLMENT = ("('enrolled', 'eligible', 'excluded_protected', 'outside_scope', 'public_address', 'shared_address', 'stale_address', "
              "'no_address', 'unverified_source', 'manual_exclusion')")


def upgrade() -> None:
    op.execute(f"""
    ALTER TABLE novrsoc.alert_quarantine DROP CONSTRAINT alert_quarantine_reason_check;
    ALTER TABLE novrsoc.alert_quarantine ADD CONSTRAINT alert_quarantine_reason_check CHECK (reason IN {QUARANTINE_NEW});

    CREATE TABLE novrsoc.vms_scan_policies (
      org_id                  uuid PRIMARY KEY REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      enabled                 boolean NOT NULL DEFAULT false,
      auto_enroll             boolean NOT NULL DEFAULT false,
      enroll_activity         text NOT NULL DEFAULT 'ports' CHECK (enroll_activity IN ('discovery', 'ports', 'vuln_nuclei', 'vuln_openvas')),
      rescan_interval_days    integer NOT NULL DEFAULT 7 CHECK (rescan_interval_days BETWEEN 1 AND 90),
      protected_networks      cidr[] NOT NULL DEFAULT '{{}}',
      windows                 jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(windows) = 'array'),
      timezone                text NOT NULL DEFAULT 'UTC' CHECK (length(timezone) BETWEEN 1 AND 64),
      max_targets_per_scan    integer NOT NULL DEFAULT 32 CHECK (max_targets_per_scan BETWEEN 1 AND 256),
      max_rate_pps            integer NOT NULL DEFAULT 100 CHECK (max_rate_pps BETWEEN 1 AND 1000),
      max_concurrent_scans    integer NOT NULL DEFAULT 1 CHECK (max_concurrent_scans BETWEEN 1 AND 4),
      address_max_age_hours   integer NOT NULL DEFAULT 72 CHECK (address_max_age_hours BETWEEN 1 AND 720),
      authorization_reference text NOT NULL DEFAULT '' CHECK (length(authorization_reference) <= 200),
      updated_by              uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      updated_at              timestamptz NOT NULL DEFAULT now(),
      CHECK (NOT enabled OR (length(authorization_reference) >= 3 AND jsonb_array_length(windows) > 0)),
      CHECK (NOT auto_enroll OR enabled)
    );
    CREATE TABLE novrsoc.vms_enrollments (
      id             uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id         uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      asset_id       uuid NOT NULL,
      address        inet,
      scope_id       uuid,
      status         text NOT NULL CHECK (status IN {ENROLLMENT}),
      reason         text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
      evaluated_at   timestamptz NOT NULL DEFAULT now(),
      last_job_id    uuid,
      last_scanned_at timestamptz,
      excluded_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      UNIQUE (org_id, asset_id),
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE CASCADE,
      FOREIGN KEY (scope_id, org_id) REFERENCES novrsoc.vms_scopes (id, org_id) ON DELETE SET NULL (scope_id));
    CREATE INDEX vms_enrollments_status ON novrsoc.vms_enrollments (org_id, status);

    ALTER TABLE novrsoc.vms_scan_jobs
      ADD COLUMN origin text NOT NULL DEFAULT 'manual' CHECK (origin IN ('manual', 'schedule', 'rescan', 'enrollment')),
      ADD COLUMN progress jsonb NOT NULL DEFAULT '{{}}'::jsonb,
      ADD COLUMN asset_ids uuid[] NOT NULL DEFAULT '{{}}',
      ADD COLUMN max_rate_pps integer CHECK (max_rate_pps IS NULL OR max_rate_pps BETWEEN 1 AND 1000);
    """)
    for t in ("vms_scan_policies", "vms_enrollments"):
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
        GRANT SELECT, INSERT, UPDATE ON novrsoc.{t} TO novrsoc_app;""")
    op.execute("GRANT SELECT (id, org_id) ON novrsoc.cases TO novrsoc_nhai;")


def downgrade() -> None:
    op.execute(f"""
    REVOKE SELECT (id, org_id) ON novrsoc.cases FROM novrsoc_nhai;
    ALTER TABLE novrsoc.vms_scan_jobs DROP COLUMN max_rate_pps, DROP COLUMN asset_ids, DROP COLUMN progress, DROP COLUMN origin;
    DROP TABLE IF EXISTS novrsoc.vms_enrollments;
    DROP TABLE IF EXISTS novrsoc.vms_scan_policies;
    DELETE FROM novrsoc.alert_quarantine WHERE reason NOT IN {QUARANTINE_OLD};
    ALTER TABLE novrsoc.alert_quarantine DROP CONSTRAINT alert_quarantine_reason_check;
    ALTER TABLE novrsoc.alert_quarantine ADD CONSTRAINT alert_quarantine_reason_check CHECK (reason IN {QUARANTINE_OLD});
    """)
