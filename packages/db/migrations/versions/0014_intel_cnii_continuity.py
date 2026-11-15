"""Threat intelligence (actors, CVE and IOC snapshots), CNII monitoring scope, data continuity, VMS schedules and
verification requests.

ti_threat_actors      actor profiles with an explicit attribution state: verified (needs at least one cited source),
                      suspected, or unknown. Nothing is pre-loaded: profiles are entered or imported by analysts.
ti_actor_links        an actor's association with an indicator, CVE, case, alert or asset; each association is itself
                      verified or suspected, with a rationale
ti_cve_records        CVE intelligence per organization (CVSS, EPSS, KEV), every import a new snapshot row
ti_snapshots          point-in-time evidence snapshots (CVSS or IOC state) with a SHA-256 over the frozen content
cnii_authorizations   the authorization record that permits monitoring (reference, issuing authority, validity)
cnii_monitored_assets designated assets: a canonical asset + an active authorization + a sector. Server-side checks
                      refuse an asset without a valid authorization.
cnii_schedules, cnii_checks   monitoring schedules and their recorded results (no probe runs unless configured)
recovery_plans, recovery_requests, recovery_events   recovery management: plans with RPO/RTO targets and their backup
                      source; requests decided by someone other than the requester; verification and evidence
vms_scan_schedules    recurring scans inside an approved scope (disabled by default; due schedules create jobs only
                      where scanning is enabled)
vms_verification_requests   retest requests for a finding, linked to the scan job that verifies it

Revision ID: 0014_intel_cnii_continuity
Revises: 0013_secops_soar_ai_activity
"""
from alembic import op

revision = "0014_intel_cnii_continuity"
down_revision = "0013_secops_soar_ai_activity"
branch_labels = None
depends_on = None

TENANT = ["ti_threat_actors", "ti_actor_links", "ti_cve_records", "ti_snapshots", "cnii_authorizations", "cnii_monitored_assets",
          "cnii_schedules", "cnii_checks", "recovery_plans", "recovery_requests", "recovery_events", "vms_scan_schedules",
          "vms_verification_requests"]


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.ti_threat_actors (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
      aliases text[] NOT NULL DEFAULT '{}',
      attribution text NOT NULL CHECK (attribution IN ('verified', 'suspected', 'unknown')),
      confidence integer NOT NULL DEFAULT 0 CHECK (confidence BETWEEN 0 AND 100),
      description text NOT NULL DEFAULT '' CHECK (length(description) <= 8000),
      motivations text[] NOT NULL DEFAULT '{}',
      target_sectors text[] NOT NULL DEFAULT '{}',
      target_regions text[] NOT NULL DEFAULT '{}',
      techniques text[] NOT NULL DEFAULT '{}',
      first_seen date, last_seen date,
      sources jsonb NOT NULL DEFAULT '[]'::jsonb,
      stix_id text,
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, created_label text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name), UNIQUE (id, org_id),
      CHECK (jsonb_typeof(sources) = 'array'),
      CHECK (attribution <> 'verified' OR jsonb_array_length(sources) > 0),
      CHECK (attribution <> 'unknown' OR confidence = 0));
    CREATE TABLE novrsoc.ti_actor_links (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      actor_id uuid NOT NULL,
      link_type text NOT NULL CHECK (link_type IN ('indicator', 'cve', 'case', 'alert', 'asset')),
      ref_id text NOT NULL CHECK (length(ref_id) BETWEEN 1 AND 200),
      association text NOT NULL CHECK (association IN ('verified', 'suspected')),
      rationale text NOT NULL CHECK (length(rationale) BETWEEN 3 AND 2000),
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, created_label text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (actor_id, link_type, ref_id),
      FOREIGN KEY (actor_id, org_id) REFERENCES novrsoc.ti_threat_actors (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.ti_cve_records (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      cve_id text NOT NULL CHECK (cve_id ~ '^CVE-[0-9]{4}-[0-9]{4,7}$'),
      cvss_v3 numeric(3,1) CHECK (cvss_v3 BETWEEN 0 AND 10),
      cvss_vector text,
      epss numeric(6,5) CHECK (epss BETWEEN 0 AND 1),
      kev boolean NOT NULL DEFAULT false,
      kev_added date,
      published_at date,
      description text NOT NULL DEFAULT '' CHECK (length(description) <= 4000),
      source text NOT NULL CHECK (length(source) BETWEEN 2 AND 80),
      captured_at timestamptz NOT NULL DEFAULT now(),
      imported_label text NOT NULL DEFAULT '');
    CREATE INDEX ti_cve_records_latest ON novrsoc.ti_cve_records (org_id, cve_id, captured_at DESC);
    CREATE TABLE novrsoc.ti_snapshots (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      kind text NOT NULL CHECK (kind IN ('cvss', 'ioc')),
      subject text NOT NULL CHECK (length(subject) BETWEEN 1 AND 300),
      content jsonb NOT NULL,
      sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
      reason text NOT NULL DEFAULT '' CHECK (length(reason) <= 500),
      captured_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, captured_label text NOT NULL DEFAULT '',
      captured_at timestamptz NOT NULL DEFAULT now());

    CREATE TABLE novrsoc.cnii_authorizations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      reference text NOT NULL CHECK (length(reference) BETWEEN 3 AND 200),
      issuing_authority text NOT NULL CHECK (length(issuing_authority) BETWEEN 2 AND 200),
      scope_description text NOT NULL CHECK (length(scope_description) BETWEEN 3 AND 4000),
      sectors text[] NOT NULL CHECK (cardinality(sectors) > 0),
      valid_from timestamptz NOT NULL, valid_until timestamptz NOT NULL,
      document_sha256 text CHECK (document_sha256 IS NULL OR document_sha256 ~ '^[0-9a-f]{64}$'),
      recorded_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, recorded_label text NOT NULL DEFAULT '',
      revoked_at timestamptz, revoked_reason text,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, reference), UNIQUE (id, org_id),
      CHECK (valid_until > valid_from));
    CREATE TABLE novrsoc.cnii_monitored_assets (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      asset_id uuid NOT NULL,
      authorization_id uuid NOT NULL,
      sector text NOT NULL,
      owning_unit text NOT NULL CHECK (length(owning_unit) BETWEEN 2 AND 200),
      monitoring text NOT NULL CHECK (monitoring IN ('availability', 'vulnerability', 'both')),
      status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
      designated_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, designated_label text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, asset_id), UNIQUE (id, org_id),
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE CASCADE,
      FOREIGN KEY (authorization_id, org_id) REFERENCES novrsoc.cnii_authorizations (id, org_id));
    CREATE TABLE novrsoc.cnii_schedules (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      monitored_asset_id uuid NOT NULL,
      check_kind text NOT NULL CHECK (check_kind IN ('availability', 'vulnerability_scan')),
      interval_minutes integer NOT NULL CHECK (interval_minutes BETWEEN 5 AND 43200),
      enabled boolean NOT NULL DEFAULT false,
      next_due_at timestamptz, last_run_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (monitored_asset_id, check_kind),
      FOREIGN KEY (monitored_asset_id, org_id) REFERENCES novrsoc.cnii_monitored_assets (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.cnii_checks (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      monitored_asset_id uuid NOT NULL,
      kind text NOT NULL CHECK (kind IN ('availability', 'vulnerability_scan')),
      observed_at timestamptz NOT NULL DEFAULT now(),
      outcome text NOT NULL CHECK (outcome IN ('up', 'down', 'degraded', 'not_run')),
      latency_ms integer CHECK (latency_ms >= 0),
      detail text NOT NULL DEFAULT '' CHECK (length(detail) <= 1000),
      source text NOT NULL,
      FOREIGN KEY (monitored_asset_id, org_id) REFERENCES novrsoc.cnii_monitored_assets (id, org_id) ON DELETE CASCADE);
    CREATE INDEX cnii_checks_asset ON novrsoc.cnii_checks (monitored_asset_id, observed_at DESC);

    CREATE TABLE novrsoc.recovery_plans (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name text NOT NULL CHECK (length(name) BETWEEN 3 AND 200),
      scope text NOT NULL CHECK (length(scope) BETWEEN 3 AND 4000),
      backup_source text NOT NULL CHECK (backup_source IN ('novrsoc_platform_backup', 'external_provider', 'manual_procedure')),
      provider_name text NOT NULL DEFAULT '' CHECK (length(provider_name) <= 200),
      rpo_minutes integer CHECK (rpo_minutes BETWEEN 1 AND 525600),
      rto_minutes integer CHECK (rto_minutes BETWEEN 1 AND 525600),
      procedure text NOT NULL DEFAULT '' CHECK (length(procedure) <= 8000),
      owning_unit text NOT NULL DEFAULT '' CHECK (length(owning_unit) <= 200),
      last_tested_at timestamptz,
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name), UNIQUE (id, org_id),
      CHECK (backup_source <> 'external_provider' OR length(provider_name) >= 2));
    CREATE TABLE novrsoc.recovery_requests (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      plan_id uuid,
      title text NOT NULL CHECK (length(title) BETWEEN 3 AND 200),
      description text NOT NULL CHECK (length(description) BETWEEN 10 AND 4000),
      affected_data text NOT NULL CHECK (length(affected_data) BETWEEN 3 AND 2000),
      loss_detected_at timestamptz NOT NULL,
      requested_recovery_point timestamptz,
      status text NOT NULL DEFAULT 'submitted' CHECK (status IN ('submitted', 'assessing', 'approved', 'in_progress', 'completed',
                                                              'rejected', 'not_recoverable')),
      requested_by uuid NOT NULL REFERENCES novrsoc.users(id), requested_label text NOT NULL DEFAULT '',
      decided_by uuid REFERENCES novrsoc.users(id), decided_label text, decision_reason text,
      backup_reference text NOT NULL DEFAULT '' CHECK (length(backup_reference) <= 300),
      recovered_point timestamptz,
      verification text NOT NULL DEFAULT 'pending' CHECK (verification IN ('pending', 'verified', 'failed', 'not_applicable')),
      verified_by uuid REFERENCES novrsoc.users(id), verified_at timestamptz,
      started_at timestamptz, completed_at timestamptz,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (id, org_id),
      FOREIGN KEY (plan_id, org_id) REFERENCES novrsoc.recovery_plans (id, org_id) ON DELETE SET NULL (plan_id),
      CHECK (decided_by IS NULL OR decided_by <> requested_by),
      CHECK (verified_by IS NULL OR verified_by <> requested_by));
    CREATE TABLE novrsoc.recovery_events (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      request_id uuid NOT NULL,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      kind text NOT NULL CHECK (kind IN ('submitted', 'status_changed', 'note', 'evidence', 'verification')),
      actor_label text NOT NULL DEFAULT '',
      body text NOT NULL DEFAULT '' CHECK (length(body) <= 4000),
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      FOREIGN KEY (request_id, org_id) REFERENCES novrsoc.recovery_requests (id, org_id) ON DELETE CASCADE);

    CREATE TABLE novrsoc.vms_scan_schedules (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      scope_id uuid NOT NULL,
      name text NOT NULL CHECK (length(name) BETWEEN 3 AND 120),
      activity text NOT NULL,
      targets text[] NOT NULL CHECK (cardinality(targets) BETWEEN 1 AND 256),
      cadence text NOT NULL CHECK (cadence IN ('daily', 'weekly', 'monthly')),
      enabled boolean NOT NULL DEFAULT false,
      next_run_at timestamptz NOT NULL,
      last_job_id uuid,
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name),
      FOREIGN KEY (scope_id, org_id) REFERENCES novrsoc.vms_scopes (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.vms_verification_requests (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      finding_id uuid NOT NULL,
      status text NOT NULL CHECK (status IN ('scan_requested', 'blocked_scanning_disabled', 'blocked_no_scope', 'verified',
                                             'still_present', 'cancelled')),
      scan_job_id uuid,
      requested_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL, requested_label text NOT NULL DEFAULT '',
      note text NOT NULL DEFAULT '' CHECK (length(note) <= 2000),
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY (finding_id, org_id) REFERENCES novrsoc.vms_findings (id, org_id) ON DELETE CASCADE);
    CREATE INDEX vms_verification_finding ON novrsoc.vms_verification_requests (finding_id, created_at DESC);
    ALTER TABLE novrsoc.vms_remediation_tasks ADD COLUMN assignee_id uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL;
    """)
    for t in TENANT:
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
        GRANT SELECT, INSERT, UPDATE ON novrsoc.{t} TO novrsoc_app;""")
    op.execute("""
    GRANT DELETE ON novrsoc.ti_actor_links TO novrsoc_app;
    REVOKE UPDATE ON novrsoc.ti_snapshots, novrsoc.recovery_events, novrsoc.cnii_checks FROM novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    ALTER TABLE novrsoc.vms_remediation_tasks DROP COLUMN IF EXISTS assignee_id;
    DROP TABLE IF EXISTS novrsoc.vms_verification_requests, novrsoc.vms_scan_schedules, novrsoc.recovery_events,
      novrsoc.recovery_requests, novrsoc.recovery_plans, novrsoc.cnii_checks, novrsoc.cnii_schedules, novrsoc.cnii_monitored_assets,
      novrsoc.cnii_authorizations, novrsoc.ti_snapshots, novrsoc.ti_cve_records, novrsoc.ti_actor_links, novrsoc.ti_threat_actors;
    """)
