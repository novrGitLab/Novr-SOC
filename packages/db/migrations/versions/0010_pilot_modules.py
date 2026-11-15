"""Pilot modules (consolidated local pilot): SOAR engine, VMS jobs and findings, Email Security, Brand Protection,
CNII organization profiles, tenant administration helpers, STIX object store and feed runs, backups.

Every tenant table: org_id NOT NULL, RLS keyed on novrsoc.app_org(), composite (id, org_id) keys so child rows can
never reference another organization's parent. Platform tables (backup_runs, restore_drills) hold no tenant data and
are readable only by platform administrators.

SOAR: the engine and approvals live here (Server 2). A consequential step needs (1) the action in the organization's
policy allow-list, (2) a human approval by someone other than the requester, before it expires, and (3) dispatch with
a unique request_id to the Server 1 execution bridge, whose signed receipt is stored. Nothing executes automatically.

Revision ID: 0010_pilot_modules
Revises: 0009_threat_insights
"""
from alembic import op

revision = "0010_pilot_modules"
down_revision = "0009_threat_insights"
branch_labels = None
depends_on = None

PERMS = [("soar:manage", "Manage SOAR playbooks and the organization's response policy"),
         ("protection:read", "Read Email Security and Brand Protection"),
         ("protection:manage", "Manage Email Security domains, DMARC reports and Brand Protection subjects and findings"),
         ("users:manage", "Create and disable users and memberships (platform administrators)"),
         ("backups:read", "Read backup and restore-drill history (platform administrators)")]
GRANTS = {"soar:manage": ["super_admin", "soc_manager"],
          "protection:read": ["super_admin", "soc_manager", "analyst", "executive"],
          "protection:manage": ["super_admin", "soc_manager", "analyst"],
          "users:manage": ["super_admin"],
          "backups:read": ["super_admin"]}

TENANT = ["soar_playbooks", "soar_policies", "soar_runs", "soar_steps", "soar_approvals", "vms_scopes", "vms_scan_jobs",
          "vms_findings", "vms_remediation_tasks", "vms_result_batches", "email_domains", "dmarc_reports",
          "brand_watch_subjects", "brand_findings", "brand_monitoring_runs", "cnii_org_profiles", "ti_stix_objects",
          "ti_feed_runs"]


def _q(s):
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " + ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMS))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for p, rs in GRANTS.items() for r in rs))
    op.execute("""
    ALTER TABLE novrsoc.service_identities DROP CONSTRAINT service_identities_kind_check;
    ALTER TABLE novrsoc.service_identities ADD CONSTRAINT service_identities_kind_check
      CHECK (kind IN ('collector', 'vms_worker', 'forwarder', 'email_gateway', 'backup_agent', 'ti_feeder'));

    -- ======================================================== SOAR
    CREATE TABLE novrsoc.soar_playbooks (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name text NOT NULL CHECK (name ~ '^[a-z0-9][a-z0-9_-]{1,59}$'),
      version integer NOT NULL CHECK (version >= 1),
      title text NOT NULL CHECK (length(title) BETWEEN 3 AND 200),
      steps jsonb NOT NULL,
      triggers jsonb NOT NULL DEFAULT '{}'::jsonb,
      enabled boolean NOT NULL DEFAULT true,
      created_by uuid REFERENCES novrsoc.users(id),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name, version), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.soar_policies (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL UNIQUE REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      allowed_actions text[] NOT NULL DEFAULT '{}',
      allowed_agent_groups text[] NOT NULL DEFAULT '{}',
      live_enabled boolean NOT NULL DEFAULT false,
      approval_ttl_minutes integer NOT NULL DEFAULT 60 CHECK (approval_ttl_minutes BETWEEN 5 AND 1440),
      updated_by uuid REFERENCES novrsoc.users(id),
      updated_at timestamptz NOT NULL DEFAULT now());
    CREATE TABLE novrsoc.soar_runs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      playbook_id uuid NOT NULL, playbook_version integer NOT NULL,
      case_id uuid NOT NULL,
      mode text NOT NULL CHECK (mode IN ('dry_run', 'live')),
      state text NOT NULL CHECK (state IN ('pending', 'awaiting_approval', 'running', 'succeeded', 'failed', 'cancelled')),
      idempotency_key text NOT NULL CHECK (length(idempotency_key) BETWEEN 16 AND 128),
      requested_by uuid NOT NULL REFERENCES novrsoc.users(id), requested_label text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, idempotency_key), UNIQUE (id, org_id),
      FOREIGN KEY (playbook_id, org_id) REFERENCES novrsoc.soar_playbooks (id, org_id),
      FOREIGN KEY (case_id, org_id) REFERENCES novrsoc.cases (id, org_id));
    CREATE TABLE novrsoc.soar_steps (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      run_id uuid NOT NULL,
      position integer NOT NULL,
      step_key text NOT NULL, action text NOT NULL,
      target text, parameters jsonb NOT NULL DEFAULT '{}'::jsonb,
      state text NOT NULL CHECK (state IN ('pending', 'awaiting_approval', 'rejected', 'expired', 'dispatched', 'succeeded',
                                           'failed', 'dry_run', 'skipped_not_configured', 'refused_by_policy')),
      request_id uuid UNIQUE,
      receipt jsonb,
      message text NOT NULL DEFAULT '',
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (run_id, step_key), UNIQUE (id, org_id),
      FOREIGN KEY (run_id, org_id) REFERENCES novrsoc.soar_runs (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.soar_approvals (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      step_id uuid NOT NULL UNIQUE,
      action text NOT NULL, target text NOT NULL,
      justification text NOT NULL CHECK (length(justification) BETWEEN 10 AND 2000),
      requested_by uuid NOT NULL REFERENCES novrsoc.users(id), requested_label text NOT NULL DEFAULT '',
      decision text CHECK (decision IN ('approve', 'reject')),
      decided_by uuid REFERENCES novrsoc.users(id), decided_label text, reason text, decided_at timestamptz,
      expires_at timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      CHECK (decided_by IS NULL OR decided_by <> requested_by),
      FOREIGN KEY (step_id, org_id) REFERENCES novrsoc.soar_steps (id, org_id) ON DELETE CASCADE);

    -- ======================================================== VMS
    CREATE TABLE novrsoc.vms_scopes (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      kind text NOT NULL CHECK (kind IN ('ip', 'cidr', 'domain', 'url')),
      value text NOT NULL CHECK (length(value) BETWEEN 1 AND 253),
      allowed_activities text[] NOT NULL,
      authorization_reference text NOT NULL CHECK (length(authorization_reference) BETWEEN 3 AND 200),
      approved_by uuid NOT NULL REFERENCES novrsoc.users(id),
      valid_until timestamptz NOT NULL,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, kind, value), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.vms_scan_jobs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      scope_id uuid NOT NULL,
      activity text NOT NULL, targets text[] NOT NULL, profile text NOT NULL DEFAULT 'standard',
      state text NOT NULL DEFAULT 'queued' CHECK (state IN ('queued', 'running', 'completed', 'failed', 'cancelled')),
      idempotency_key text NOT NULL,
      requested_by uuid NOT NULL REFERENCES novrsoc.users(id),
      claimed_by uuid REFERENCES novrsoc.service_identities(id), claimed_at timestamptz, lease_until timestamptz,
      finished_at timestamptz, outcome jsonb NOT NULL DEFAULT '{}'::jsonb, error text,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, idempotency_key), UNIQUE (id, org_id),
      FOREIGN KEY (scope_id, org_id) REFERENCES novrsoc.vms_scopes (id, org_id));
    CREATE TABLE novrsoc.vms_findings (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      dedupe_key text NOT NULL,
      host text NOT NULL, port integer, protocol text, check_id text, title text NOT NULL,
      severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
      cvss numeric(3,1), cves text[] NOT NULL DEFAULT '{}',
      status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'acknowledged', 'in_progress', 'fixed_pending_verification',
                                                          'verified', 'reopened', 'risk_accepted')),
      priority text NOT NULL CHECK (priority IN ('P1', 'P2', 'P3', 'P4')),
      risk_score integer NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
      source text NOT NULL,
      first_seen_at timestamptz NOT NULL DEFAULT now(), last_seen_at timestamptz NOT NULL DEFAULT now(),
      occurrences integer NOT NULL DEFAULT 1, last_job_id uuid,
      UNIQUE (org_id, dedupe_key), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.vms_remediation_tasks (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      finding_id uuid NOT NULL,
      priority text NOT NULL, due_at timestamptz NOT NULL,
      status text NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'in_progress', 'done', 'cancelled')),
      note text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, finding_id),
      FOREIGN KEY (finding_id, org_id) REFERENCES novrsoc.vms_findings (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.vms_result_batches (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      batch_id text NOT NULL, job_id uuid NOT NULL, observations integer NOT NULL, new_findings integer NOT NULL,
      received_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, batch_id),
      FOREIGN KEY (job_id, org_id) REFERENCES novrsoc.vms_scan_jobs (id, org_id));

    -- ======================================================== Email Security and Brand Protection
    CREATE TABLE novrsoc.email_domains (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      domain citext NOT NULL CHECK (domain ~ '^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\\.)+[a-z]{2,63}$'),
      verification text NOT NULL DEFAULT 'pending' CHECK (verification IN ('pending', 'verified', 'failed')),
      verification_token text NOT NULL,
      dmarc_policy text CHECK (dmarc_policy IN ('none', 'quarantine', 'reject', 'missing')),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, domain), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.dmarc_reports (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      domain_id uuid NOT NULL,
      reporter text NOT NULL, report_id text NOT NULL,
      period_start timestamptz NOT NULL, period_end timestamptz NOT NULL,
      published_policy text, messages_total integer NOT NULL, messages_failing integer NOT NULL,
      records jsonb NOT NULL, source text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, reporter, report_id),
      FOREIGN KEY (domain_id, org_id) REFERENCES novrsoc.email_domains (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.brand_watch_subjects (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      type text NOT NULL, value text NOT NULL CHECK (length(value) BETWEEN 2 AND 200),
      consent_reference text, active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, type, value), UNIQUE (id, org_id),
      CHECK (type <> 'executive' OR consent_reference IS NOT NULL));
    CREATE TABLE novrsoc.brand_findings (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      subject_id uuid NOT NULL,
      source text NOT NULL, value text NOT NULL, url text, summary text NOT NULL,
      severity text NOT NULL, status text NOT NULL DEFAULT 'new' CHECK (status IN ('new', 'triaged', 'actioned', 'dismissed')),
      evidence jsonb NOT NULL DEFAULT '{}'::jsonb, observed_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, subject_id, source, value),
      FOREIGN KEY (subject_id, org_id) REFERENCES novrsoc.brand_watch_subjects (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.brand_monitoring_runs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      subject_id uuid NOT NULL, source text NOT NULL,
      started_at timestamptz NOT NULL DEFAULT now(), finished_at timestamptz,
      outcome text CHECK (outcome IN ('completed', 'source_unconfigured', 'rate_limited', 'failed')),
      new_findings integer NOT NULL DEFAULT 0,
      FOREIGN KEY (subject_id, org_id) REFERENCES novrsoc.brand_watch_subjects (id, org_id) ON DELETE CASCADE);

    -- ======================================================== CNII organization profiles
    CREATE TABLE novrsoc.cnii_org_profiles (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL UNIQUE REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      sectors text[] NOT NULL CHECK (cardinality(sectors) > 0),
      criticality text NOT NULL CHECK (criticality IN ('vital', 'high', 'moderate')),
      updated_by uuid REFERENCES novrsoc.users(id), updated_at timestamptz NOT NULL DEFAULT now());

    -- ======================================================== Threat Insights: STIX object store and feed runs
    CREATE TABLE novrsoc.ti_stix_objects (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      stix_id text NOT NULL CHECK (stix_id ~ '^[a-z][a-z0-9-]+--[0-9a-f-]{36}$'),
      type text NOT NULL, modified timestamptz NOT NULL,
      source_ref text, target_ref text, relationship_type text,
      object jsonb NOT NULL, source text NOT NULL, received_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, stix_id, modified));
    CREATE INDEX ti_stix_rel ON novrsoc.ti_stix_objects (org_id, source_ref) WHERE type = 'relationship';
    CREATE TABLE novrsoc.ti_feed_runs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      source text NOT NULL, collection text NOT NULL DEFAULT '',
      objects_received integer NOT NULL, objects_stored integer NOT NULL, indicators_imported integer NOT NULL,
      rejected integer NOT NULL, received_at timestamptz NOT NULL DEFAULT now());

    -- ======================================================== backups (platform; no tenant data)
    CREATE TABLE novrsoc.backup_runs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      kind text NOT NULL CHECK (kind IN ('logical_dump', 'wal_archive')),
      started_at timestamptz NOT NULL, finished_at timestamptz,
      status text NOT NULL CHECK (status IN ('running', 'succeeded', 'failed')),
      target text NOT NULL, size_bytes bigint, sha256 text CHECK (sha256 IS NULL OR sha256 ~ '^[0-9a-f]{64}$'),
      encrypted boolean NOT NULL DEFAULT true CHECK (encrypted), note text NOT NULL DEFAULT '');
    CREATE TABLE novrsoc.restore_drills (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      backup_id uuid NOT NULL REFERENCES novrsoc.backup_runs(id),
      status text NOT NULL CHECK (status IN ('succeeded', 'failed')),
      restored_tables integer NOT NULL, row_count_checks_passed boolean NOT NULL,
      duration_seconds integer NOT NULL, finished_at timestamptz NOT NULL DEFAULT now(), note text NOT NULL DEFAULT '');
    ALTER TABLE novrsoc.backup_runs ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.restore_drills ENABLE ROW LEVEL SECURITY;
    CREATE POLICY backup_runs_platform ON novrsoc.backup_runs FOR SELECT USING (novrsoc.app_platform_admin());
    CREATE POLICY restore_drills_platform ON novrsoc.restore_drills FOR SELECT USING (novrsoc.app_platform_admin());
    GRANT SELECT ON novrsoc.backup_runs, novrsoc.restore_drills TO novrsoc_app;

    -- ======================================================== administration helpers (platform administrators only)
    CREATE FUNCTION novrsoc.admin_create_user(p_email citext, p_name text, p_hash text) RETURNS uuid
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE v uuid;
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        INSERT INTO novrsoc.users (email, display_name, password_hash) VALUES (p_email, p_name, p_hash) RETURNING id INTO v;
        RETURN v;
      END $$;
    CREATE FUNCTION novrsoc.admin_set_user_status(p_user uuid, p_status text) RETURNS boolean
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        IF p_user = novrsoc.app_user() THEN RAISE EXCEPTION 'administrators cannot change their own status'; END IF;
        UPDATE novrsoc.users SET status = p_status, failed_login_count = 0, locked_until = NULL WHERE id = p_user;
        IF p_status = 'disabled' THEN UPDATE novrsoc.sessions SET revoked_at = now() WHERE user_id = p_user AND revoked_at IS NULL; END IF;
        RETURN FOUND;
      END $$;

    -- CNII sector overview: callable only by a user holding an active designation for the sector (checked here too).
    CREATE FUNCTION novrsoc.cnii_sector_overview(p_sector text)
      RETURNS TABLE (org_id uuid, org_name text, criticality text, open_alerts bigint, critical_alerts_7d bigint, open_cases bigint)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        WITH d AS (SELECT scope_org_ids FROM novrsoc.cnii_designations
                    WHERE user_id = novrsoc.app_user() AND revoked_at IS NULL AND expires_at > now() AND p_sector = ANY(sectors)
                    ORDER BY expires_at DESC LIMIT 1)
        SELECT o.id, o.name, p.criticality,
               (SELECT count(*) FROM novrsoc.alerts a WHERE a.org_id = o.id AND a.status <> 'closed'),
               (SELECT count(*) FROM novrsoc.alerts a WHERE a.org_id = o.id AND a.severity = 'critical' AND a.observed_at > now() - interval '7 days'),
               (SELECT count(*) FROM novrsoc.cases c WHERE c.org_id = o.id AND c.status IN ('open', 'in_progress'))
          FROM novrsoc.cnii_org_profiles p JOIN novrsoc.organizations o ON o.id = p.org_id, d
         WHERE p_sector = ANY(p.sectors) AND (d.scope_org_ids IS NULL OR o.id = ANY(d.scope_org_ids))
         ORDER BY o.name $$;
    REVOKE ALL ON FUNCTION novrsoc.admin_create_user(citext, text, text), novrsoc.admin_set_user_status(uuid, text),
                           novrsoc.cnii_sector_overview(text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.admin_create_user(citext, text, text), novrsoc.admin_set_user_status(uuid, text),
                              novrsoc.cnii_sector_overview(text) TO novrsoc_app;
    """)
    for t in TENANT:
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
        GRANT SELECT, INSERT, UPDATE ON novrsoc.{t} TO novrsoc_app;""")
    op.execute("""
    -- the platform administrator also sees every CNII profile (to maintain them)
    CREATE POLICY cnii_org_profiles_platform ON novrsoc.cnii_org_profiles FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());""")


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.cnii_sector_overview(text);
    DROP FUNCTION IF EXISTS novrsoc.admin_set_user_status(uuid, text);
    DROP FUNCTION IF EXISTS novrsoc.admin_create_user(citext, text, text);
    DROP TABLE IF EXISTS novrsoc.restore_drills, novrsoc.backup_runs, novrsoc.ti_feed_runs, novrsoc.ti_stix_objects,
      novrsoc.cnii_org_profiles, novrsoc.brand_monitoring_runs, novrsoc.brand_findings, novrsoc.brand_watch_subjects,
      novrsoc.dmarc_reports, novrsoc.email_domains, novrsoc.vms_result_batches, novrsoc.vms_remediation_tasks,
      novrsoc.vms_findings, novrsoc.vms_scan_jobs, novrsoc.vms_scopes, novrsoc.soar_approvals, novrsoc.soar_steps,
      novrsoc.soar_runs, novrsoc.soar_policies, novrsoc.soar_playbooks;
    DELETE FROM novrsoc.service_identities WHERE kind = 'ti_feeder';
    ALTER TABLE novrsoc.service_identities DROP CONSTRAINT service_identities_kind_check;
    ALTER TABLE novrsoc.service_identities ADD CONSTRAINT service_identities_kind_check
      CHECK (kind IN ('collector', 'vms_worker', 'forwarder', 'email_gateway', 'backup_agent'));
    DELETE FROM novrsoc.role_permissions WHERE permission_key IN ('soar:manage', 'protection:read', 'protection:manage',
      'users:manage', 'backups:read');
    DELETE FROM novrsoc.permissions WHERE key IN ('soar:manage', 'protection:read', 'protection:manage', 'users:manage', 'backups:read');
    """)
