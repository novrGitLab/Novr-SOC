"""Administration, exports and NovrChat.

billing_plans        plan catalogue (platform). Nothing is seeded: plans are created by a platform administrator.
org_subscriptions    one subscription per organization (platform administrators write; the organization reads its own).
                     No payment provider exists: status changes are administrative records, never payments.
data_exports         authorized exports of one organization's records (justification required, checksum, expiry,
                     download count). The content is stored with the export so a download is exactly what was approved.
teams, team_members  analyst teams inside an organization
chat_conversations, chat_messages   NovrChat (own conversations only: RLS on organization AND user)
platform_analytics() / platform_health()   SECURITY DEFINER read-only aggregates for platform administrators; they
                     refuse any other caller. They return counts and component states, never tenant records.

Revision ID: 0015_admin_exports_chat
Revises: 0014_intel_cnii_continuity
"""
from alembic import op

revision = "0015_admin_exports_chat"
down_revision = "0014_intel_cnii_continuity"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    CREATE TABLE novrsoc.billing_plans (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      code text NOT NULL UNIQUE CHECK (code ~ '^[a-z0-9][a-z0-9-]{1,39}$'),
      name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
      description text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
      price_minor bigint NOT NULL CHECK (price_minor >= 0),
      currency text NOT NULL CHECK (currency ~ '^[A-Z]{3}$'),
      billing_interval text NOT NULL CHECK (billing_interval IN ('monthly', 'annual')),
      max_assets integer CHECK (max_assets > 0),
      max_users integer CHECK (max_users > 0),
      features text[] NOT NULL DEFAULT '{}',
      active boolean NOT NULL DEFAULT true,
      created_at timestamptz NOT NULL DEFAULT now());
    ALTER TABLE novrsoc.billing_plans ENABLE ROW LEVEL SECURITY;
    CREATE POLICY billing_plans_read ON novrsoc.billing_plans FOR SELECT USING (true);
    CREATE POLICY billing_plans_admin ON novrsoc.billing_plans FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());
    CREATE TABLE novrsoc.org_subscriptions (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL UNIQUE REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      plan_id uuid NOT NULL REFERENCES novrsoc.billing_plans(id),
      status text NOT NULL CHECK (status IN ('trial', 'active', 'past_due', 'cancelled')),
      started_at timestamptz NOT NULL DEFAULT now(),
      renews_at timestamptz,
      notes text NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
      updated_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      updated_at timestamptz NOT NULL DEFAULT now());
    ALTER TABLE novrsoc.org_subscriptions ENABLE ROW LEVEL SECURITY;
    CREATE POLICY org_subscriptions_read ON novrsoc.org_subscriptions FOR SELECT
      USING (org_id = novrsoc.app_org() OR novrsoc.app_platform_admin());
    CREATE POLICY org_subscriptions_admin ON novrsoc.org_subscriptions FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.billing_plans, novrsoc.org_subscriptions TO novrsoc_app;

    CREATE TABLE novrsoc.data_exports (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      dataset text NOT NULL CHECK (dataset IN ('alerts', 'cases', 'vms_findings', 'assets', 'audit_events', 'ti_indicators')),
      format text NOT NULL CHECK (format IN ('csv', 'json')),
      period_start timestamptz NOT NULL, period_end timestamptz NOT NULL,
      justification text NOT NULL CHECK (length(justification) BETWEEN 10 AND 1000),
      recipient text NOT NULL CHECK (length(recipient) BETWEEN 2 AND 200),
      row_count integer NOT NULL CHECK (row_count >= 0),
      truncated boolean NOT NULL DEFAULT false,
      content text NOT NULL,
      sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
      requested_by uuid NOT NULL REFERENCES novrsoc.users(id), requested_label text NOT NULL DEFAULT '',
      created_at timestamptz NOT NULL DEFAULT now(),
      expires_at timestamptz NOT NULL,
      downloads integer NOT NULL DEFAULT 0,
      revoked_at timestamptz,
      CHECK (period_end > period_start), CHECK (expires_at > created_at));
    CREATE TABLE novrsoc.teams (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
      description text NOT NULL DEFAULT '' CHECK (length(description) <= 1000),
      created_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.team_members (
      team_id uuid NOT NULL,
      org_id uuid NOT NULL,
      user_id uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      team_role text NOT NULL DEFAULT 'member' CHECK (team_role IN ('lead', 'member')),
      added_at timestamptz NOT NULL DEFAULT now(),
      PRIMARY KEY (team_id, user_id),
      FOREIGN KEY (team_id, org_id) REFERENCES novrsoc.teams (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.chat_conversations (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      user_id uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      title text NOT NULL CHECK (length(title) BETWEEN 1 AND 200),
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (id, org_id));
    CREATE TABLE novrsoc.chat_messages (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      conversation_id uuid NOT NULL,
      user_id uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      role text NOT NULL CHECK (role IN ('user', 'assistant')),
      content text NOT NULL CHECK (length(content) BETWEEN 1 AND 16000),
      tools jsonb NOT NULL DEFAULT '[]'::jsonb,
      citations jsonb NOT NULL DEFAULT '[]'::jsonb,
      state text NOT NULL DEFAULT 'complete' CHECK (state IN ('complete', 'refused')),
      nhai_job_id uuid,
      created_at timestamptz NOT NULL DEFAULT now(),
      FOREIGN KEY (conversation_id, org_id) REFERENCES novrsoc.chat_conversations (id, org_id) ON DELETE CASCADE);
    CREATE INDEX chat_messages_conv ON novrsoc.chat_messages (conversation_id, created_at);
    """)
    for t in ("data_exports", "teams", "team_members"):
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());""")
    for t in ("chat_conversations", "chat_messages"):
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_own ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user())
          WITH CHECK (org_id = novrsoc.app_org() AND user_id = novrsoc.app_user());""")
    op.execute("""
    GRANT SELECT, INSERT, UPDATE ON novrsoc.data_exports, novrsoc.teams, novrsoc.chat_conversations TO novrsoc_app;
    GRANT SELECT, INSERT, DELETE ON novrsoc.team_members TO novrsoc_app;
    GRANT DELETE ON novrsoc.teams, novrsoc.chat_conversations TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.chat_messages TO novrsoc_app;

    CREATE FUNCTION novrsoc.platform_analytics()
      RETURNS TABLE (org_id uuid, org_name text, kind text, status text, users bigint, assets bigint, alerts_7d bigint,
                     open_alerts bigint, open_cases bigint, open_findings bigint, critical_findings bigint,
                     last_alert_at timestamptz, plan_code text, subscription_status text)
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        RETURN QUERY
        SELECT o.id, o.name, o.kind, o.status,
               (SELECT count(*) FROM novrsoc.memberships m WHERE m.org_id = o.id),
               (SELECT count(*) FROM novrsoc.assets a WHERE a.org_id = o.id AND a.status = 'active'),
               (SELECT count(*) FROM novrsoc.alerts a WHERE a.org_id = o.id AND a.observed_at > now() - interval '7 days'),
               (SELECT count(*) FROM novrsoc.alerts a WHERE a.org_id = o.id AND a.status <> 'closed'),
               (SELECT count(*) FROM novrsoc.cases c WHERE c.org_id = o.id AND c.status IN ('open', 'in_progress')),
               (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.org_id = o.id AND f.status NOT IN ('verified', 'risk_accepted')),
               (SELECT count(*) FROM novrsoc.vms_findings f WHERE f.org_id = o.id AND f.severity = 'critical'
                  AND f.status NOT IN ('verified', 'risk_accepted')),
               (SELECT max(a.observed_at) FROM novrsoc.alerts a WHERE a.org_id = o.id),
               p.code, s.status
          FROM novrsoc.organizations o
          LEFT JOIN novrsoc.org_subscriptions s ON s.org_id = o.id
          LEFT JOIN novrsoc.billing_plans p ON p.id = s.plan_id
         ORDER BY o.kind DESC, o.name;
      END $$;

    CREATE FUNCTION novrsoc.platform_health() RETURNS jsonb
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE r jsonb;
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        SELECT jsonb_build_object(
          'database', jsonb_build_object(
             'size_bytes', pg_database_size(current_database()),
             'connections', (SELECT count(*) FROM pg_stat_activity WHERE datname = current_database()),
             'server_version', current_setting('server_version')),
          'vms_workers', coalesce((SELECT jsonb_agg(jsonb_build_object('name', s.name, 'organization', o.name,
                 'received_at', h.received_at, 'state', h.state, 'version', h.component_version,
                 'queue_depth', h.queue_depth) ORDER BY h.received_at DESC)
               FROM novrsoc.vms_worker_heartbeats h JOIN novrsoc.service_identities s ON s.id = h.identity_id
               JOIN novrsoc.organizations o ON o.id = h.org_id), '[]'::jsonb),
          'machine_identities', coalesce((SELECT jsonb_agg(jsonb_build_object('kind', kind, 'active', active, 'last_used_at', last_used))
               FROM (SELECT kind, count(*) FILTER (WHERE status = 'active') AS active, max(last_used_at) AS last_used
                       FROM novrsoc.service_identities GROUP BY kind) k), '[]'::jsonb),
          'nhai_queue', jsonb_build_object(
             'queued', (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status = 'queued'),
             'running', (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status = 'running'),
             'failed_24h', (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status IN ('failed', 'timed_out') AND finished_at > now() - interval '24 hours'),
             'succeeded_24h', (SELECT count(*) FROM novrsoc.nhai_jobs WHERE status = 'succeeded' AND finished_at > now() - interval '24 hours'),
             'oldest_queued_at', (SELECT min(queued_at) FROM novrsoc.nhai_jobs WHERE status = 'queued')),
          'soar', jsonb_build_object(
             'dispatched_without_receipt', (SELECT count(*) FROM novrsoc.soar_steps WHERE state = 'dispatched'),
             'awaiting_approval', (SELECT count(*) FROM novrsoc.soar_steps WHERE state = 'awaiting_approval'),
             'failed_24h', (SELECT count(*) FROM novrsoc.soar_steps WHERE state = 'failed' AND updated_at > now() - interval '24 hours'),
             'emergency_stops', (SELECT count(*) FROM novrsoc.soar_policies WHERE emergency_stop)),
          'vms_jobs', jsonb_build_object(
             'queued', (SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'queued'),
             'running', (SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'running'),
             'failed_24h', (SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state = 'failed' AND finished_at > now() - interval '24 hours')),
          'ingest', jsonb_build_object(
             'last_batch_at', (SELECT max(received_at) FROM novrsoc.ingest_batches),
             'batches_24h', (SELECT count(*) FROM novrsoc.ingest_batches WHERE received_at > now() - interval '24 hours'),
             'quarantined_24h', (SELECT count(*) FROM novrsoc.alert_quarantine WHERE received_at > now() - interval '24 hours'),
             'last_feed_run_at', (SELECT max(received_at) FROM novrsoc.ti_feed_runs)),
          'backups', jsonb_build_object(
             'last_succeeded_at', (SELECT max(finished_at) FROM novrsoc.backup_runs WHERE status = 'succeeded'),
             'last_failed_at', (SELECT max(finished_at) FROM novrsoc.backup_runs WHERE status = 'failed'),
             'last_drill_at', (SELECT max(finished_at) FROM novrsoc.restore_drills),
             'last_drill_status', (SELECT status FROM novrsoc.restore_drills ORDER BY finished_at DESC LIMIT 1)),
          'failures_24h', coalesce((SELECT jsonb_agg(jsonb_build_object('action', action, 'count', n) ORDER BY n DESC)
               FROM (SELECT action, count(*) AS n FROM novrsoc.audit_events
                      WHERE outcome = 'failure' AND occurred_at > now() - interval '24 hours' GROUP BY action LIMIT 20) f), '[]'::jsonb)
        ) INTO r;
        RETURN r;
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.platform_analytics(), novrsoc.platform_health() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.platform_analytics(), novrsoc.platform_health() TO novrsoc_app;

    -- background components without a machine identity (the jobs worker, the NHAI worker) report liveness here
    CREATE TABLE novrsoc.platform_heartbeats (
      component text PRIMARY KEY CHECK (component ~ '^[a-z_]{3,40}$'),
      instance text NOT NULL DEFAULT '' CHECK (length(instance) <= 120),
      state text NOT NULL CHECK (state IN ('ok', 'degraded', 'failing')),
      detail text NOT NULL DEFAULT '' CHECK (length(detail) <= 500),
      last_seen_at timestamptz NOT NULL DEFAULT now());
    ALTER TABLE novrsoc.platform_heartbeats ENABLE ROW LEVEL SECURITY;
    CREATE POLICY platform_heartbeats_platform ON novrsoc.platform_heartbeats FOR SELECT USING (novrsoc.app_platform_admin());
    GRANT SELECT ON novrsoc.platform_heartbeats TO novrsoc_app;
    CREATE FUNCTION novrsoc.platform_heartbeat(p_component text, p_instance text, p_state text, p_detail text) RETURNS void
      LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        INSERT INTO novrsoc.platform_heartbeats (component, instance, state, detail) VALUES (p_component, p_instance, p_state, p_detail)
        ON CONFLICT (component) DO UPDATE SET instance = EXCLUDED.instance, state = EXCLUDED.state, detail = EXCLUDED.detail,
          last_seen_at = now() $$;
    REVOKE ALL ON FUNCTION novrsoc.platform_heartbeat(text, text, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.platform_heartbeat(text, text, text, text) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.platform_heartbeat(text, text, text, text);
    DROP TABLE IF EXISTS novrsoc.platform_heartbeats;
    DROP FUNCTION IF EXISTS novrsoc.platform_health();
    DROP FUNCTION IF EXISTS novrsoc.platform_analytics();
    DROP TABLE IF EXISTS novrsoc.chat_messages, novrsoc.chat_conversations, novrsoc.team_members, novrsoc.teams,
      novrsoc.data_exports, novrsoc.org_subscriptions, novrsoc.billing_plans;
    """)
