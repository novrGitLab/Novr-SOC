"""Organization management and explicit attribution of syslog and agentless sources.

  * organizations: an `archived` status (data kept, no sign-in, no telemetry), profile fields (contact, timezone,
    notes), the reason of the last status change, updated_at / archived_at.
  * log_sources: syslog devices (firewalls, routers, switches, Linux servers, ...) and agentless targets that reach
    NovrSOC through the Wazuh manager (agent 000). Each is registered to exactly ONE organization with an
    authorization reference; the match value (the sender IP that wazuh-remoted records in `location`, or the
    agentless host configured on the manager) is unique across ALL organizations among sources that are not
    retired, so an event can never be attributed to two tenants. Reassignment retires the record in the old
    organization (its history and alert links stay there) and registers a new one in the new organization.
  * alerts.log_source_id links an alert to the source it came from (same organization: composite key).
  * alert_quarantine: three more reasons. Manager-originated events are never assigned to a tenant by default:
    unknown_log_source, log_source_disabled, manager_local_event (the manager's own logs and modules).
  * novrsoc.log_source_for(kind, value): the ingest lookup (SECURITY DEFINER, like org_for_agent_groups).
  * novrsoc.org_onboarding(org): onboarding steps computed from the organization's real configuration (one
    definition for the onboarding panel and the directory). novrsoc.org_directory(): per-organization status,
    counts and integration state for platform administrators (guarded like platform_analytics()).

Revision ID: 0017_org_management_log_sources
Revises: 0016_nhai_worker_role
"""
from alembic import op

revision = "0017_org_management_log_sources"
down_revision = "0016_nhai_worker_role"
branch_labels = None
depends_on = None

QUARANTINE_OLD = "('no_organization_for_groups', 'ambiguous_organization')"
QUARANTINE_NEW = ("('no_organization_for_groups', 'ambiguous_organization', 'unknown_log_source', 'log_source_disabled', "
                  "'manager_local_event')")


def upgrade() -> None:
    op.execute(f"""
    ALTER TABLE novrsoc.organizations DROP CONSTRAINT organizations_status_check;
    ALTER TABLE novrsoc.organizations ADD CONSTRAINT organizations_status_check CHECK (status IN ('active', 'suspended', 'archived'));
    ALTER TABLE novrsoc.organizations
      ADD COLUMN contact_name  text NOT NULL DEFAULT '' CHECK (length(contact_name) <= 200),
      ADD COLUMN contact_email text NOT NULL DEFAULT '' CHECK (contact_email = '' OR position('@' in contact_email) > 1),
      ADD COLUMN timezone      text NOT NULL DEFAULT 'UTC' CHECK (timezone ~ '^[A-Za-z_]+(/[A-Za-z0-9_+-]+)*$' AND length(timezone) <= 64),
      ADD COLUMN notes         text NOT NULL DEFAULT '' CHECK (length(notes) <= 4000),
      ADD COLUMN status_reason text NOT NULL DEFAULT '' CHECK (length(status_reason) <= 500),
      ADD COLUMN updated_at    timestamptz NOT NULL DEFAULT now(),
      ADD COLUMN archived_at   timestamptz;

    CREATE TABLE novrsoc.log_sources (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name          text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
      kind          text NOT NULL CHECK (kind IN ('syslog', 'agentless')),
      -- syslog: the sender address wazuh-remoted records in the alert's `location`; agentless: the host configured
      -- in the manager's <agentless> block. match_value is the normalized form used at ingest.
      source_ip     inet,
      host          text NOT NULL DEFAULT '' CHECK (length(host) <= 253),
      match_value   text NOT NULL CHECK (length(match_value) BETWEEN 1 AND 253),
      device_type   text NOT NULL CHECK (device_type IN ('firewall', 'router', 'switch', 'linux_server', 'windows_server',
                                                         'network_appliance', 'storage', 'other')),
      vendor        text NOT NULL DEFAULT '' CHECK (length(vendor) <= 120),
      protocol      text NOT NULL CHECK (protocol IN ('udp', 'tcp', 'tls', 'ssh')),
      port          integer CHECK (port IS NULL OR port BETWEEN 1 AND 65535),
      site_id       uuid,
      network       cidr,
      enabled       boolean NOT NULL DEFAULT true,
      authorization_reference text NOT NULL CHECK (length(authorization_reference) BETWEEN 3 AND 200),
      notes         text NOT NULL DEFAULT '' CHECK (length(notes) <= 2000),
      asset_id      uuid,
      event_count   bigint NOT NULL DEFAULT 0 CHECK (event_count >= 0),
      last_event_at timestamptz,
      retired_at    timestamptz,
      retired_reason text NOT NULL DEFAULT '' CHECK (length(retired_reason) <= 500),
      created_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at    timestamptz NOT NULL DEFAULT now(),
      updated_at    timestamptz NOT NULL DEFAULT now(),
      UNIQUE (id, org_id),
      FOREIGN KEY (site_id, org_id) REFERENCES novrsoc.sites (id, org_id) ON DELETE SET NULL (site_id),
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE SET NULL (asset_id),
      CHECK ((kind = 'syslog') = (source_ip IS NOT NULL)),
      CHECK (kind <> 'syslog' OR match_value = host(source_ip)),
      CHECK (kind <> 'agentless' OR (host <> '' AND match_value = lower(host) AND protocol = 'ssh')),
      CHECK (kind <> 'syslog' OR protocol IN ('udp', 'tcp', 'tls')),
      CHECK (network IS NULL OR source_ip IS NULL OR source_ip <<= network),
      CHECK (retired_at IS NULL OR NOT enabled)
    );
    -- One live registration per source across ALL organizations: no event can match two tenants.
    CREATE UNIQUE INDEX log_sources_one_live ON novrsoc.log_sources (kind, match_value) WHERE retired_at IS NULL;
    CREATE UNIQUE INDEX log_sources_name ON novrsoc.log_sources (org_id, lower(name)) WHERE retired_at IS NULL;
    CREATE INDEX log_sources_org ON novrsoc.log_sources (org_id);
    ALTER TABLE novrsoc.log_sources ENABLE ROW LEVEL SECURITY;
    CREATE POLICY log_sources_tenant ON novrsoc.log_sources FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.log_sources TO novrsoc_app;

    ALTER TABLE novrsoc.alerts ADD COLUMN log_source_id uuid;
    ALTER TABLE novrsoc.alerts ADD CONSTRAINT alerts_log_source_fk FOREIGN KEY (log_source_id, org_id)
      REFERENCES novrsoc.log_sources (id, org_id) ON DELETE SET NULL (log_source_id);
    CREATE INDEX alerts_log_source ON novrsoc.alerts (org_id, log_source_id, observed_at DESC) WHERE log_source_id IS NOT NULL;

    ALTER TABLE novrsoc.alert_quarantine DROP CONSTRAINT alert_quarantine_reason_check;
    ALTER TABLE novrsoc.alert_quarantine ADD CONSTRAINT alert_quarantine_reason_check CHECK (reason IN {QUARANTINE_NEW});

    -- Ingest lookup: the live registration for a source, whatever the caller's organization context.
    CREATE FUNCTION novrsoc.log_source_for(p_kind text, p_value text)
      RETURNS TABLE (id uuid, org_id uuid, enabled boolean, asset_id uuid, org_status text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT s.id, s.org_id, s.enabled, s.asset_id, o.status FROM novrsoc.log_sources s
          JOIN novrsoc.organizations o ON o.id = s.org_id
         WHERE s.kind = p_kind AND s.match_value = p_value AND s.retired_at IS NULL $$;
    REVOKE ALL ON FUNCTION novrsoc.log_source_for(text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.log_source_for(text, text) TO novrsoc_app;

    -- Onboarding from real configuration. The caller's own organization, or any organization for a platform admin.
    CREATE FUNCTION novrsoc.org_onboarding(p_org uuid) RETURNS jsonb
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF NOT (novrsoc.app_platform_admin() OR p_org = novrsoc.app_org()) THEN
          RAISE EXCEPTION 'organization context required';
        END IF;
        RETURN (SELECT jsonb_build_object(
          'organization_created', true,
          'profile_completed', o.contact_name <> '' AND o.contact_email <> '',
          'users_added', EXISTS (SELECT 1 FROM memberships m WHERE m.org_id = o.id),
          'wazuh_groups_mapped', EXISTS (SELECT 1 FROM wazuh_group_mappings g WHERE g.org_id = o.id),
          'log_sources_registered', EXISTS (SELECT 1 FROM log_sources s WHERE s.org_id = o.id AND s.retired_at IS NULL),
          'telemetry_received', EXISTS (SELECT 1 FROM alerts a WHERE a.org_id = o.id),
          'sites_defined', EXISTS (SELECT 1 FROM sites s WHERE s.org_id = o.id),
          'assets_inventoried', EXISTS (SELECT 1 FROM assets a WHERE a.org_id = o.id),
          'sla_policies_set', EXISTS (SELECT 1 FROM sla_policies p WHERE p.org_id = o.id),
          'response_policy_set', EXISTS (SELECT 1 FROM soar_policies p WHERE p.org_id = o.id),
          'subscription_set', EXISTS (SELECT 1 FROM org_subscriptions s WHERE s.org_id = o.id))
          FROM organizations o WHERE o.id = p_org);
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.org_onboarding(uuid) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.org_onboarding(uuid) TO novrsoc_app;

    CREATE FUNCTION novrsoc.org_directory()
      RETURNS TABLE (org_id uuid, slug text, name text, kind text, status text, status_reason text, contact_name text,
                     contact_email text, timezone text, created_at timestamptz, updated_at timestamptz, users bigint,
                     assets bigint, wazuh_agents bigint, wazuh_groups bigint, log_sources bigint, log_sources_disabled bigint,
                     log_sources_receiving bigint, log_sources_never bigint, service_identities bigint, sites bigint,
                     alerts_7d bigint, last_alert_at timestamptz, open_cases bigint, onboarding jsonb)
      LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        RETURN QUERY
        SELECT o.id, o.slug::text, o.name, o.kind, o.status, o.status_reason, o.contact_name, o.contact_email, o.timezone,
               o.created_at, o.updated_at,
               (SELECT count(*) FROM memberships m WHERE m.org_id = o.id),
               (SELECT count(*) FROM assets a WHERE a.org_id = o.id AND a.status = 'active'),
               (SELECT count(DISTINCT i.asset_id) FROM asset_identifiers i JOIN assets a ON a.id = i.asset_id
                 WHERE i.org_id = o.id AND i.kind = 'wazuh_agent' AND a.status = 'active'),
               (SELECT count(*) FROM wazuh_group_mappings g WHERE g.org_id = o.id),
               (SELECT count(*) FROM log_sources s WHERE s.org_id = o.id AND s.retired_at IS NULL),
               (SELECT count(*) FROM log_sources s WHERE s.org_id = o.id AND s.retired_at IS NULL AND NOT s.enabled),
               (SELECT count(*) FROM log_sources s WHERE s.org_id = o.id AND s.retired_at IS NULL AND s.enabled
                  AND s.last_event_at > now() - interval '1 hour'),
               (SELECT count(*) FROM log_sources s WHERE s.org_id = o.id AND s.retired_at IS NULL AND s.enabled AND s.last_event_at IS NULL),
               (SELECT count(*) FROM service_identities i WHERE i.org_id = o.id AND i.status = 'active'),
               (SELECT count(*) FROM sites s WHERE s.org_id = o.id),
               (SELECT count(*) FROM alerts a WHERE a.org_id = o.id AND a.observed_at > now() - interval '7 days'),
               (SELECT max(a.observed_at) FROM alerts a WHERE a.org_id = o.id),
               (SELECT count(*) FROM cases c WHERE c.org_id = o.id AND c.status IN ('open', 'in_progress')),
               novrsoc.org_onboarding(o.id)
          FROM organizations o
         ORDER BY o.kind DESC, o.name;
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.org_directory() FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.org_directory() TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute(f"""
    DROP FUNCTION IF EXISTS novrsoc.org_directory();
    DROP FUNCTION IF EXISTS novrsoc.org_onboarding(uuid);
    DROP FUNCTION IF EXISTS novrsoc.log_source_for(text, text);
    DELETE FROM novrsoc.alert_quarantine WHERE reason NOT IN {QUARANTINE_OLD};
    ALTER TABLE novrsoc.alert_quarantine DROP CONSTRAINT alert_quarantine_reason_check;
    ALTER TABLE novrsoc.alert_quarantine ADD CONSTRAINT alert_quarantine_reason_check CHECK (reason IN {QUARANTINE_OLD});
    DROP INDEX IF EXISTS novrsoc.alerts_log_source;
    ALTER TABLE novrsoc.alerts DROP CONSTRAINT IF EXISTS alerts_log_source_fk;
    ALTER TABLE novrsoc.alerts DROP COLUMN IF EXISTS log_source_id;
    DROP TABLE IF EXISTS novrsoc.log_sources;
    UPDATE novrsoc.organizations SET status = 'suspended' WHERE status = 'archived';
    ALTER TABLE novrsoc.organizations DROP CONSTRAINT organizations_status_check;
    ALTER TABLE novrsoc.organizations ADD CONSTRAINT organizations_status_check CHECK (status IN ('active', 'suspended'));
    ALTER TABLE novrsoc.organizations DROP COLUMN archived_at, DROP COLUMN updated_at, DROP COLUMN status_reason,
      DROP COLUMN notes, DROP COLUMN timezone, DROP COLUMN contact_email, DROP COLUMN contact_name;
    """)
