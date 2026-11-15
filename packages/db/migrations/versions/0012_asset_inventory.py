"""Unified asset inventory: ONE canonical identity per asset, with the source identifiers that reconcile to it.

assets               the canonical record (organization-owned; optional site; classification, criticality, owner)
asset_identifiers    every identifier any source reported (Wazuh agent id, hostname, FQDN, IP, MAC, domain, URL, cloud id),
                     unique per (organization, kind, value, site_key): one identifier can never belong to two assets.
                     site_key is the site id for addresses (10.0.0.5 at site A is not 10.0.0.5 at site B), '' otherwise.
asset_services       services and technologies seen on an asset (port/protocol, product, version), with their source
asset_events         discovery and change history (append-only for the runtime role: no UPDATE or DELETE grant)
asset_sync_runs      reconciliation runs per source (counts, outcome)
collectors           collector and discovery settings (configuration only: network discovery stays disabled until
                     separately authorized; a Wazuh sync reads the configured connector)
alerts.asset_id, vms_findings.asset_id link SIEM and VMS records to the canonical asset (ON DELETE SET NULL of the id
only, so the organization column is never nulled).

Also adds the consolidation permissions (app/authz/catalog.py CONSOLIDATION).

Revision ID: 0012_asset_inventory
Revises: 0011_account_security
"""
from alembic import op

revision = "0012_asset_inventory"
down_revision = "0011_account_security"
branch_labels = None
depends_on = None

PERMS = [("assets:read", "Read the unified asset inventory"),
         ("assets:manage", "Create, classify, merge and retire assets; manage collectors and discovery settings"),
         ("sla:manage", "Manage SLA policies and run SLA escalation"),
         ("chat:use", "Use NovrChat (read-only, tenant-scoped questions)"),
         ("recovery:read", "Read recovery plans and recovery requests"),
         ("recovery:manage", "Manage recovery plans and decide recovery requests"),
         ("billing:manage", "Manage billing plans and organization subscriptions (platform)"),
         ("exports:manage", "Create authorized data exports of an organization's records"),
         ("platform:monitor", "Read platform analytics and platform health (platform)")]
GRANTS = {"assets:read": ["super_admin", "soc_manager", "analyst", "executive"],
          "assets:manage": ["super_admin", "soc_manager", "analyst"],
          "sla:manage": ["super_admin", "soc_manager"],
          "chat:use": ["super_admin", "soc_manager", "analyst", "executive"],
          "recovery:read": ["super_admin", "soc_manager", "analyst", "executive"],
          "recovery:manage": ["super_admin", "soc_manager"],
          "billing:manage": ["super_admin"],
          "exports:manage": ["super_admin", "soc_manager"],
          "platform:monitor": ["super_admin"]}
TENANT = ["assets", "asset_identifiers", "asset_services", "asset_events", "asset_sync_runs", "collectors"]


def _q(s):
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " + ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMS))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for p, rs in GRANTS.items() for r in rs))
    op.execute("""
    CREATE TABLE novrsoc.assets (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      site_id uuid,
      kind text NOT NULL CHECK (kind IN ('host', 'domain', 'web_application', 'network_device', 'cloud_resource')),
      display_name text NOT NULL CHECK (length(display_name) BETWEEN 1 AND 200),
      hostname citext, fqdn citext, primary_ip inet, mac_address macaddr,
      os_platform text, os_name text, os_version text,
      classification text NOT NULL DEFAULT 'unclassified'
        CHECK (classification IN ('server', 'workstation', 'network', 'domain', 'web', 'cloud', 'iot', 'unclassified')),
      criticality text NOT NULL DEFAULT 'medium' CHECK (criticality IN ('low', 'medium', 'high', 'critical')),
      exposure text NOT NULL DEFAULT 'unknown' CHECK (exposure IN ('internet_facing', 'internal', 'unknown')),
      owner text NOT NULL DEFAULT '' CHECK (length(owner) <= 200),
      tags text[] NOT NULL DEFAULT '{}',
      status text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'retired')),
      merged_into uuid,
      first_seen_at timestamptz NOT NULL DEFAULT now(),
      last_seen_at timestamptz NOT NULL DEFAULT now(),
      created_at timestamptz NOT NULL DEFAULT now(),
      updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (id, org_id),
      FOREIGN KEY (site_id, org_id) REFERENCES novrsoc.sites (id, org_id) ON DELETE SET NULL (site_id),
      FOREIGN KEY (merged_into, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE SET NULL (merged_into),
      CHECK (merged_into IS NULL OR status = 'retired'));
    CREATE INDEX assets_org_name ON novrsoc.assets (org_id, lower(display_name));
    CREATE TABLE novrsoc.asset_identifiers (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      asset_id uuid NOT NULL,
      kind text NOT NULL CHECK (kind IN ('wazuh_agent', 'hostname', 'fqdn', 'ip', 'mac', 'domain', 'url', 'cloud_id', 'serial')),
      value text NOT NULL CHECK (length(value) BETWEEN 1 AND 300),
      site_key text NOT NULL DEFAULT '',
      sources text[] NOT NULL CHECK (cardinality(sources) > 0),
      first_seen_at timestamptz NOT NULL DEFAULT now(),
      last_seen_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, kind, value, site_key),
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE CASCADE);
    CREATE INDEX asset_identifiers_asset ON novrsoc.asset_identifiers (asset_id);
    CREATE TABLE novrsoc.asset_services (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      asset_id uuid NOT NULL,
      port integer NOT NULL DEFAULT 0 CHECK (port BETWEEN 0 AND 65535),
      protocol text NOT NULL DEFAULT '' CHECK (protocol IN ('', 'tcp', 'udp')),
      name text NOT NULL DEFAULT '' CHECK (length(name) <= 120),
      product text NOT NULL DEFAULT '' CHECK (length(product) <= 200),
      version text NOT NULL DEFAULT '' CHECK (length(version) <= 100),
      source text NOT NULL,
      first_seen_at timestamptz NOT NULL DEFAULT now(),
      last_seen_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (asset_id, port, protocol, product),
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE CASCADE);
    CREATE TABLE novrsoc.asset_events (
      id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      asset_id uuid NOT NULL,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      kind text NOT NULL CHECK (kind IN ('discovered', 'identifier_added', 'identifier_conflict', 'updated', 'service_seen',
                                         'merged', 'retired', 'reclassified')),
      source text NOT NULL,
      actor_label text NOT NULL DEFAULT '',
      details jsonb NOT NULL DEFAULT '{}'::jsonb,
      FOREIGN KEY (asset_id, org_id) REFERENCES novrsoc.assets (id, org_id) ON DELETE CASCADE);
    CREATE INDEX asset_events_asset ON novrsoc.asset_events (asset_id, id DESC);
    CREATE TABLE novrsoc.asset_sync_runs (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      source text NOT NULL,
      source_state text NOT NULL,
      started_at timestamptz NOT NULL DEFAULT now(),
      finished_at timestamptz,
      outcome text NOT NULL CHECK (outcome IN ('completed', 'source_unconfigured', 'source_unavailable', 'failed')),
      observed integer NOT NULL DEFAULT 0, created integer NOT NULL DEFAULT 0, updated integer NOT NULL DEFAULT 0,
      conflicts integer NOT NULL DEFAULT 0,
      detail text NOT NULL DEFAULT '',
      requested_label text NOT NULL DEFAULT '');
    CREATE TABLE novrsoc.collectors (
      id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      site_id uuid,
      name text NOT NULL CHECK (length(name) BETWEEN 2 AND 120),
      kind text NOT NULL CHECK (kind IN ('wazuh_sync', 'network_discovery', 'cloud_inventory', 'manual_import')),
      enabled boolean NOT NULL DEFAULT false,
      interval_minutes integer NOT NULL DEFAULT 1440 CHECK (interval_minutes BETWEEN 15 AND 10080),
      settings jsonb NOT NULL DEFAULT '{}'::jsonb,
      authorization_reference text NOT NULL DEFAULT '' CHECK (length(authorization_reference) <= 200),
      service_identity_id uuid REFERENCES novrsoc.service_identities(id) ON DELETE SET NULL,
      last_run_at timestamptz, last_outcome text,
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name),
      FOREIGN KEY (site_id, org_id) REFERENCES novrsoc.sites (id, org_id) ON DELETE SET NULL (site_id),
      -- Active network discovery is never enabled without a recorded authorization.
      CHECK (kind <> 'network_discovery' OR NOT enabled OR length(authorization_reference) >= 3));
    ALTER TABLE novrsoc.alerts ADD COLUMN asset_id uuid;
    ALTER TABLE novrsoc.alerts ADD CONSTRAINT alerts_asset_fk FOREIGN KEY (asset_id, org_id)
      REFERENCES novrsoc.assets (id, org_id) ON DELETE SET NULL (asset_id);
    CREATE INDEX alerts_asset ON novrsoc.alerts (asset_id) WHERE asset_id IS NOT NULL;
    ALTER TABLE novrsoc.vms_findings ADD COLUMN asset_id uuid;
    ALTER TABLE novrsoc.vms_findings ADD CONSTRAINT vms_findings_asset_fk FOREIGN KEY (asset_id, org_id)
      REFERENCES novrsoc.assets (id, org_id) ON DELETE SET NULL (asset_id);
    CREATE INDEX vms_findings_asset ON novrsoc.vms_findings (asset_id) WHERE asset_id IS NOT NULL;
    """)
    for t in TENANT:
        op.execute(f"""
        ALTER TABLE novrsoc.{t} ENABLE ROW LEVEL SECURITY;
        CREATE POLICY {t}_tenant ON novrsoc.{t} FOR ALL USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());""")
    op.execute("""
    GRANT SELECT, INSERT, UPDATE ON novrsoc.assets, novrsoc.asset_identifiers, novrsoc.asset_services, novrsoc.asset_sync_runs,
                                    novrsoc.collectors TO novrsoc_app;
    GRANT DELETE ON novrsoc.collectors TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.asset_events TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    ALTER TABLE novrsoc.vms_findings DROP CONSTRAINT IF EXISTS vms_findings_asset_fk;
    ALTER TABLE novrsoc.vms_findings DROP COLUMN IF EXISTS asset_id;
    ALTER TABLE novrsoc.alerts DROP CONSTRAINT IF EXISTS alerts_asset_fk;
    ALTER TABLE novrsoc.alerts DROP COLUMN IF EXISTS asset_id;
    DROP TABLE IF EXISTS novrsoc.collectors, novrsoc.asset_sync_runs, novrsoc.asset_events, novrsoc.asset_services,
      novrsoc.asset_identifiers, novrsoc.assets;
    """)
    keys = ", ".join(_q(k) for k, _ in PERMS)
    op.execute(f"DELETE FROM novrsoc.role_permissions WHERE permission_key IN ({keys}); DELETE FROM novrsoc.permissions WHERE key IN ({keys});")
