"""Endpoint-management foundation: permissions and the organisation <-> Wazuh agent-group map.

One Wazuh deployment serves many organisations. Each organisation owns the Wazuh agent groups that belong to
it; this table is the ONLY source of an organisation's Wazuh scope (OrgScope), and of the organisation an
ingested alert belongs to (via novrsoc.org_for_agent_groups, used by the forwarder ingest path).

  endpoints:read    read endpoint inventory, details, vulnerability and SCA summaries
                    (super_admin, soc_manager, analyst, executive)
  endpoints:manage  map Wazuh agent groups to the organisation (super_admin, soc_manager)

Revision ID: 0003_endpoint_foundation
Revises: 0002_nhai_gateway_permissions
"""
from alembic import op

revision = "0003_endpoint_foundation"
down_revision = "0002_nhai_gateway_permissions"
branch_labels = None
depends_on = None

PERMS = [("endpoints:read", "Read endpoint inventory, details, vulnerability and SCA summaries"),
         ("endpoints:manage", "Map Wazuh agent groups to the organization")]
GRANTS = {"endpoints:read": ["super_admin", "soc_manager", "analyst", "executive"],
          "endpoints:manage": ["super_admin", "soc_manager"]}


def _q(s):
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " + ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMS))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for p, rs in GRANTS.items() for r in rs))
    op.execute("""
    CREATE TABLE novrsoc.wazuh_group_mappings (
      id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id     uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      group_name text NOT NULL UNIQUE CHECK (group_name ~ '^[A-Za-z0-9_.-]{1,128}$'),
      created_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE INDEX wazuh_group_mappings_org ON novrsoc.wazuh_group_mappings (org_id);
    ALTER TABLE novrsoc.wazuh_group_mappings ENABLE ROW LEVEL SECURITY;
    CREATE POLICY wazuh_group_mappings_tenant ON novrsoc.wazuh_group_mappings FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, DELETE ON novrsoc.wazuh_group_mappings TO novrsoc_app;

    -- Ingest path: which organisation owns an alert, from the agent's groups. Exactly one organisation must
    -- match; none or several -> org_id NULL (the alert is quarantined with the reason, never guessed).
    CREATE FUNCTION novrsoc.org_for_agent_groups(p_groups text[]) RETURNS TABLE (org_id uuid, matched_orgs integer)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT CASE WHEN count(DISTINCT m.org_id) = 1 THEN min(m.org_id::text)::uuid END, count(DISTINCT m.org_id)::integer
          FROM novrsoc.wazuh_group_mappings m WHERE m.group_name = ANY(p_groups) $$;
    REVOKE ALL ON FUNCTION novrsoc.org_for_agent_groups(text[]) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.org_for_agent_groups(text[]) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("DROP FUNCTION IF EXISTS novrsoc.org_for_agent_groups(text[]); DROP TABLE IF EXISTS novrsoc.wazuh_group_mappings;")
    keys = ", ".join(_q(k) for k, _ in PERMS)
    op.execute(f"DELETE FROM novrsoc.role_permissions WHERE permission_key IN ({keys}); DELETE FROM novrsoc.permissions WHERE key IN ({keys});")
