"""V2 foundation schema: organisations, users, memberships, roles/permissions, sessions,
service identities, sites, audit events, CNII designations. Row-level security on tenant data.

THIS IS A NEW, MINIMAL V2 SCHEMA FOR LOCAL DEVELOPMENT. It is not reconstructed from the legacy
SQL and is NOT claimed to be compatible with the production database. The authoritative model
needs the approved schema-only dump (blocker B-02 / decision D-05).

Roles (created outside migrations, cluster-wide): novrsoc_owner owns these objects and runs
migrations; novrsoc_app is the API runtime role and is subject to RLS (it owns nothing and has
no BYPASSRLS). Pre-authentication lookups go through narrow SECURITY DEFINER functions, so the
app role never reads users, sessions or service identities wholesale.

Revision ID: 0001_foundation
Revises:
Create Date: 2026-11-13
"""
from alembic import op

revision = "0001_foundation"
down_revision = None
branch_labels = None
depends_on = None

APP = "novrsoc_app"

# Permission catalogue and role map. tests/test_catalog.py asserts this equals app/authz/catalog.py.
PERMISSIONS = [
    ("org:read", "Read the active organisation and the organisations one may act on"),
    ("sites:read", "Read the organisation's sites"),
    ("sites:manage", "Create and change the organisation's sites"),
    ("audit:read", "Read the organisation's audit events"),
    ("service_identities:manage", "Create, rotate and revoke machine identities"),
    ("alerts:read", "Read stored alerts"),
    ("alerts:triage", "Change a stored alert's status"),
    ("cases:read", "Read cases"),
    ("cases:write", "Create and update cases"),
    ("cases:close", "Close cases"),
    ("response:contain", "Request a containment action"),
    ("response:approve", "Approve or reject a containment action"),
    ("handover:write", "Write shift handovers"),
    ("vms:read", "Read assets and vulnerabilities"),
    ("vms:scan", "Request scans within approved scope"),
    ("vms:scope", "Approve scan scope"),
    ("vms:manage", "Manage findings and remediation"),
    ("intel:read", "Read threat insights"),
    ("intel:manage", "Review and manage threat insights"),
    ("cnii:read", "Read CNII data (also needs an explicit CNII designation)"),
    ("cnii:manage", "Manage CNII profiles (also needs an explicit CNII designation)"),
    ("cnii:sector", "Read across organisations by sector (also needs an explicit CNII designation)"),
    ("vms:client", "Client portal: own organisation's VMS view"),
    ("secops:client", "Client portal: own organisation's security monitoring view"),
]
_ALL = [p for p, _ in PERMISSIONS]
ROLES = [
    ("super_admin", True, "Platform administration; may act on any organisation (audited)"),
    ("soc_manager", True, "SOC management; own and assigned organisations"),
    ("analyst", True, "SOC analyst; own and assigned organisations; cannot approve containment"),
    ("executive", False, "Read-only executive view; reporting assignments are read-only"),
    ("portal_user", False, "Client portal account; own organisation only"),
]
ROLE_PERMISSIONS = {
    "super_admin": _ALL,
    "soc_manager": _ALL,
    "analyst": ["org:read", "sites:read", "alerts:read", "alerts:triage", "cases:read", "cases:write",
                "cases:close", "response:contain", "handover:write", "vms:read", "vms:scan", "vms:manage",
                "intel:read", "intel:manage", "cnii:read", "cnii:sector"],
    "executive": ["org:read", "sites:read", "vms:read", "intel:read", "cnii:read"],
    "portal_user": ["org:read", "vms:client", "secops:client"],
}


def _q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def upgrade() -> None:
    op.execute("CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public")

    # ---- session-context helpers (set per transaction by the API with set_config(..., true)) ----
    op.execute("""
    CREATE FUNCTION novrsoc.app_org() RETURNS uuid LANGUAGE sql STABLE AS
      $$ SELECT nullif(current_setting('app.org_id', true), '')::uuid $$;
    CREATE FUNCTION novrsoc.app_user() RETURNS uuid LANGUAGE sql STABLE AS
      $$ SELECT nullif(current_setting('app.user_id', true), '')::uuid $$;
    CREATE FUNCTION novrsoc.app_platform_admin() RETURNS boolean LANGUAGE sql STABLE AS
      $$ SELECT coalesce(current_setting('app.platform_admin', true), '') = 'on' $$;
    """)

    # ---- catalogues (global, read-only to the app) ----
    op.execute("""
    CREATE TABLE novrsoc.roles (
      key         text PRIMARY KEY CHECK (key ~ '^[a-z_]{3,40}$'),
      is_staff    boolean NOT NULL,
      description text NOT NULL
    );
    CREATE TABLE novrsoc.permissions (
      key         text PRIMARY KEY CHECK (key ~ '^[a-z_]+:[a-z_]+$'),
      description text NOT NULL
    );
    CREATE TABLE novrsoc.role_permissions (
      role_key       text NOT NULL REFERENCES novrsoc.roles(key) ON DELETE CASCADE,
      permission_key text NOT NULL REFERENCES novrsoc.permissions(key) ON DELETE CASCADE,
      PRIMARY KEY (role_key, permission_key)
    );
    """)
    op.execute("INSERT INTO novrsoc.permissions(key, description) VALUES " +
               ", ".join(f"({_q(k)}, {_q(d)})" for k, d in PERMISSIONS))
    op.execute("INSERT INTO novrsoc.roles(key, is_staff, description) VALUES " +
               ", ".join(f"({_q(k)}, {'true' if s else 'false'}, {_q(d)})" for k, s, d in ROLES))
    op.execute("INSERT INTO novrsoc.role_permissions(role_key, permission_key) VALUES " +
               ", ".join(f"({_q(r)}, {_q(p)})" for r, ps in ROLE_PERMISSIONS.items() for p in ps))

    # ---- identity and tenancy ----
    op.execute("""
    CREATE TABLE novrsoc.organizations (
      id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      slug       citext NOT NULL UNIQUE CHECK (slug ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
      name       text NOT NULL CHECK (length(name) BETWEEN 1 AND 200),
      kind       text NOT NULL CHECK (kind IN ('platform', 'client')),
      status     text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
      created_at timestamptz NOT NULL DEFAULT now()
    );
    CREATE UNIQUE INDEX organizations_single_platform ON novrsoc.organizations ((kind)) WHERE kind = 'platform';

    CREATE TABLE novrsoc.users (
      id                 uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      email              citext NOT NULL UNIQUE CHECK (position('@' in email) > 1),
      display_name       text NOT NULL DEFAULT '',
      password_hash      text,
      status             text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
      failed_login_count integer NOT NULL DEFAULT 0 CHECK (failed_login_count >= 0),
      locked_until       timestamptz,
      last_login_at      timestamptz,
      created_at         timestamptz NOT NULL DEFAULT now()
    );

    CREATE TABLE novrsoc.memberships (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id      uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      org_id       uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      role_key     text NOT NULL REFERENCES novrsoc.roles(key),
      access_scope text NOT NULL CHECK (access_scope IN ('home', 'operations', 'reporting')),
      created_at   timestamptz NOT NULL DEFAULT now(),
      UNIQUE (user_id, org_id)
    );
    CREATE UNIQUE INDEX memberships_one_home ON novrsoc.memberships (user_id) WHERE access_scope = 'home';
    CREATE INDEX memberships_org ON novrsoc.memberships (org_id);

    CREATE TABLE novrsoc.sessions (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id      uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
      csrf_hash    bytea NOT NULL CHECK (length(csrf_hash) = 32),
      created_at   timestamptz NOT NULL DEFAULT now(),
      expires_at   timestamptz NOT NULL,
      revoked_at   timestamptz
    );
    CREATE INDEX sessions_user ON novrsoc.sessions (user_id);
    """)

    # ---- tenant-owned records ----
    op.execute("""
    CREATE TABLE novrsoc.sites (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      name          text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
      description   text NOT NULL DEFAULT '' CHECK (length(description) <= 2000),
      network_cidrs cidr[] NOT NULL DEFAULT '{}',
      created_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at    timestamptz NOT NULL DEFAULT now(),
      UNIQUE (org_id, name),
      UNIQUE (id, org_id)
    );

    CREATE TABLE novrsoc.service_identities (
      id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id       uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      site_id      uuid,
      kind         text NOT NULL CHECK (kind IN ('collector', 'vms_worker', 'forwarder', 'email_gateway', 'backup_agent')),
      name         text NOT NULL CHECK (length(name) BETWEEN 1 AND 120),
      secret_hash  bytea NOT NULL CHECK (length(secret_hash) = 32),
      scopes       text[] NOT NULL DEFAULT '{}',
      status       text NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'revoked')),
      created_by   uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_at   timestamptz NOT NULL DEFAULT now(),
      expires_at   timestamptz,
      revoked_at   timestamptz,
      last_used_at timestamptz,
      -- A site binding must name a site of the SAME organisation.
      FOREIGN KEY (site_id, org_id) REFERENCES novrsoc.sites(id, org_id) ON DELETE CASCADE,
      CHECK ((status = 'revoked') = (revoked_at IS NOT NULL))
    );
    CREATE INDEX service_identities_org ON novrsoc.service_identities (org_id);

    CREATE TABLE novrsoc.audit_events (
      id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
      occurred_at timestamptz NOT NULL DEFAULT now(),
      org_id      uuid REFERENCES novrsoc.organizations(id) ON DELETE SET NULL,
      actor_type  text NOT NULL CHECK (actor_type IN ('user', 'service', 'system')),
      actor_id    uuid,
      actor_label text NOT NULL DEFAULT '',
      action      text NOT NULL CHECK (action ~ '^[A-Z][A-Z0-9_]{2,63}$'),
      outcome     text NOT NULL CHECK (outcome IN ('success', 'denied', 'failure')),
      resource_type text NOT NULL DEFAULT '',
      resource_id text NOT NULL DEFAULT '',
      request_id  text NOT NULL DEFAULT '',
      ip          inet,
      details     jsonb NOT NULL DEFAULT '{}'::jsonb
    );
    CREATE INDEX audit_events_org_time ON novrsoc.audit_events (org_id, occurred_at DESC);

    CREATE TABLE novrsoc.cnii_designations (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      user_id       uuid NOT NULL REFERENCES novrsoc.users(id) ON DELETE CASCADE,
      sectors       text[] NOT NULL CHECK (cardinality(sectors) > 0),
      scope_org_ids uuid[],
      reason        text NOT NULL CHECK (length(reason) BETWEEN 3 AND 500),
      granted_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      granted_at    timestamptz NOT NULL DEFAULT now(),
      expires_at    timestamptz NOT NULL,
      revoked_at    timestamptz,
      CHECK (expires_at > granted_at)
    );
    CREATE INDEX cnii_designations_user ON novrsoc.cnii_designations (user_id);
    """)

    # ---- append-only audit, even for the owner ----
    op.execute("""
    CREATE FUNCTION novrsoc.audit_events_immutable() RETURNS trigger LANGUAGE plpgsql AS
      $$ BEGIN RAISE EXCEPTION 'audit_events is append-only'; END $$;
    CREATE TRIGGER audit_events_no_update BEFORE UPDATE OR DELETE ON novrsoc.audit_events
      FOR EACH ROW EXECUTE FUNCTION novrsoc.audit_events_immutable();
    CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON novrsoc.audit_events
      FOR EACH STATEMENT EXECUTE FUNCTION novrsoc.audit_events_immutable();
    """)

    # ---- row-level security (the app role is never the owner, so RLS always applies to it) ----
    op.execute("""
    ALTER TABLE novrsoc.organizations      ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.users              ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.memberships        ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.sessions           ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.sites              ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.service_identities ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.audit_events       ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.cnii_designations  ENABLE ROW LEVEL SECURITY;

    CREATE POLICY org_visible ON novrsoc.organizations FOR SELECT USING (
      id = novrsoc.app_org() OR novrsoc.app_platform_admin()
      OR EXISTS (SELECT 1 FROM novrsoc.memberships m WHERE m.org_id = organizations.id AND m.user_id = novrsoc.app_user()));
    CREATE POLICY org_admin_write ON novrsoc.organizations FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());

    CREATE POLICY users_visible ON novrsoc.users FOR SELECT USING (
      id = novrsoc.app_user() OR novrsoc.app_platform_admin()
      OR EXISTS (SELECT 1 FROM novrsoc.memberships m WHERE m.user_id = users.id AND m.org_id = novrsoc.app_org()));

    CREATE POLICY memberships_visible ON novrsoc.memberships FOR SELECT USING (
      user_id = novrsoc.app_user() OR org_id = novrsoc.app_org() OR novrsoc.app_platform_admin());
    CREATE POLICY memberships_admin_write ON novrsoc.memberships FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());

    -- sessions: no policy for the app role at all (deny); only the SECURITY DEFINER functions touch it.

    CREATE POLICY sites_tenant ON novrsoc.sites FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());

    CREATE POLICY service_identities_tenant ON novrsoc.service_identities FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());

    CREATE POLICY audit_read_tenant ON novrsoc.audit_events FOR SELECT USING (org_id = novrsoc.app_org());
    CREATE POLICY audit_insert ON novrsoc.audit_events FOR INSERT
      WITH CHECK (org_id IS NULL OR org_id = novrsoc.app_org());

    CREATE POLICY cnii_designations_visible ON novrsoc.cnii_designations FOR SELECT
      USING (user_id = novrsoc.app_user() OR novrsoc.app_platform_admin());
    CREATE POLICY cnii_designations_admin_write ON novrsoc.cnii_designations FOR ALL
      USING (novrsoc.app_platform_admin()) WITH CHECK (novrsoc.app_platform_admin());
    """)

    # ---- pre-authentication functions (SECURITY DEFINER, fixed search_path, minimal results) ----
    op.execute("""
    CREATE FUNCTION novrsoc.auth_user_for_login(p_email citext)
      RETURNS TABLE (user_id uuid, password_hash text, status text, locked_until timestamptz)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT id, password_hash, status, locked_until FROM novrsoc.users WHERE email = p_email $$;

    CREATE FUNCTION novrsoc.auth_record_login(p_user uuid, p_success boolean, p_max_failures integer, p_lock_minutes integer)
      RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF p_success THEN
          UPDATE novrsoc.users SET failed_login_count = 0, locked_until = NULL, last_login_at = now() WHERE id = p_user;
        ELSE
          UPDATE novrsoc.users
             SET failed_login_count = failed_login_count + 1,
                 locked_until = CASE WHEN failed_login_count + 1 >= p_max_failures
                                     THEN now() + make_interval(mins => p_lock_minutes) ELSE locked_until END
           WHERE id = p_user;
        END IF;
      END $$;

    CREATE FUNCTION novrsoc.auth_create_session(p_user uuid, p_token_hash bytea, p_csrf_hash bytea, p_ttl_minutes integer)
      RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ INSERT INTO novrsoc.sessions(user_id, token_hash, csrf_hash, expires_at)
         VALUES (p_user, p_token_hash, p_csrf_hash, now() + make_interval(mins => p_ttl_minutes)) RETURNING id $$;

    CREATE FUNCTION novrsoc.auth_session(p_token_hash bytea)
      RETURNS TABLE (session_id uuid, user_id uuid, csrf_hash bytea)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT s.id, s.user_id, s.csrf_hash FROM novrsoc.sessions s JOIN novrsoc.users u ON u.id = s.user_id
          WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL AND s.expires_at > now() AND u.status = 'active' $$;

    CREATE FUNCTION novrsoc.auth_revoke_session(p_token_hash bytea)
      RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ UPDATE novrsoc.sessions SET revoked_at = now() WHERE token_hash = p_token_hash AND revoked_at IS NULL $$;

    CREATE FUNCTION novrsoc.auth_service_identity(p_id uuid)
      RETURNS TABLE (id uuid, org_id uuid, site_id uuid, kind text, scopes text[], secret_hash bytea, usable boolean)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT s.id, s.org_id, s.site_id, s.kind, s.scopes, s.secret_hash,
                (s.status = 'active' AND (s.expires_at IS NULL OR s.expires_at > now()) AND o.status = 'active')
           FROM novrsoc.service_identities s JOIN novrsoc.organizations o ON o.id = s.org_id
          WHERE s.id = p_id $$;

    CREATE FUNCTION novrsoc.auth_touch_service_identity(p_id uuid)
      RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ UPDATE novrsoc.service_identities SET last_used_at = now() WHERE id = p_id $$;
    """)

    # ---- grants: least privilege for the runtime role ----
    op.execute(f"""
    REVOKE ALL ON ALL TABLES IN SCHEMA novrsoc FROM PUBLIC;
    REVOKE ALL ON ALL FUNCTIONS IN SCHEMA novrsoc FROM PUBLIC;
    GRANT SELECT ON novrsoc.roles, novrsoc.permissions, novrsoc.role_permissions TO {APP};
    GRANT SELECT ON novrsoc.alembic_version TO {APP};  -- readiness reports the migration revision
    GRANT SELECT, INSERT, UPDATE ON novrsoc.organizations TO {APP};
    GRANT SELECT ON novrsoc.users TO {APP};
    GRANT SELECT, INSERT, UPDATE, DELETE ON novrsoc.memberships TO {APP};
    GRANT SELECT, INSERT, UPDATE ON novrsoc.sites TO {APP};
    GRANT SELECT, INSERT, UPDATE ON novrsoc.service_identities TO {APP};
    GRANT SELECT, INSERT ON novrsoc.audit_events TO {APP};
    GRANT SELECT, INSERT, UPDATE ON novrsoc.cnii_designations TO {APP};
    GRANT EXECUTE ON FUNCTION novrsoc.app_org(), novrsoc.app_user(), novrsoc.app_platform_admin() TO {APP};
    GRANT EXECUTE ON FUNCTION novrsoc.auth_user_for_login(citext), novrsoc.auth_record_login(uuid, boolean, integer, integer),
      novrsoc.auth_create_session(uuid, bytea, bytea, integer), novrsoc.auth_session(bytea),
      novrsoc.auth_revoke_session(bytea), novrsoc.auth_service_identity(uuid),
      novrsoc.auth_touch_service_identity(uuid) TO {APP};
    """)


def downgrade() -> None:
    op.execute("""
    DROP TABLE IF EXISTS novrsoc.cnii_designations, novrsoc.audit_events, novrsoc.service_identities,
      novrsoc.sites, novrsoc.sessions, novrsoc.memberships, novrsoc.users, novrsoc.organizations,
      novrsoc.role_permissions, novrsoc.permissions, novrsoc.roles CASCADE;
    DROP FUNCTION IF EXISTS novrsoc.auth_user_for_login(citext), novrsoc.auth_record_login(uuid, boolean, integer, integer),
      novrsoc.auth_create_session(uuid, bytea, bytea, integer), novrsoc.auth_session(bytea),
      novrsoc.auth_revoke_session(bytea), novrsoc.auth_service_identity(uuid),
      novrsoc.auth_touch_service_identity(uuid), novrsoc.audit_events_immutable(),
      novrsoc.app_org(), novrsoc.app_user(), novrsoc.app_platform_admin();
    """)
