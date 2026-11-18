"""Organization portals, branding, invitations and onboarding.

  * organizations: a portal subdomain (one label under the installation's base domain, unique, reserved names refused),
    portal_enabled, and branding (display name, primary and secondary colors, a raster logo up to 256 KiB: PNG, JPEG or
    WebP only, never SVG). One shared deployment serves every portal; the host only SELECTS an organization's branding
    and RESTRICTS who may sign in there. It never grants access.
  * novrsoc.portal_for_host(label) / novrsoc.portal_logo(label): what an unauthenticated portal page may know (name,
    display name, colors, logo) for an ACTIVE organization with an enabled portal. SECURITY DEFINER, nothing else.
  * sessions.portal_org_id: the portal a session was created on (NULL: the platform host). A session is valid only on
    the host it was created on (enforced by the API: auth_session_portal returns it).
  * user_invitations: an organization administrator invitation. Only the SHA-256 of the token is stored; it expires,
    is single use and can be revoked. Accepting creates the account and its home membership in one statement
    (novrsoc.invitation_accept), so the token is the only thing that authorizes it.
  * wazuh_group_mappings.provisioned: the group NovrSOC generated for the organization's agent installer (at most one
    per organization, an unguessable name). Existing mappings stay `false` (mapped by hand).
  * novrsoc.admin_end_platform_sessions(org): when a portal is switched on, the organization's members' sessions on the
    platform address end (platform administrators only).
  * agent_enrollment_tickets / agent_enrollments: server-controlled agent enrollment. A ticket is organization-bound,
    expires, can be revoked and admits a limited number of endpoints; NovrSOC itself registers each agent on the NovrSIEM
    manager in the organization's provisioned group (no shared enrollment password, no self-chosen group).
  * rate_limit_windows / novrsoc.rate_limit_hit(): fixed-window abuse protection for the public endpoints, shared by
    every API worker (client addresses are stored only as a digest).
  * log_sources.verified_at / verified_by: a sender registered by an organization stays disabled until a NovrSOC
    administrator verifies it. Existing sources were registered by platform staff: they count as verified.

Revision ID: 0019_org_portals_onboarding
Revises: 0018_vms_policy_attribution
"""
from alembic import op

revision = "0019_org_portals_onboarding"
down_revision = "0018_vms_policy_attribution"
branch_labels = None
depends_on = None

RESERVED = ("www", "api", "app", "admin", "platform", "soc", "mail", "smtp", "imap", "pop", "ftp", "vpn", "status", "docs",
            "static", "assets", "cdn", "login", "auth", "install", "portal", "novrsoc", "localhost")


def upgrade() -> None:
    reserved = ", ".join(f"'{r}'" for r in RESERVED)
    op.execute(f"""
    ALTER TABLE novrsoc.organizations
      ADD COLUMN portal_subdomain citext UNIQUE
        CHECK (portal_subdomain ~ '^[a-z0-9]([a-z0-9-]{{0,38}}[a-z0-9])?$' AND portal_subdomain NOT IN ({reserved})),
      ADD COLUMN portal_enabled boolean NOT NULL DEFAULT false,
      ADD COLUMN brand_display_name text NOT NULL DEFAULT '' CHECK (length(brand_display_name) <= 120),
      ADD COLUMN brand_primary_color text CHECK (brand_primary_color ~ '^#[0-9a-f]{{6}}$'),
      ADD COLUMN brand_secondary_color text CHECK (brand_secondary_color ~ '^#[0-9a-f]{{6}}$'),
      ADD COLUMN brand_logo bytea CHECK (brand_logo IS NULL OR octet_length(brand_logo) <= 262144),
      ADD COLUMN brand_logo_type text CHECK (brand_logo_type IN ('image/png', 'image/jpeg', 'image/webp')),
      ADD COLUMN brand_logo_sha256 text CHECK (brand_logo_sha256 ~ '^[0-9a-f]{{64}}$'),
      ADD CONSTRAINT organizations_logo_complete CHECK ((brand_logo IS NULL) = (brand_logo_type IS NULL)),
      ADD CONSTRAINT organizations_portal_needs_subdomain CHECK (NOT portal_enabled OR portal_subdomain IS NOT NULL);

    CREATE FUNCTION novrsoc.portal_for_host(p_label text)
      RETURNS TABLE (org_id uuid, slug text, name text, display_name text, primary_color text, secondary_color text,
                     logo_sha256 text, kind text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT o.id, o.slug::text, o.name, o.brand_display_name, o.brand_primary_color, o.brand_secondary_color,
               o.brand_logo_sha256, o.kind
          FROM novrsoc.organizations o
         WHERE o.portal_subdomain = p_label AND o.portal_enabled AND o.status = 'active' AND o.kind = 'client' $$;
    CREATE FUNCTION novrsoc.portal_logo(p_label text) RETURNS TABLE (logo bytea, logo_type text, logo_sha256 text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT o.brand_logo, o.brand_logo_type, o.brand_logo_sha256 FROM novrsoc.organizations o
         WHERE o.portal_subdomain = p_label AND o.portal_enabled AND o.status = 'active' AND o.kind = 'client'
           AND o.brand_logo IS NOT NULL $$;

    ALTER TABLE novrsoc.sessions ADD COLUMN portal_org_id uuid REFERENCES novrsoc.organizations(id) ON DELETE CASCADE;
    CREATE FUNCTION novrsoc.auth_create_portal_session(p_user uuid, p_token_hash bytea, p_csrf_hash bytea, p_ttl_minutes integer,
                                                       p_portal_org uuid)
      RETURNS uuid LANGUAGE sql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ INSERT INTO novrsoc.sessions(user_id, token_hash, csrf_hash, expires_at, portal_org_id)
         VALUES (p_user, p_token_hash, p_csrf_hash, now() + make_interval(mins => p_ttl_minutes), p_portal_org) RETURNING id $$;
    CREATE FUNCTION novrsoc.auth_session_portal(p_token_hash bytea)
      RETURNS TABLE (session_id uuid, user_id uuid, csrf_hash bytea, portal_org_id uuid)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS
      $$ SELECT s.id, s.user_id, s.csrf_hash, s.portal_org_id FROM novrsoc.sessions s JOIN novrsoc.users u ON u.id = s.user_id
          WHERE s.token_hash = p_token_hash AND s.revoked_at IS NULL AND s.expires_at > now() AND u.status = 'active' $$;

    CREATE TABLE novrsoc.user_invitations (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      email         citext NOT NULL CHECK (position('@' in email) > 1),
      role_key      text NOT NULL CHECK (role_key IN ('soc_manager', 'analyst', 'executive', 'portal_user')),
      token_hash    bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
      invited_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      invited_label text NOT NULL DEFAULT '',
      created_at    timestamptz NOT NULL DEFAULT now(),
      expires_at    timestamptz NOT NULL,
      accepted_at   timestamptz,
      accepted_user uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      revoked_at    timestamptz,
      CHECK (expires_at > created_at), CHECK (accepted_at IS NULL OR revoked_at IS NULL));
    CREATE UNIQUE INDEX user_invitations_one_open ON novrsoc.user_invitations (org_id, email)
      WHERE accepted_at IS NULL AND revoked_at IS NULL;
    ALTER TABLE novrsoc.user_invitations ENABLE ROW LEVEL SECURITY;
    CREATE POLICY user_invitations_tenant ON novrsoc.user_invitations FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.user_invitations TO novrsoc_app;

    -- What an invitation link may reveal before it is accepted, and its acceptance. The token hash is the only key.
    CREATE FUNCTION novrsoc.invitation_preview(p_token_hash bytea)
      RETURNS TABLE (invitation_id uuid, org_id uuid, email text, role_key text, expires_at timestamptz, state text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT i.id, i.org_id, i.email::text, i.role_key, i.expires_at,
               CASE WHEN i.revoked_at IS NOT NULL THEN 'revoked' WHEN i.accepted_at IS NOT NULL THEN 'accepted'
                    WHEN i.expires_at <= now() THEN 'expired' WHEN o.status <> 'active' THEN 'organization_inactive' ELSE 'open' END
          FROM novrsoc.user_invitations i JOIN novrsoc.organizations o ON o.id = i.org_id WHERE i.token_hash = p_token_hash $$;
    CREATE FUNCTION novrsoc.invitation_accept(p_token_hash bytea, p_name text, p_password_hash text)
      RETURNS uuid LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE inv record; v uuid;
      BEGIN
        SELECT i.* INTO inv FROM novrsoc.user_invitations i JOIN novrsoc.organizations o ON o.id = i.org_id
         WHERE i.token_hash = p_token_hash AND i.accepted_at IS NULL AND i.revoked_at IS NULL AND i.expires_at > now()
           AND o.status = 'active' FOR UPDATE OF i;
        IF NOT FOUND THEN RETURN NULL; END IF;
        IF EXISTS (SELECT 1 FROM novrsoc.users WHERE email = inv.email) THEN RAISE EXCEPTION 'account exists' USING ERRCODE = '23505'; END IF;
        INSERT INTO novrsoc.users (email, display_name, password_hash) VALUES (inv.email, p_name, p_password_hash) RETURNING id INTO v;
        INSERT INTO novrsoc.memberships (user_id, org_id, role_key, access_scope) VALUES (v, inv.org_id, inv.role_key, 'home');
        UPDATE novrsoc.user_invitations SET accepted_at = now(), accepted_user = v WHERE id = inv.id;
        RETURN v;
      END $$;
    -- When an organization's portal is switched on, its members' sessions on the platform address end: they sign in again
    -- at the portal. Platform administrators only (checked here as well).
    CREATE FUNCTION novrsoc.admin_end_platform_sessions(p_org uuid) RETURNS integer
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE n integer;
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        UPDATE novrsoc.sessions s SET revoked_at = now() FROM novrsoc.memberships m
         WHERE m.user_id = s.user_id AND m.org_id = p_org AND m.access_scope = 'home' AND s.portal_org_id IS NULL AND s.revoked_at IS NULL;
        GET DIAGNOSTICS n = ROW_COUNT;
        RETURN n;
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.admin_end_platform_sessions(uuid) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.admin_end_platform_sessions(uuid) TO novrsoc_app;
    REVOKE ALL ON FUNCTION novrsoc.portal_for_host(text), novrsoc.portal_logo(text),
      novrsoc.auth_create_portal_session(uuid, bytea, bytea, integer, uuid), novrsoc.auth_session_portal(bytea),
      novrsoc.invitation_preview(bytea), novrsoc.invitation_accept(bytea, text, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.portal_for_host(text), novrsoc.portal_logo(text),
      novrsoc.auth_create_portal_session(uuid, bytea, bytea, integer, uuid), novrsoc.auth_session_portal(bytea),
      novrsoc.invitation_preview(bytea), novrsoc.invitation_accept(bytea, text, text) TO novrsoc_app;

    ALTER TABLE novrsoc.wazuh_group_mappings ADD COLUMN provisioned boolean NOT NULL DEFAULT false;
    CREATE UNIQUE INDEX wazuh_group_mappings_one_provisioned ON novrsoc.wazuh_group_mappings (org_id) WHERE provisioned;

    ALTER TABLE novrsoc.log_sources
      ADD COLUMN verified_at timestamptz,
      ADD COLUMN verified_by uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL;
    UPDATE novrsoc.log_sources SET verified_at = created_at;

    -- Server-controlled agent enrollment. An organization administrator issues a ticket (org-bound, expiring, revocable,
    -- limited number of endpoints); the installer presents it and NovrSOC itself registers the agent on the NovrSIEM
    -- manager, in the organization's provisioned group. No shared enrollment password, no self-chosen group.
    CREATE TABLE novrsoc.agent_enrollment_tickets (
      id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id        uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      os            text NOT NULL CHECK (os IN ('windows', 'linux', 'macos')),
      token_hash    bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
      max_uses      integer NOT NULL CHECK (max_uses BETWEEN 1 AND 500),
      uses          integer NOT NULL DEFAULT 0 CHECK (uses >= 0 AND uses <= max_uses),
      created_by    uuid REFERENCES novrsoc.users(id) ON DELETE SET NULL,
      created_label text NOT NULL DEFAULT '',
      created_at    timestamptz NOT NULL DEFAULT now(),
      expires_at    timestamptz NOT NULL,
      revoked_at    timestamptz,
      CHECK (expires_at > created_at), UNIQUE (id, org_id));
    CREATE TABLE novrsoc.agent_enrollments (
      id          uuid PRIMARY KEY DEFAULT gen_random_uuid(),
      org_id      uuid NOT NULL REFERENCES novrsoc.organizations(id) ON DELETE CASCADE,
      ticket_id   uuid NOT NULL,
      agent_id    text NOT NULL CHECK (agent_id ~ '^[0-9]{{3,6}}$'),
      agent_name  text NOT NULL CHECK (length(agent_name) BETWEEN 1 AND 128),
      group_name  text NOT NULL,
      hostname    text NOT NULL CHECK (length(hostname) BETWEEN 1 AND 64),
      os          text NOT NULL,
      source_ip   inet,
      enrolled_at timestamptz NOT NULL DEFAULT now(),
      UNIQUE (agent_id),
      FOREIGN KEY (ticket_id, org_id) REFERENCES novrsoc.agent_enrollment_tickets (id, org_id) ON DELETE CASCADE);
    ALTER TABLE novrsoc.agent_enrollment_tickets ENABLE ROW LEVEL SECURITY;
    ALTER TABLE novrsoc.agent_enrollments ENABLE ROW LEVEL SECURITY;
    CREATE POLICY agent_enrollment_tickets_tenant ON novrsoc.agent_enrollment_tickets FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    CREATE POLICY agent_enrollments_tenant ON novrsoc.agent_enrollments FOR ALL
      USING (org_id = novrsoc.app_org()) WITH CHECK (org_id = novrsoc.app_org());
    GRANT SELECT, INSERT, UPDATE ON novrsoc.agent_enrollment_tickets TO novrsoc_app;
    GRANT SELECT, INSERT ON novrsoc.agent_enrollments TO novrsoc_app;
    -- The only thing an unauthenticated installer may learn from a ticket: its organization, if the ticket is valid.
    CREATE FUNCTION novrsoc.enrollment_ticket_org(p_token_hash bytea) RETURNS uuid
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
        SELECT t.org_id FROM novrsoc.agent_enrollment_tickets t
         WHERE t.token_hash = p_token_hash AND t.revoked_at IS NULL AND t.expires_at > now() $$;

    -- Abuse protection for the public endpoints, shared by every API worker: fixed windows per (bucket, window). The
    -- bucket names the endpoint group and a digest of the client address (never the address itself).
    CREATE TABLE novrsoc.rate_limit_windows (
      bucket       text NOT NULL CHECK (length(bucket) BETWEEN 3 AND 120),
      window_start timestamptz NOT NULL,
      hits         integer NOT NULL,
      PRIMARY KEY (bucket, window_start));
    ALTER TABLE novrsoc.rate_limit_windows ENABLE ROW LEVEL SECURITY;      -- no policy: only the function below
    CREATE FUNCTION novrsoc.rate_limit_hit(p_bucket text, p_window_seconds integer) RETURNS integer
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE w timestamptz := to_timestamp(floor(extract(epoch FROM now()) / p_window_seconds) * p_window_seconds); n integer;
      BEGIN
        INSERT INTO novrsoc.rate_limit_windows AS r (bucket, window_start, hits) VALUES (p_bucket, w, 1)
          ON CONFLICT (bucket, window_start) DO UPDATE SET hits = r.hits + 1 RETURNING hits INTO n;
        IF random() < 0.01 THEN DELETE FROM novrsoc.rate_limit_windows WHERE window_start < now() - interval '1 day'; END IF;
        RETURN n;
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.enrollment_ticket_org(bytea), novrsoc.rate_limit_hit(text, integer) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.enrollment_ticket_org(bytea), novrsoc.rate_limit_hit(text, integer) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.rate_limit_hit(text, integer);
    DROP TABLE IF EXISTS novrsoc.rate_limit_windows;
    DROP FUNCTION IF EXISTS novrsoc.enrollment_ticket_org(bytea);
    DROP TABLE IF EXISTS novrsoc.agent_enrollments;
    DROP TABLE IF EXISTS novrsoc.agent_enrollment_tickets;
    ALTER TABLE novrsoc.log_sources DROP COLUMN verified_by, DROP COLUMN verified_at;
    DROP INDEX IF EXISTS novrsoc.wazuh_group_mappings_one_provisioned;
    ALTER TABLE novrsoc.wazuh_group_mappings DROP COLUMN provisioned;
    DROP FUNCTION IF EXISTS novrsoc.admin_end_platform_sessions(uuid);
    DROP FUNCTION IF EXISTS novrsoc.invitation_accept(bytea, text, text);
    DROP FUNCTION IF EXISTS novrsoc.invitation_preview(bytea);
    DROP TABLE IF EXISTS novrsoc.user_invitations;
    DROP FUNCTION IF EXISTS novrsoc.auth_session_portal(bytea);
    DROP FUNCTION IF EXISTS novrsoc.auth_create_portal_session(uuid, bytea, bytea, integer, uuid);
    ALTER TABLE novrsoc.sessions DROP COLUMN portal_org_id;
    DROP FUNCTION IF EXISTS novrsoc.portal_logo(text);
    DROP FUNCTION IF EXISTS novrsoc.portal_for_host(text);
    ALTER TABLE novrsoc.organizations DROP CONSTRAINT organizations_portal_needs_subdomain,
      DROP CONSTRAINT organizations_logo_complete, DROP COLUMN brand_logo_sha256, DROP COLUMN brand_logo_type,
      DROP COLUMN brand_logo, DROP COLUMN brand_secondary_color, DROP COLUMN brand_primary_color,
      DROP COLUMN brand_display_name, DROP COLUMN portal_enabled, DROP COLUMN portal_subdomain;
    """)
