"""Account security for production: forced password change for temporary passwords, self-service password change.

Revision ID: 0011_account_security
Revises: 0010_pilot_modules

- users.password_change_required: set for every account created with a temporary password (tenant administration,
  operator bootstrap). While it is set the API answers 403 password_change_required on every route except
  /auth/me, /auth/password and /auth/logout.
- auth_change_password(): acts only on the signed-in user (app_user()); replaces the hash, clears the flag and revokes
  every other session of that user. The current password is verified by the API before the call.
- admin_create_user(): now marks the new account password_change_required.
- admin_reset_password(): platform administrators issue a new temporary password for another user (never their own):
  the flag is set, the lockout cleared and every session of that user revoked.
"""
from alembic import op

revision = "0011_account_security"
down_revision = "0010_pilot_modules"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute("""
    ALTER TABLE novrsoc.users
      ADD COLUMN password_change_required boolean NOT NULL DEFAULT false,
      ADD COLUMN password_changed_at timestamptz;

    CREATE OR REPLACE FUNCTION novrsoc.admin_create_user(p_email citext, p_name text, p_hash text) RETURNS uuid
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE v uuid;
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        INSERT INTO novrsoc.users (email, display_name, password_hash, password_change_required)
          VALUES (p_email, p_name, p_hash, true) RETURNING id INTO v;
        RETURN v;
      END $$;

    CREATE FUNCTION novrsoc.auth_change_password(p_new_hash text, p_keep_session bytea) RETURNS void
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF novrsoc.app_user() IS NULL THEN RAISE EXCEPTION 'signed-in user context required'; END IF;
        IF p_new_hash IS NULL OR length(p_new_hash) < 20 THEN RAISE EXCEPTION 'invalid password hash'; END IF;
        UPDATE novrsoc.users SET password_hash = p_new_hash, password_change_required = false,
               password_changed_at = now(), failed_login_count = 0, locked_until = NULL
         WHERE id = novrsoc.app_user();
        UPDATE novrsoc.sessions SET revoked_at = now()
         WHERE user_id = novrsoc.app_user() AND revoked_at IS NULL AND token_hash <> p_keep_session;
      END $$;
    CREATE FUNCTION novrsoc.admin_reset_password(p_user uuid, p_hash text) RETURNS boolean
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        IF p_user = novrsoc.app_user() THEN RAISE EXCEPTION 'administrators cannot reset their own password'; END IF;
        IF p_hash IS NULL OR length(p_hash) < 20 THEN RAISE EXCEPTION 'invalid password hash'; END IF;
        UPDATE novrsoc.users SET password_hash = p_hash, password_change_required = true, password_changed_at = now(),
               failed_login_count = 0, locked_until = NULL
         WHERE id = p_user;
        IF NOT FOUND THEN RETURN false; END IF;
        UPDATE novrsoc.sessions SET revoked_at = now() WHERE user_id = p_user AND revoked_at IS NULL;
        RETURN true;
      END $$;
    REVOKE ALL ON FUNCTION novrsoc.auth_change_password(text, bytea), novrsoc.admin_reset_password(uuid, text) FROM PUBLIC;
    GRANT EXECUTE ON FUNCTION novrsoc.auth_change_password(text, bytea), novrsoc.admin_reset_password(uuid, text) TO novrsoc_app;
    """)


def downgrade() -> None:
    op.execute("""
    DROP FUNCTION IF EXISTS novrsoc.auth_change_password(text, bytea), novrsoc.admin_reset_password(uuid, text);
    CREATE OR REPLACE FUNCTION novrsoc.admin_create_user(p_email citext, p_name text, p_hash text) RETURNS uuid
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = novrsoc, pg_temp AS $$
      DECLARE v uuid;
      BEGIN
        IF NOT novrsoc.app_platform_admin() THEN RAISE EXCEPTION 'platform administrator context required'; END IF;
        INSERT INTO novrsoc.users (email, display_name, password_hash) VALUES (p_email, p_name, p_hash) RETURNING id INTO v;
        RETURN v;
      END $$;
    ALTER TABLE novrsoc.users DROP COLUMN password_changed_at, DROP COLUMN password_change_required;
    """)
