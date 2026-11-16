#!/bin/sh
# The NHAI worker's database role (novrsoc_nhai), IDEMPOTENT: safe to run any number of times.
#   * First start: runs automatically after 01-roles.sh (docker-entrypoint-initdb.d).
#   * Existing volume (initdb scripts never run again): run it ONCE before upgrading to migration 0016:
#       docker compose exec -T postgres sh /docker-entrypoint-initdb.d/02-nhai-role.sh
# It only creates the role when it is missing (NOLOGIN, NOSUPERUSER, NOBYPASSRLS) and grants CONNECT on the database.
# It never changes an existing role, password or login (gate G-F2 enables login), and touches no data.
# Its table and function grants come from migration 0016_nhai_worker_role.
set -eu
PGPASSWORD="${PGPASSWORD:-$(cat /run/secrets/pg_superuser_password)}"
export PGPASSWORD
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'novrsoc_nhai') THEN
    CREATE ROLE novrsoc_nhai NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS CONNECTION LIMIT 2;
    ALTER ROLE novrsoc_nhai SET search_path = novrsoc, public;
    RAISE NOTICE 'created role novrsoc_nhai (NOLOGIN)';
  ELSE
    RAISE NOTICE 'role novrsoc_nhai already exists: unchanged';
  END IF;
END $$;
GRANT CONNECT ON DATABASE novrsoc TO novrsoc_nhai;
SELECT rolname, rolcanlogin AS login, rolsuper AS superuser, rolbypassrls AS bypassrls FROM pg_roles WHERE rolname = 'novrsoc_nhai';
EOSQL
