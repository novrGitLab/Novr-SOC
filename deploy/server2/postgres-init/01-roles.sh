#!/bin/sh
# Server 2 PostgreSQL first start only (docker-entrypoint-initdb.d; never runs again once the data volume exists).
# Same roles and grants as the tested development cluster (deploy/dev/postgres/init/01-roles.sh):
#   novrsoc_owner  owns the schema and runs migrations (migrate service, operator jobs, backups). Not used by the API.
#   novrsoc_app    the API's runtime role. NOSUPERUSER, NOBYPASSRLS: row-level security applies to every query.
# The NHAI worker's role (novrsoc_nhai) is created by 02-nhai-role.sh, which is idempotent so that an existing volume
# can run it before the 0016 upgrade.
# Passwords come from compose secrets (files readable by the postgres user, uid 70), never from the environment.
set -eu
owner_pw=$(cat /run/secrets/pg_owner_password)
app_pw=$(cat /run/secrets/pg_app_password)
[ "${#owner_pw}" -ge 24 ] && [ "${#app_pw}" -ge 24 ] || { echo "role passwords must be at least 24 characters" >&2; exit 1; }

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_pw="$owner_pw" -v app_pw="$app_pw" <<'EOSQL'
CREATE ROLE novrsoc_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE novrsoc_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE novrsoc_owner SET search_path = novrsoc, public;
ALTER ROLE novrsoc_app   SET search_path = novrsoc, public;
EOSQL

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
REVOKE ALL ON DATABASE novrsoc FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE SCHEMA novrsoc AUTHORIZATION novrsoc_owner;
GRANT USAGE ON SCHEMA novrsoc TO novrsoc_app;
GRANT CONNECT ON DATABASE novrsoc TO novrsoc_app, novrsoc_owner;
EOSQL

# Gate G-F2 (platform owner, as the superuser; not run here): enable login for the NHAI worker role with a password
# generated on the server, and admit it ONLY over TLS from the Server 1 WireGuard address:
#   ALTER ROLE novrsoc_nhai LOGIN PASSWORD '<from ${NOVRSOC_CONFIG_DIR}/secrets/pg_nhai_password>';
#   pg_hba.conf:  hostssl novrsoc novrsoc_nhai <Server 1 WireGuard address>/32 scram-sha-256
# Its table and function grants come from migration 0016_nhai_worker_role; nothing else is granted.
