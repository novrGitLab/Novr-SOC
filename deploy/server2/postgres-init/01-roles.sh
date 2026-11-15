#!/bin/sh
# Server 2 PostgreSQL first start only (docker-entrypoint-initdb.d; never runs again once the data volume exists).
# Same roles and grants as the tested development cluster (deploy/dev/postgres/init/01-roles.sh):
#   novrsoc_owner  owns the schema and runs migrations (migrate service, operator jobs, backups). Not used by the API.
#   novrsoc_app    the API's runtime role. NOSUPERUSER, NOBYPASSRLS: row-level security applies to every query.
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

# Before gate G-F2: a dedicated NHAI worker role for Server 1, reachable only over WireGuard with TLS
# (hostssl + verify-full). Created by the platform owner at that gate, not here. The grants below are the
# alert-triage minimum; re-derive them for every NHAI task enabled at the gate (finding explanation, asset
# summary, chat answer read their own evidence tables and write novrsoc.ai_activity):
#   CREATE ROLE novrsoc_nhai LOGIN NOSUPERUSER NOBYPASSRLS PASSWORD '<from a file>';
#   GRANT CONNECT ON DATABASE novrsoc TO novrsoc_nhai; GRANT USAGE ON SCHEMA novrsoc TO novrsoc_nhai;
#   GRANT EXECUTE ON FUNCTION novrsoc.nhai_claim_job(text, integer), novrsoc.nhai_expire_jobs() TO novrsoc_nhai;
#   GRANT SELECT, UPDATE ON novrsoc.nhai_jobs TO novrsoc_nhai; GRANT SELECT ON novrsoc.alerts TO novrsoc_nhai;
#   GRANT INSERT ON novrsoc.audit_events TO novrsoc_nhai;
