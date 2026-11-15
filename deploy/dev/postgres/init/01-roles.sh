#!/bin/sh
# Creates the two V2 database roles in the disposable dev cluster.
#   novrsoc_owner  owns the schema and runs migrations (Alembic). Not used by the API at runtime.
#   novrsoc_app    the API's runtime role. NOSUPERUSER, NOBYPASSRLS: row-level security applies to it.
#   novrsoc_nhai   the NHAI worker's least-privilege role (grants: migration 0016). NOLOGIN; tests use SET ROLE.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v owner_pw="$NOVRSOC_OWNER_PASSWORD" -v app_pw="$NOVRSOC_APP_PASSWORD" <<'EOSQL'
CREATE ROLE novrsoc_owner LOGIN PASSWORD :'owner_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE ROLE novrsoc_app   LOGIN PASSWORD :'app_pw'   NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
ALTER ROLE novrsoc_owner SET search_path = novrsoc, public;
ALTER ROLE novrsoc_app   SET search_path = novrsoc, public;
CREATE ROLE novrsoc_nhai NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS CONNECTION LIMIT 2;
ALTER ROLE novrsoc_nhai  SET search_path = novrsoc, public;
EOSQL
# The schema and extensions for the dev database itself (test databases repeat this per database).
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
CREATE EXTENSION IF NOT EXISTS citext WITH SCHEMA public;
CREATE SCHEMA novrsoc AUTHORIZATION novrsoc_owner;
GRANT USAGE ON SCHEMA novrsoc TO novrsoc_app;
GRANT CONNECT ON DATABASE novrsoc_v2_dev TO novrsoc_app, novrsoc_owner, novrsoc_nhai;
EOSQL
