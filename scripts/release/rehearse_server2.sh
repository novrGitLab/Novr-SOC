#!/usr/bin/env bash
# Local rehearsal of the Server 2 deployment (docker compose, production mode, the real images). LOCAL ONLY:
# loopback ports 18000/13210, compose project "novrsoc-rehearsal", a throwaway config directory with freshly generated
# secrets (never printed), and everything is removed at the end (`down -v` removes only this project's volume).
# It never contacts a server, a registry or GitHub.
#
#   bash scripts/release/rehearse_server2.sh [image tag]     # default tag: rehearsal (build first, see below)
#   for i in api web vms-worker; do docker build -f deploy/docker/$i.Dockerfile -t novrsoc-$i:rehearsal .; done
#
# Steps: compose up (postgres -> migrate -> api after check-env -> web) -> bootstrap-platform (and its refusal on a
# second run) -> production-path checks (scripts/release/rehearsal_checks.py) -> VMS worker (identity, heartbeat,
# scanning disabled, network isolation) -> encrypted backup -> restore drill
# into a disposable database -> rollback guard (downgrade to 0010, i.e. 0011-0016: check-env must FAIL; upgrade back) ->
# upgrade of an existing 0015 installation without the novrsoc_nhai role (refusal, 02-nhai-role.sh, 0016, data intact) ->
# container hardening inspection -> teardown.
set -euo pipefail
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TAG="${1:-rehearsal}"
PY="${PYTHON:-python}"
WORK="$(mktemp -d)"
if command -v cygpath >/dev/null 2>&1; then   # Git Bash on Windows: hand Docker and Python native paths
  WORK="$(cygpath -m "$WORK")"; ROOT="$(cygpath -m "$ROOT")"
fi
DC=(docker compose -p novrsoc-rehearsal --env-file "$WORK/.env" -f "$ROOT/deploy/server2/compose.yaml")
quiet() { grep -v -E '^\s*(Container|Network|Volume)|Creat|Start|Waiting|Healthy|Running|Pulling' || true; }
cleanup() { "${DC[@]}" --profile ops --profile vms down -v >/dev/null 2>&1 || true; rm -rf "$WORK"; }
trap cleanup EXIT

echo "== configuration (throwaway, $WORK)"
"$PY" - "$WORK" "$TAG" <<'EOF'
import base64, os, secrets, sys
w, tag = sys.argv[1], sys.argv[2]
c = os.path.join(w, "config")
for d in ("secrets", "files", "backups", "bootstrap"):
    os.makedirs(os.path.join(c if d in ("secrets", "files") else w, d), exist_ok=True)
pw = {k: secrets.token_urlsafe(32) for k in ("pg_superuser_password", "pg_owner_password", "pg_app_password")}
for k, v in pw.items():
    open(os.path.join(c, "secrets", k), "w", newline="\n").write(v)
open(os.path.join(c, "files", "backup.key"), "w").write(base64.b64encode(secrets.token_bytes(32)).decode())
common = ("NOVRSOC_ENV=production\nNOVRSOC_PRODUCTION_DATABASE_HOSTS=postgres\nNOVRSOC_SESSION_COOKIE_SECURE=true\n"
          f"NOVRSOC_DATABASE_URL=postgresql+psycopg://novrsoc_app:{pw['pg_app_password']}@postgres:5432/novrsoc\n")
owner = f"NOVRSOC_MIGRATION_DATABASE_URL=postgresql+psycopg://novrsoc_owner:{pw['pg_owner_password']}@postgres:5432/novrsoc\n"
w_ = lambda n, t: open(os.path.join(c, n), "w", newline="\n").write(t)
w_("api.env", common + "NOVRSOC_DOCS_ENABLED=false\nNOVRSOC_WAZUH_MODE=unconfigured\nNOVRSOC_NHAI_BACKEND=unconfigured\n"
   "NOVRSOC_VMS_SCANNING=disabled\nNOVRSOC_BRAND_RESOLVER=unconfigured\n")
w_("migrate.env", common + owner)
w_("backup.env", common + owner +
   f"NOVRSOC_TEST_ADMIN_DATABASE_URL=postgresql+psycopg://postgres:{pw['pg_superuser_password']}@postgres:5432/postgres\n")
open(os.path.join(w, ".env"), "w", newline="\n").write(
    f"NOVRSOC_IMAGE_TAG={tag}\nNOVRSOC_CONFIG_DIR={c}\nNOVRSOC_BACKUP_DIR={os.path.join(w, 'backups')}\n"
    "NOVRSOC_API_BIND=127.0.0.1:18000\nNOVRSOC_WEB_BIND=127.0.0.1:13210\nNOVRSOC_APP_SUBNET=172.30.10.0/24\n")
print("secrets generated (not printed); images tag", tag)
EOF

echo "== docker compose config"; "${DC[@]}" config -q && echo "valid"
echo "== up"
if ! "${DC[@]}" up -d --wait --wait-timeout 300 2>&1 | quiet; then
  "${DC[@]}" ps -a --format '{{.Service}}: {{.State}} {{.Status}}'; "${DC[@]}" logs --tail 300 migrate api 2>&1 | grep -v 'alembic.runtime.plugins'; exit 1
fi
"${DC[@]}" ps -a --format '{{.Service}}: {{.State}} {{.Status}}'
"${DC[@]}" logs api 2>/dev/null | grep -E '(OK|FAIL)  ' || true

echo "== bootstrap-platform"
"${DC[@]}" --profile ops run --rm --no-TTY -v "$WORK/bootstrap:/out" operator bootstrap-platform --email owner@rehearsal.invalid --out /out/first-admin.txt 2>&1 | quiet
if "${DC[@]}" --profile ops run --rm --no-TTY -v "$WORK/bootstrap:/out" operator bootstrap-platform --email again@rehearsal.invalid --out /out/again.txt >/dev/null 2>&1; then
  echo "FAIL  a second bootstrap was accepted"; exit 1; else echo "PASS  a second bootstrap is refused"; fi

echo "== production-path checks"; "$PY" "$ROOT/scripts/release/rehearsal_checks.py" owner@rehearsal.invalid "$WORK/bootstrap/first-admin.txt"

echo "== VMS worker (profile vms; scanning disabled; internal network to the API only)"
mkdir -p "$WORK/issued" "$WORK/config/vms"
"${DC[@]}" --profile ops run --rm --no-TTY -v "$WORK/issued:/out" operator create-service-identity --kind vms_worker \
  --name server2-vms-worker --org-slug rehearsal-client --scope vms:worker --out /out/rehearsal-client.token 2>&1 | quiet
install -m 0444 "$WORK/issued/rehearsal-client.token" "$WORK/config/vms/rehearsal-client.token"   # production: -o 10002 -m 0400
"${DC[@]}" --profile vms up -d vms-worker 2>&1 | quiet
pg() { "${DC[@]}" exec -T postgres sh -c "PGPASSWORD=\$(cat /run/secrets/pg_superuser_password) psql -U postgres -d novrsoc -tAc \"$1\""; }
beats=0
for _ in $(seq 1 30); do
  beats=$(pg "SELECT count(*) FROM novrsoc.vms_worker_heartbeats" | tr -d '[:space:]')
  [ "${beats:-0}" -gt 0 ] && break; sleep 2
done
if [ "${beats:-0}" -gt 0 ]; then echo "PASS  the VMS worker's heartbeat reached the API ($beats)"; else echo "FAIL  no VMS worker heartbeat"; exit 1; fi
dep=$(pg "SELECT dependencies->0->>'name' FROM novrsoc.vms_worker_heartbeats ORDER BY received_at DESC LIMIT 1" | tr -d '[:space:]')
[ "$dep" = "engine.disabled" ] && echo "PASS  the worker reports scanning disabled (engine.disabled)" || { echo "FAIL  engine state: $dep"; exit 1; }
jobs=$(pg "SELECT count(*) FROM novrsoc.vms_scan_jobs WHERE state <> 'queued'" | tr -d '[:space:]')
[ "${jobs:-0}" = "0" ] && echo "PASS  no scan job was claimed" || { echo "FAIL  $jobs scan job(s) left the queue"; exit 1; }
docker network inspect novrsoc-rehearsal_vms --format 'vms network internal={{.Internal}}'
if "${DC[@]}" exec -T vms-worker python -c "import socket; socket.create_connection(('postgres', 5432), 3)" >/dev/null 2>&1; then
  echo "FAIL  the VMS worker reaches the database"; exit 1; else echo "PASS  the VMS worker cannot reach the database"; fi
"${DC[@]}" exec -T vms-worker python -c "import socket; socket.create_connection(('api', 8000), 3)" \
  && echo "PASS  the VMS worker reaches the API on the internal network" || { echo "FAIL  the VMS worker cannot reach the API"; exit 1; }

echo "== backup and restore drill"
"${DC[@]}" --profile ops run --rm --no-TTY backup 2>&1 | quiet
FILE=$(ls "$WORK/backups" | head -1)
"${DC[@]}" --profile ops run --rm --no-TTY restore-drill --file "/backups/$FILE" 2>&1 | quiet | tee "$WORK/drill.json"
grep -q '"status": "succeeded"' "$WORK/drill.json"

echo "== rollback guard"
"${DC[@]}" run --rm --no-TTY --no-deps migrate alembic downgrade 0010_pilot_modules >/dev/null 2>&1
guard=$("${DC[@]}" run --rm --no-TTY --no-deps api python -m app.cli check-env 2>/dev/null || true)   # expected to exit 1
if grep -E 'FAIL' <<<"$guard"; then
  echo "PASS  check-env refuses a schema behind the image (the API cannot start against it)"
else echo "FAIL  check-env accepted a mismatched schema"; exit 1; fi
"${DC[@]}" run --rm --no-TTY --no-deps migrate alembic upgrade head >/dev/null 2>&1
"${DC[@]}" run --rm --no-TTY --no-deps api python -m app.cli check-env 2>/dev/null | grep -E 'database'

echo "== upgrade of an existing 0015 installation (persistent volume; initdb scripts do not rerun)"
# Recreate exactly what a 0015 production volume holds: the schema at 0015 with its data, and NO novrsoc_nhai role
# (the 0015 initdb script never created it). Then run the documented upgrade (docs/public/DEPLOYMENT.md §5).
"${DC[@]}" --profile vms stop vms-worker web jobs api 2>&1 | quiet
"${DC[@]}" run --rm --no-TTY --no-deps migrate alembic downgrade 0015_admin_exports_chat >/dev/null 2>&1
pg "REVOKE CONNECT ON DATABASE novrsoc FROM novrsoc_nhai; DROP ROLE novrsoc_nhai;" >/dev/null
fingerprint() {
  pg "SELECT md5(string_agg(x, '|' ORDER BY x)) FROM (
        SELECT 'u:' || id || email || coalesce(password_hash, '') || status AS x FROM novrsoc.users
        UNION ALL SELECT 'o:' || id || slug || name FROM novrsoc.organizations
        UNION ALL SELECT 'm:' || user_id || org_id || role_key FROM novrsoc.memberships
        UNION ALL SELECT 's:' || id || encode(secret_hash, 'hex') || status FROM novrsoc.service_identities
        UNION ALL SELECT 'a:' || count(*) FROM novrsoc.audit_events) t" | tr -d '[:space:]'
}
before=$(fingerprint)
[ "$(pg "SELECT version_num FROM novrsoc.alembic_version" | tr -d '[:space:]')" = "0015_admin_exports_chat" ] \
  && [ "$(pg "SELECT count(*) FROM pg_roles WHERE rolname = 'novrsoc_nhai'" | tr -d '[:space:]')" = "0" ] \
  && echo "PASS  starting point: schema 0015, data present, no novrsoc_nhai role ($before)" \
  || { echo "FAIL  could not recreate the 0015 starting point"; exit 1; }
if "${DC[@]}" run --rm --no-TTY --no-deps migrate >"$WORK/migrate-norole.log" 2>&1; then
  echo "FAIL  0016 was applied without the role"; exit 1; fi
grep -q "role novrsoc_nhai is missing" "$WORK/migrate-norole.log" \
  && [ "$(pg "SELECT version_num FROM novrsoc.alembic_version" | tr -d '[:space:]')" = "0015_admin_exports_chat" ] \
  && [ "$(fingerprint)" = "$before" ] \
  && echo "PASS  without the role, 0016 is refused with a clear message and the database stays at 0015, unchanged" \
  || { echo "FAIL  the refused migration changed something:"; tail -5 "$WORK/migrate-norole.log"; exit 1; }
"${DC[@]}" exec -T postgres sh /docker-entrypoint-initdb.d/02-nhai-role.sh 2>&1 | grep -E "NOTICE|novrsoc_nhai" | sed 's/^/      /'
again=$("${DC[@]}" exec -T postgres sh /docker-entrypoint-initdb.d/02-nhai-role.sh 2>&1)
grep -q "already exists: unchanged" <<<"$again" && echo "PASS  02-nhai-role.sh is idempotent (a second run changes nothing)" \
  || { echo "FAIL  second run of 02-nhai-role.sh: $again"; exit 1; }
"${DC[@]}" --profile vms up -d --wait --wait-timeout 300 2>&1 | quiet
after=$(fingerprint)
[ "$(pg "SELECT version_num FROM novrsoc.alembic_version" | tr -d '[:space:]')" = "0016_nhai_worker_role" ] \
  && echo "PASS  upgraded to 0016_nhai_worker_role" || { echo "FAIL  not at 0016"; exit 1; }
[ "$after" = "$before" ] && echo "PASS  users, password hashes, organizations, memberships, machine credentials and audit history unchanged" \
  || { echo "FAIL  data changed during the upgrade ($before -> $after)"; exit 1; }
[ "$(pg "SELECT rolcanlogin::text || rolsuper::text || rolbypassrls::text FROM pg_roles WHERE rolname = 'novrsoc_nhai'" | tr -d '[:space:]')" = "falsefalsefalse" ] \
  && [ "$(pg "SELECT count(*) FROM information_schema.column_privileges WHERE grantee = 'novrsoc_nhai'" | tr -d '[:space:]')" -gt 0 ] \
  && echo "PASS  novrsoc_nhai exists NOLOGIN with the 0016 grants" || { echo "FAIL  novrsoc_nhai attributes or grants"; exit 1; }
ready=$(curl -fsS http://127.0.0.1:18000/readyz || true)
grep -q '"ready"' <<<"$ready" && echo "PASS  the API is ready on the upgraded database" || { echo "FAIL  readyz: $ready"; exit 1; }

echo "== container hardening"
for c in $("${DC[@]}" ps -q); do
  docker inspect "$c" --format '{{.Name}} user={{.Config.User}} read_only={{.HostConfig.ReadonlyRootfs}} cap_drop={{.HostConfig.CapDrop}} cap_add={{.HostConfig.CapAdd}} no_new_privs={{.HostConfig.SecurityOpt}} ports={{range $p,$b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}:{{.HostPort}}{{end}} {{end}}'
done
docker network inspect novrsoc-rehearsal_db --format 'db network internal={{.Internal}}'
echo "== teardown (this project's containers, networks and volume only)"
