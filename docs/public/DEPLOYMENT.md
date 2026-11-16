# Deployment

NovrSOC runs on two hosts:

- **Server 2 (application host):** PostgreSQL, the API, the background jobs worker, the web app and the VMS worker,
  all under Docker Compose. The VMS worker is gated behind its own profile, runs with scanning disabled, and its
  only network reaches the API and nothing else.
- **Server 1 (security host):** the existing Wazuh environment, plus small NovrSOC services that run as Python
  under systemd.

There is no MISP, no hosted platform (Vercel, Railway or similar) and no model server on Server 2.

Every live integration is off until its approval gate (§6) is signed. A fresh installation shows each connector as
`unconfigured` and holds no data.

## 1. Requirements

| | Server 2 | Server 1 |
|---|---|---|
| OS | Linux with systemd (Ubuntu 22.04+ or Debian 12+) | the existing Wazuh host |
| Runtime | Docker Engine with the Compose plugin ≥ 2.24; NGINX; certbot | Python 3.12 (NHAI worker venv); system `python3` for the standard-library services |
| Size | 2 vCPU, 4 GB RAM, 40 GB disk minimum | existing; the services add < 1 GB RAM |
| Network in | 80/443 (NGINX), SSH (restricted), WireGuard | WireGuard from Server 2 only |
| Network out | Server 1 over WireGuard | Server 2 API over WireGuard |
| Listeners | API `127.0.0.1:8000`, web `127.0.0.1:3210`; PostgreSQL and the VMS worker have no port | bridge and Threat Insights on the WireGuard address only |

## 2. Server 2: files outside the repository

Nothing secret is committed. Every secret is generated on the server, and the templates in `deploy/server2/` hold
only placeholders.

| Path | Owner : mode | Content | Template |
|---|---|---|---|
| `/opt/novrsoc-v2/` | root : 0755 | the reviewed release | — |
| `/opt/novrsoc-v2/deploy/server2/.env` | root : 0600 | image tag, config and backup directories, loopback binds, app subnet (no secrets) | `compose.env.example` |
| `/etc/novrsoc-v2/api.env` | root : 0600 | API settings and the application-role database URL | `api.env.example` |
| `/etc/novrsoc-v2/migrate.env` | root : 0600 | schema-owner database URL | `migrate.env.example` |
| `/etc/novrsoc-v2/backup.env` | root : 0600 | backup and restore-drill URLs | `backup.env.example` |
| `/etc/novrsoc-v2/secrets/pg_superuser_password`, `pg_owner_password`, `pg_app_password` | 70:70 : 0400 | random, ≥ 24 characters each | — |
| `/etc/novrsoc-v2/files/backup.key` | 10001:10001 : 0400 | 32 random bytes, base64; keep an offline copy | — |
| `/etc/novrsoc-v2/files/server2-soar.key`, `bridge-ca.pem` | 10001:10001 : 0400 | only for gate G-S1 | — |
| `/etc/novrsoc-v2/vms/<org-slug>.token` | 10002:10002 : 0400 (directory 0500) | one `vms_worker` credential per organization; only for gate G-B | — |
| `/var/backups/novrsoc-v2/` | 10001:10001 : 0700 | encrypted backups; copy them off the host | — |
| `/etc/nginx/sites-available/novrsoc` | root : 0644 | TLS, same-origin proxy, machine routes limited to WireGuard | `nginx-novrsoc.conf` |
| `/etc/systemd/system/novrsoc-backup.{service,timer}` | root : 0644 | nightly encrypted backup | same names |

Generate the secrets on the server, never in a shell argument or a chat:

```sh
umask 077; install -d -m 0700 /etc/novrsoc-v2/secrets /etc/novrsoc-v2/files
for f in pg_superuser_password pg_owner_password pg_app_password; do
  openssl rand -base64 36 | tr -d '/+=\n' > /etc/novrsoc-v2/secrets/$f
done
chown 70:70 /etc/novrsoc-v2/secrets/*; chmod 0400 /etc/novrsoc-v2/secrets/*
openssl rand -base64 32 > /etc/novrsoc-v2/files/backup.key
chown -R 10001:10001 /etc/novrsoc-v2/files; chmod 0400 /etc/novrsoc-v2/files/*
# then fill the <pg_*_password> placeholders in api.env, migrate.env and backup.env with an editor
```

## 3. Server 2: first installation

Each step is verified before the next one starts.

| # | Step | Verify |
|---|---|---|
| 1 | Take a provider snapshot of the host | snapshot id recorded |
| 2 | Install Docker Engine with the Compose plugin, NGINX and certbot | `docker compose version` ≥ 2.24 |
| 3 | On the release workstation, run `python scripts/release/preflight.py` on the reviewed release; copy that release to `/opt/novrsoc-v2` | every check `PASS` |
| 4 | Build the images from the repository root: `docker build -f deploy/docker/api.Dockerfile -t novrsoc-api:<tag> .`, and the same with `web.Dockerfile` for `novrsoc-web:<tag>` and `vms-worker.Dockerfile` for `novrsoc-vms-worker:<tag>` | three image ids recorded |
| 5 | Create `/etc/novrsoc-v2/` from the templates and generate the secrets (§2) | modes as listed; `grep -c '<' /etc/novrsoc-v2/*.env` prints 0 for each file |
| 6 | `cd /opt/novrsoc-v2/deploy/server2 && cp compose.env.example .env`; set `NOVRSOC_IMAGE_TAG`; `docker compose config -q` | exit 0 |
| 7 | `docker compose up -d --wait` | postgres, api, jobs and web are `healthy`; migrate `exited (0)`; every `check-env` line in `docker compose logs api` is OK |
| 8 | Install the NGINX site with a real certificate; `nginx -t`; reload | `https://<host>/login` loads; `/api/docs` returns 404 |
| 9 | Create the first administrator (§4) | a second run is refused |
| 10 | Install and start `novrsoc-backup.timer`; run one restore drill (§5) | backup and drill `succeeded` |
| 11 | Run the security checks (§7) | every check passes; **gate G-0 signed** |

Compose start order: `postgres` (healthy) → `migrate` (`alembic upgrade head`, once, as the schema owner) → `api`
(`check-env` must pass first) → `jobs` and `web`. The `backup`, `restore-drill` and `operator` services run on demand
under the `ops` profile. `vms-worker` starts only under the `vms` profile, at gate G-B (§6).

### VMS worker (gate G-B)

| Property | Value |
|---|---|
| Image | `novrsoc-vms-worker:<tag>`: Python 3.12, `services/vms-worker/requirements.lock`; uid 10002; no scanning tool (no nmap, nuclei or python-gvm) |
| Network | `vms` only (internal: no route out). It reaches `api:8000` and nothing else: no database, no web, no internet, no client network |
| Engine | `VMS_ENGINE=disabled`: heartbeat only, no job is ever claimed. The API also refuses scans while `NOVRSOC_VMS_SCANNING=disabled` |
| Scope | the API checks every target against the organization's approved scope when a scan is requested, at claim, and for every observation at ingest |
| Identity | one organization-bound `vms_worker` machine identity (scope `vms:worker`) per organization, one token file each |
| NGINX | `/api/v1/vms/worker/` is refused from outside (403); the worker never goes through NGINX |
| Hardening | read-only root, all capabilities dropped, no-new-privileges, 256 MiB, 64 processes, no published port |

```sh
cd /opt/novrsoc-v2/deploy/server2
install -d -o 10002 -g 10002 -m 0500 /etc/novrsoc-v2/vms
install -d -o 10001 -m 0700 /root/novrsoc-issued
docker compose --profile ops run --rm -v /root/novrsoc-issued:/out operator create-service-identity \
  --kind vms_worker --name server2-vms-worker --org-slug <org-slug> --scope vms:worker --out /out/<org-slug>.token
install -o 10002 -g 10002 -m 0400 /root/novrsoc-issued/<org-slug>.token /etc/novrsoc-v2/vms/<org-slug>.token
shred -u /root/novrsoc-issued/<org-slug>.token        # repeat the two steps above for each organization
docker compose --profile vms up -d vms-worker
```

Verify: **Vulnerability management → VMS overview** lists the worker's heartbeat for each organization with the engine
`disabled`, and no scan job leaves the queue. To revoke a worker, run `operator revoke-service-identity` and delete
its token file.

Enabling real scanning is a separate decision. It needs:

- a production scanning mode in the API;
- a scanning engine, and egress for the worker;
- per-organization scope approvals;
- scan windows.

None of these exist yet.

## 4. First administrator

Migrations seed only the role and permission catalogues: no organization, user, plan, playbook or security record.
The development seed commands refuse to run when `NOVRSOC_ENV=production`.

```sh
install -d -o 10001 -m 0700 /root/novrsoc-bootstrap
docker compose --profile ops run --rm -v /root/novrsoc-bootstrap:/out operator \
  bootstrap-platform --email <administrator e-mail> --out /out/first-admin.txt
```

This creates the platform organization and one `super_admin`. The one-time password is written only to that file.

1. Sign in with it. A password change is forced before anything else is allowed.
2. Delete the file.
3. Create client organizations and users under **Clients & Admin**.

The audit log records `PLATFORM_BOOTSTRAPPED` and `PASSWORD_CHANGED`. The command refuses to run a second time.

### Onboarding a client organization

Do every step in **Clients and administration → Organizations**, as a platform administrator. Nothing is pre-loaded,
and no organization is assumed.

1. **New organization:** enter the name, a permanent slug, the contact and the time zone. Open it; the Overview
   lists the onboarding steps, and each step opens the tab where it is configured.
2. **Integrations → Wazuh agent groups:** map the client's groups.
   - A group belongs to one organization at a time.
   - Mapping `default` needs the acknowledgement shown on screen, because every agent is in `default` until it is
     moved.
   - An agent whose groups map to two organizations is quarantined, not guessed.
3. **Integrations → Syslog and agentless sources:** register each device that sends syslog to the Wazuh manager.
   Record its name, its source IP as the manager receives it, its device type, vendor, protocol and port, its site
   and network, and the client's authorization reference.
   - Events from an unregistered or disabled source are quarantined.
   - The manager's own events are always quarantined.
4. **Assets → Sync Wazuh agents now:** reconciles the agents into the client's inventory. The endpoints table shows
   their Wazuh status.
5. **Users and teams:** assign existing analysts to the organization. Use **Create account** only for people who
   have no account yet.
6. **Check the quarantine:** **Organizations → Quarantined events** lists unmapped groups and unattributed sources.
   An entry that belongs to the client means a mapping or a registration is missing.

The Wazuh manager must accept the device's syslog itself, in a `<remote>` block of type `syslog` that allows the
device's address. NovrSOC never changes the Wazuh configuration.

## 5. Backups, upgrades and migrations

**Backups**

- The timer runs `docker compose --profile ops run --rm backup` nightly. Each backup is encrypted with
  `backup.key`.
- To check a backup, run `docker compose --profile ops run --rm restore-drill --file /backups/<file> --key-file
  /run/novrsoc/backup.key`. It restores into a disposable database and checks it.
- Copy the encrypted files off the host and record their SHA-256.

**Upgrades**

1. Take a fresh backup.
2. Build the new tag and set `NOVRSOC_IMAGE_TAG`.
3. Run `docker compose up -d --wait`. The API refuses to start unless the schema is at the head its image ships.
4. Keep the previous images until the release is accepted.

**Upgrading an existing installation to migration 0016 (`novrsoc_nhai` role)**

Migration 0016 grants privileges to the `novrsoc_nhai` role. A role is a cluster object that the schema owner cannot
create, and initdb scripts never rerun on an existing volume. So an installation at 0015 creates the role once with the
idempotent `postgres-init/02-nhai-role.sh` before it migrates. Without the role, 0016 is refused with
`role novrsoc_nhai is missing`, and the database stays at 0015, unchanged.

Nothing in this procedure deletes or rewrites data. It keeps users, password hashes, organizations, memberships,
machine credentials and history. The role is created NOLOGIN, and no password is set.

```sh
cd /opt/novrsoc-v2/deploy/server2              # the new release is in place; postgres keeps running
# 0. Record the starting point
docker compose exec -T postgres sh -c 'PGPASSWORD=$(cat /run/secrets/pg_superuser_password) psql -U postgres -d novrsoc -tAc "SELECT version_num FROM novrsoc.alembic_version"'
#    expected: 0015_admin_exports_chat
# 1. Fresh encrypted backup, checked by a restore drill; copy it off the host (and take a provider snapshot)
docker compose --profile ops run --rm backup
docker compose --profile ops run --rm restore-drill --file /backups/<newest file>
# 2. Build the new images under a new tag (keep the current ones for rollback)
for i in api web vms-worker; do docker build -f ../docker/$i.Dockerfile -t novrsoc-$i:<new tag> ../..; done
# 3. Create the role (idempotent; postgres mounts postgres-init/ read-only, so the new script is already visible)
docker compose exec -T postgres sh /docker-entrypoint-initdb.d/02-nhai-role.sh
#    expected: "created role novrsoc_nhai (NOLOGIN)", then  novrsoc_nhai | f | f | f
# 4. Switch the tag and start: migrate applies 0016, then api (check-env), jobs and web are recreated.
#    postgres and its volume are not recreated. The VMS worker stays off (profile vms, gate G-B).
sed -i 's/^NOVRSOC_IMAGE_TAG=.*/NOVRSOC_IMAGE_TAG=<new tag>/' .env
docker compose up -d --wait
# 5. Verify
docker compose logs migrate | tail -3                      # ... Running upgrade 0015_admin_exports_chat -> 0016_nhai_worker_role
docker compose logs api | grep -E 'OK +database'           # migration 0016_nhai_worker_role (expected 0016_nhai_worker_role)
curl -s http://127.0.0.1:8000/readyz                       # "ready"
```

Then sign in with an existing account and check that the organizations and users are as before. Update the host NGINX
site from `nginx-novrsoc.conf`, which now refuses `/api/v1/vms/worker/` from outside. Test it with `nginx -t`, then
reload.

To roll back, use the NEW image, because only it knows 0016:

1. Run `docker compose run --rm migrate alembic downgrade 0015_admin_exports_chat`. This revokes the 0016 grants and
   leaves the data unchanged.
2. Set `NOVRSOC_IMAGE_TAG` back to the previous tag, and run `docker compose up -d --wait`.

The NOLOGIN role can stay; it holds no table privileges.

`scripts/release/rehearse_server2.sh` rehearses this exact sequence on a throwaway installation:

- it brings the schema to 0015 with data and drops the role;
- it checks that the migration is refused;
- it runs `02-nhai-role.sh` twice, to show it is idempotent;
- it upgrades;
- it compares fingerprints of users, password hashes, organizations, memberships, machine credentials and audit
  history.

**Upgrading to migration 0017 (organization management, log sources)**

There is no manual step beyond the usual backup: `docker compose up -d --wait` applies it.

- Existing organizations stay `active` and keep their data. Their new profile fields start empty.
- Existing alerts are unchanged.
- From then on, events received by the Wazuh manager itself (agent `000`) are attributed only through registered
  sources. Before, they could match a group mapping. Register the client's syslog devices right after the upgrade,
  and check **Quarantined events** for any sender that is still unregistered.

Rollback: `alembic downgrade 0016_nhai_worker_role`. This removes the log sources and their alert links, and the
quarantine entries with the new reasons. It also turns any archived organization back into a suspended one.

**Migrations**

- They are additive and reversible.
- They run only as the schema owner, never as the API role.
- Every downgrade is exercised in the test suite.

## 6. Server 1 and approval gates

Server 1 keeps its existing Python/systemd environment; NovrSOC adds no container runtime there. Each service has a
hardened unit and a configuration template:

| Service | Unit | Configuration | Runtime |
|---|---|---|---|
| Alert forwarder | `services/edge/forwarder/deploy/novrsoc-forwarder.service` | `/etc/novrsoc-forwarder/forwarder.env` | system `python3`, standard library |
| Threat Insights (TAXII 2.1 / STIX 2.1) | `deploy/server1/novrsoc-ti.service` | `/etc/novrsoc-ti/config.json` (`ti-config.json.example`, every source disabled) | system `python3`, standard library plus `packages/contracts/python` on `PYTHONPATH` |
| Response bridge | `deploy/server1/novrsoc-response-bridge.service` | `/etc/novrsoc-bridge/bridge.json` (`bridge.json.example`: simulated adapter, `allow_live: false`) | system `python3`, standard library |
| NHAI worker | `deploy/server1/novrsoc-nhai-worker.service` | `/etc/novrsoc-nhai/nhai-worker.env` (database role `novrsoc_nhai`) | `/opt/novrsoc-v2/apps/api/.venv` (Python 3.12, `requirements.runtime.lock`) |

Each unit runs as its own system user with `NoNewPrivileges` and `ProtectSystem=strict`. NovrSOC never changes the
Wazuh configuration.

Gates are signed in this order. Each one is rolled back by disabling its unit, revoking its machine identity, or
setting its API variable back to `unconfigured`.

| Gate | Enables | Preconditions |
|---|---|---|
| G-0 | Server 2 base (§3) | preflight passed; secrets generated |
| G-C1 | read-only Wazuh connectors (`NOVRSOC_WAZUH_MODE=live`) | read-only Wazuh accounts; WireGuard path from Server 2 to Server 1 only |
| G-A1 | Wazuh group → organization mappings | every client's groups map to exactly one organization |
| G-A2 | alert forwarder | G-C1, G-A1; one `forwarder` machine identity |
| G-F1 | Threat Insights indicator import | G-A2 |
| G-T1 | TAXII service on Server 1, one vetted source | G-F1; one `ti_feeder` identity per subscribing organization |
| G-S1 | response bridge with the **simulated** adapter | bridge key and TLS on WireGuard; tenant map mirrors each SOAR policy; a cross-tenant request is refused |
| G-S2 | live Wazuh active response | a separate approval after G-S1; one designated non-production agent; the owner present |
| G-F2 | NHAI worker | the `novrsoc_nhai` role (created NOLOGIN; grants from migration 0016) given a password and a `hostssl` rule for the Server 1 WireGuard address only; a TLS listener for it on the WireGuard address; an evaluation set reviewed by analysts |
| G-B | VMS worker on Server 2 (`vms` profile), heartbeat only | one `vms_worker` identity per organization (§3); production scanning stays `disabled` |
| G-N | CNII monitoring of a designated asset | a recorded authorization with reference, scope and validity, approved by a second person |

Live scanning, live response and AI-initiated actions stay disabled until their gate is signed. See
[`SOAR_POLICY.md`](SOAR_POLICY.md).

## 7. Security checks

**Before each release**

Run `python scripts/release/preflight.py`. It checks:

- the publication allowlist and a secret scan of exactly the published files;
- Compose hardening: loopback-only ports, no privileged containers, no Docker socket, read-only roots, dropped
  capabilities, digest-pinned images;
- that the templates hold only placeholders;
- that the Dockerfiles are pinned and run as non-root;
- the runtime dependency lock;
- the absence of hosted-platform dependencies.

**After each deployment**

| Check | Command | Expected |
|---|---|---|
| Listeners | `ss -ltnp` | public: 80, 443, SSH, WireGuard only; 8000 and 3210 on loopback |
| Containers | `docker inspect --format '{{.Name}} {{.Config.User}} {{.HostConfig.ReadonlyRootfs}}' $(docker compose ps -q)` | non-root and read-only (PostgreSQL: writable data only) |
| Database network | `docker network inspect novrsoc_db --format '{{.Internal}}'` | `true` |
| Readiness | `curl -s http://127.0.0.1:8000/readyz` | `ready`, migrations at head |
| API docs | `curl -so /dev/null -w '%{http_code}' https://<host>/api/docs` | 404 |
| Machine routes | `curl https://<host>/api/v1/soc/ingest/alerts` and `/api/v1/vms/worker/heartbeat`, run from a public address | 403 from NGINX |
| VMS isolation | `docker network inspect novrsoc_vms --format '{{.Internal}}'` | `true` |
| Honest states | **Clients & Admin → Platform Health** | every connector reads `unconfigured` until its gate is signed |

## 8. Rollback

| What | How |
|---|---|
| Application, same schema | set `NOVRSOC_IMAGE_TAG` to the previous tag; `docker compose up -d --wait` |
| Across a migration | take a backup; `docker compose run --rm migrate alembic downgrade <previous head>`; then deploy the previous tag. Or restore the pre-upgrade backup into a fresh volume |
| A Server 1 service | `systemctl disable --now <unit>`; revoke its machine identity; set the API variable to `unconfigured` |
| Whole host | the provider snapshot from step 1 |
