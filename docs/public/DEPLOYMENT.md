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

- the production scanning mode in the API (`NOVRSOC_VMS_SCANNING=authorized_scopes`);
- a scanning engine with a declared route to the client networks (`nmap_service` for ports, or Greenbone below);
- per-organization scope approvals;
- each organization's enabled scan policy, with its windows and caps (migration 0018).

### Greenbone (NovrVMS vulnerability scanning, gate G-B)

Greenbone runs on Server 2 as its **own compose project** (`deploy/server2/greenbone/compose.yaml`), isolated from
NovrSOC's database and API. NovrVMS talks to it only through gvmd's GMP socket, as a dedicated Greenbone user.

| Property | Value |
|---|---|
| Stack | gvmd, its own PostgreSQL (`pg-gvm`) and Redis, ospd-openvas with notus-scanner, feed data. No web interface, no published port |
| Images | every image pinned by digest in `/etc/novrsoc-v2/greenbone.env` (compose refuses an unpinned one). The layout follows Greenbone Community Containers 22.4: check it against the release you pin |
| Networks | `gb_internal` (internal: no route out) for everything; only `ospd-openvas` also joins `gb_scan`, the one network with egress |
| NovrVMS bridge | compose service `vms-greenbone` (profile `greenbone`): the NovrVMS worker image, `vms` network only, the gvmd socket from `${NOVRSOC_GREENBONE_RUN_DIR}/gvmd-socket` and `openvas.conf` read-only |
| GMP client | `services/vms-worker/gmp.py`: standard library only (no python-gvm), one authenticated session per step |
| Scan safety | refused before any task exists unless the scan configuration has safe checks on and vhost expansion confirmed off (`expand_vhosts = no` is written by `configure-openvas`) |
| Load | per-service memory and CPU caps; the scanner limited to `GB_MAX_HOSTS` hosts and `GB_MAX_CHECKS` checks; one task at a time per worker, at most `VMS_GREENBONE_MAX_TARGETS` targets; platform caps in the API: `NOVRSOC_VMS_MAX_RUNNING_SCANS` (default 2) and `NOVRSOC_VMS_MAX_RUNNING_GREENBONE` (default 1) across every organization (migration 0023); results ingested in batches of 1000 |

1. **Host directories.** `install -d -m 0750 /srv/novrsoc-greenbone/gvmd-socket /srv/novrsoc-greenbone/openvas-conf`.
   The socket directory must be writable by gvmd's user in its image. The socket must be connectable by uid 10002
   (NovrVMS): give both a shared group, or start gvmd with a listen mode that allows the group. Check the pinned
   image's gvmd user and its `--listen-group` / `--listen-mode` options.
2. **Pin and start the stack.** Copy `greenbone.env.example` to `/etc/novrsoc-v2/greenbone.env`, pin every image,
   then `cd deploy/server2/greenbone && docker compose --env-file /etc/novrsoc-v2/greenbone.env up -d`. Wait until the
   feeds are loaded (gvmd's log reports the NVT and SCAP sync complete).
3. **Scanner egress.** In the `DOCKER-USER` chain, accept traffic from `GB_SCAN_SUBNET` only to the authorized client
   networks (over WireGuard), then drop everything else from it. Nothing else may be reachable from the scanner.
4. **Dedicated Greenbone user.**
   `docker compose --env-file /etc/novrsoc-v2/greenbone.env exec -u gvmd gvmd gvmd --create-user=novrsoc_vms`
   prints a generated password. Put it in `/etc/novrsoc-v2/vms-greenbone.env` (from `deploy/server2/vms-greenbone.env.example`;
   mode 0400, uid 10002) with `VMS_ALLOWED_NETWORKS`, the same networks as step 3. Never use the admin account.
5. **Verify, read-only.** In NovrSOC's `.env`, set `NOVRSOC_GREENBONE_RUN_DIR=/srv/novrsoc-greenbone` and leave
   `NOVRSOC_GREENBONE_ENGINE` unset (disabled). Then:
   `docker compose --profile greenbone run --rm vms-greenbone python v2_adapter.py --greenbone-check`
   must print `"ok": true`: authenticated, gvmd's version, every feed with its age, and `scan_config_safe: true`.
   It creates nothing and scans nothing.
6. **Enable.** Only after steps 1 to 5 pass and the owner approves the scanner host and its routes:
   - set `NOVRSOC_GREENBONE_ENGINE=greenbone_gmp` in `.env` and `NOVRSOC_VMS_SCANNING=authorized_scopes` in `api.env`;
   - `docker compose --profile greenbone up -d vms-greenbone`;
   - for each organization: a scope that allows `vuln_openvas`, and an enabled scan policy.
   The first scan of each organization should be a single, agreed target in its scan window. Check its job page:
   the per-target outcomes, the Greenbone task name `novrsoc-<job id>` in the detail, and the findings.

To stop scanning at once, either unset `NOVRSOC_GREENBONE_ENGINE` and recreate `vms-greenbone`, or disable the
organization's scan policy. A running Greenbone task is stopped and deleted by its job when it times out or fails.

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

**Upgrading to migration 0018 (VMS scan policy and enrollment, collection groups)**

This release changes how two kinds of alerts are attributed. Audit first, then upgrade:

1. Before the upgrade, on the running release, take the usual backup. Then run the read-only audit **with the new
   image** (it reads only; it opens a `READ ONLY` transaction):

   ```bash
   docker compose run --rm migrate python -m app.cli attribution-audit --days 7 > /root/attribution-audit.json
   ```

   It lists every group mapping, flags collection groups (`default`) that are mapped, the agents whose recent alerts
   carry **only** collection groups (with the organization that receives them today), agent ids seen under two
   organizations, registered sources, and quarantine by reason.
2. For every `agent_only_in_collection_groups` entry, move the agent into its organization's own group on the Wazuh
   manager **before** upgrading. Otherwise its alerts are quarantined (`collection_group_only`) after the upgrade,
   instead of being attributed by the `default` mapping.
3. `docker compose up -d --wait` applies 0018. There is no other manual step.
4. Remove each mapping of `default` from **Wazuh group mappings** once the audit shows no agent depends on it. A
   remaining mapping is shown as "collection group: ignored for attribution".

What changes:

- **Endpoint alerts.** A collection group (`NOVRSOC_WAZUH_COLLECTION_GROUPS`, default `default`) never establishes
  ownership. An agent in `cybernovr` and `default` belongs to the organization that maps `cybernovr`. Before, it was
  quarantined as ambiguous if `default` was mapped to another organization. An agent only in `default` is
  quarantined. A collection group can no longer be mapped, nor named as a SOAR response target.
- **Manager telemetry.** The Wazuh manager's own events (agent `000`, not a registered syslog or agentless source) are
  stored under the platform organization (`NOVRSOC_MANAGER_EVENTS=platform`). Before, they were quarantined. Set
  `quarantine` to keep the old behaviour. Unregistered or disabled syslog senders are still quarantined.
- **VMS scan policy.** Every organization gets a scan policy, disabled by default. Nothing is scanned until
  `NOVRSOC_VMS_SCANNING=authorized_scopes` **and** an organization enables its policy (gate G-B2).
- **NHAI worker grant.** `novrsoc_nhai` gains `SELECT (id, org_id)` on `cases`, for investigation assistance.

Rollback: `alembic downgrade 0017_org_management_log_sources`. This removes scan policies, enrollments, the scan-job
progress columns and `collection_group_only` quarantine entries, and revokes the cases grant. Then restore
`NOVRSOC_MANAGER_EVENTS=quarantine` behaviour by redeploying the previous image.

**Upgrading to migration 0019 (organization portals, invitations, onboarding)**

`docker compose up -d --wait` applies it, and nothing changes for existing users until a portal is switched on:

- Existing sessions keep working on the platform address.
- Existing log sources count as verified, because platform staff registered them.
- Existing agent group mappings stay as they are. The provisioned group is an additional one.

To serve organization portals:

1. **DNS.** Create a wildcard record `*.<portal base domain>` for Server 2.
2. **TLS.** Obtain a certificate that covers `<public hostname>` and `*.<portal base domain>`. Let's Encrypt issues
   wildcards through the DNS-01 challenge only.
3. **nginx.** Install the updated `nginx-novrsoc.conf`. Its default server drops every other host name.
4. **API settings.** Set `NOVRSOC_PLATFORM_HOSTS`, `NOVRSOC_PUBLIC_PLATFORM_HOST` and `NOVRSOC_PORTAL_BASE_DOMAIN` in
   `api.env`, then `docker compose up -d --wait`.
5. **Server-controlled agent enrollment** (optional, separate approval). NovrSOC registers every agent itself. No
   shared enrollment password and no self-chosen group decides which organization an agent belongs to:
   - On the NovrSIEM manager (Server 1), create a dedicated API user (for example `novrsoc_enroll`). Give it a role
     limited to `manager:read`, `group:read`, `group:create`, `agent:create`, `agent:modify_group` and `agent:delete`.
   - In `api.env`, set:
     - `NOVRSOC_ENROLLMENT_MODE=manager_api`;
     - `WAZUH_ENROLLMENT_URL`, `_USER`, `_PASSWORD` and `_CA_CERT`, reached over WireGuard;
     - `NOVRSOC_AGENT_MANAGER_ADDRESS`, the address endpoints use to reach the manager.
   - Check compatibility: the onboarding page shows the manager version the API read. Agents install that exact
     version by default. `NOVRSOC_AGENT_VERSION` may only pin an older version of the same major.
   - Switch off password enrollment on the manager (`<auth><disabled>yes</disabled></auth>` in `ossec.conf`, then
     restart the manager), once every existing agent is registered. Existing agents keep their keys. From then on,
     only NovrSOC can register an agent.
   - Provision each organization's agent group from its organization page. NovrSOC creates the group on the manager.
     Administrators then issue installer commands: each has an expiry and an endpoint limit, and can be revoked.
6. **Scheduled asset sync.** The `jobs` service now reaches the manager's read-only API over the `app` network.
   `NOVRSOC_ASSET_SYNC_INTERVAL_MINUTES` defaults to 60; 0 means on demand only. An organization's own
   `wazuh_sync` collector overrides the interval. Each run, and each failure, is recorded per organization and shown on
   its onboarding page.
7. **Enroll each organization.** A platform administrator:
   - creates or opens the organization in the Command Center;
   - sets its subdomain, branding and logo (Settings tab), then enables the portal;
   - provisions its agent group (Integrations tab);
   - invites its administrator (Users tab) and sends the one-time link through an approved channel.
8. **Rate limits.** Portal identity, invitations, installer downloads and enrollment are rate limited per client
   address, with counters shared in PostgreSQL by every API worker. They rely on uvicorn's trusted proxy headers
   (`FORWARDED_ALLOW_IPS`, already set in `compose.yaml`).

What switching a portal on changes:

- **Sign-in.** The organization's members sign in at its portal, and their platform-address sessions end.
- **Session binding.** A session works only at the address it was created on.
- **Senders.** A sender the organization registers stays disabled until a NovrSOC administrator verifies it (Verify,
  in the organization's Integrations tab).

Rollback: `alembic downgrade 0018_vms_policy_attribution`. This removes:

- portals and branding;
- invitations;
- session binding (every session then works at the platform address);
- the provisioned flag on agent group mappings (the mappings stay);
- sender verification.

Remove the wildcard `server_name` from nginx too.

**Upgrading to migration 0020 (NovrSOAR policy-driven orchestration)**

0020 adds the automation policy, run origin and confidence, policy authorizations, the exact bridge request of each
step, automation decisions, and an index on `alerts (org_id, received_at, id)`. Building that index locks alert writes
for the time it takes. On a large `alerts` table, apply 0020 in a quiet window. The forwarder retries, so no alert is
lost.

1. Back up as in step 1 of every upgrade, then `docker compose up -d --wait` applies 0020.
2. Automation is **off** for every organization after the upgrade. Existing runs become `manual`. Nothing else
   changes until a `soar:manage` holder switches it on (Response policy → Automation).
3. Before switching on pre-authorized actions, run the simulated procedure in `SOAR_POLICY.md` §12 with the bridge
   on `adapter: simulated` and `allow_live: false`. Live enforcement stays disabled until that procedure and the
   integration checks pass and the owner approves.
4. Protected targets: add at least the WireGuard network, both servers' public addresses and the office egress, the
   same networks as the bridge's `never_block`.

Rollback: `alembic downgrade 0019_org_portals_onboarding`. This removes automatic runs, their steps and policy
authorizations (the audit log keeps them), the automation decisions and settings, and the stored requests. Manual
runs and their approvals stay.

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

**Historical alert backfill** (`python -m novrsoc_forwarder.backfill`) is a one-off operator tool, separate from the live
forwarder: its own install directory, user, credential and state.

1. **Plan:** a read-only classification report of a past window, showing who would own each alert and what would be
   quarantined.
2. **Pilot:** a limited plan, for example 100 alerts.
3. **Full import:** an import of exactly an approved plan (`--approve <plan sha256>`), which stops if ownership changes
   in the meantime.

Rollback uses the import's ledger: `operator backfill-rollback`. It needs Server 2 to run a release with
`/api/v1/soc/ingest/classify`. Procedure: `services/edge/forwarder/README.md`, "Historical backfill".

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
| G-S1 | response bridge with the **simulated** adapter | bridge key and TLS on WireGuard; each tenant entry generated read-only from that organization's SOAR policy (`python -m app.cli soar-bridge-tenant --org <slug>`: its own mapped groups only, never a collection group); a cross-tenant request is refused |
| G-S2 | live Wazuh active response | a separate approval after G-S1; one designated non-production agent; the owner present |
| G-F2 | NHAI worker | the `novrsoc_nhai` role (created NOLOGIN; grants from migrations 0016 and 0018) given a password and a `hostssl` rule for the Server 1 WireGuard address only; a TLS listener for it on the WireGuard address; `python -m app.nhai.diagnose --db` reports `"ready": true` on Server 1; an evaluation set reviewed by analysts |
| G-B | VMS worker on Server 2 (`vms` profile), heartbeat only | one `vms_worker` identity per organization (§3); production scanning stays `disabled` |
| G-B2 | production scanning (`NOVRSOC_VMS_SCANNING=authorized_scopes`, engine `nmap_service`) | **a topology decision**: a scanner host with a route to the client network (the Server 2 container has none, by design), declared in `VMS_ALLOWED_NETWORKS`, image `vms-scanner.Dockerfile`; the organization's approved scope and **enabled scan policy** (authorization reference, windows, protected networks); one supervised first scan of a single host |
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
