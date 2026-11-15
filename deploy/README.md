# deploy

Deployment templates. No file here holds a secret: every secret value is a `<placeholder>` in an `*.example`
template, and it is generated on the server. The full procedure is in
[`docs/public/DEPLOYMENT.md`](../docs/public/DEPLOYMENT.md).

| Path | What it is |
|---|---|
| `docker/` | Two images. `api.Dockerfile` serves the API, migrations, the operator CLI and the jobs worker. `web.Dockerfile` is the Next.js standalone server. Both build from the repository root and use `.dockerignore`. |
| `server2/` | Application host. `compose.yaml` runs PostgreSQL 16, one-shot migrations, the API, the jobs worker and the web app; the backup, restore-drill and operator services are under the `ops` profile. Also here: database init, env templates, the host NGINX site, and the backup service and timer. Private configuration goes in `/etc/novrsoc-v2/`. |
| `server1/` | Security host, on the existing Python/systemd environment. systemd units and configuration templates for the Threat Insights service, the response bridge and the NHAI worker. The alert forwarder's unit is in `services/edge/forwarder/deploy/`. Wazuh and WireGuard are not managed here. |
| `dev/` | The disposable local development database: in-memory, on `127.0.0.1:55432`. |

The VMS worker runs on the owner's local host only, never on either server. There is no MISP and no hosted-platform
dependency. Before any release, run `python scripts/release/preflight.py`.
