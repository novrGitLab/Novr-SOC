# VMS worker

The VMS worker carries out vulnerability scans for the Vulnerability Management module.

- **Production:** it runs on Server 2 as the Compose service `vms-worker`, under the `vms` profile, from its own
  image (`deploy/docker/vms-worker.Dockerfile`). Its only network is internal and reaches the API alone: no
  database, no internet, no client network.
- **Development:** it runs on any local host.

It authenticates with one `vms_worker` machine identity per organization, read from a token file.

**Production scanning is disabled until gate G-B2.**

- The image defaults to `VMS_ENGINE=disabled`: heartbeat only, and no job is ever claimed.
- The default image contains no scanning tool: no nmap, no nuclei, no python-gvm. The separate scanner image
  (`deploy/docker/vms-scanner.Dockerfile`) adds nmap only, and still defaults to `disabled`.
- The API refuses scans while `NOVRSOC_VMS_SCANNING=disabled`. `local_test_targets` is refused outside development and
  test. `authorized_scopes` is the production mode: scans run only inside scopes the organization approved, under its
  **enabled scan policy**.

**Where a production scanner runs is a deployment decision, not a default.** The Server 2 container reaches only the
API, by design, so it cannot scan a client network. A scanner needs a host with a route to the client network it
scans, for example a host on that network or one connected to it over a VPN, declared in `VMS_ALLOWED_NETWORKS`.
Private address ranges overlap between clients, so a scanner scans only the networks it declares, for the
organizations whose credentials it holds.

## Files

| File | Purpose |
|---|---|
| `v2_adapter.py` | Speaks the V2 worker protocol: heartbeat, claim, results, finish. It reads one token per organization, from `NOVRSOC_VMS_TOKEN_DIR` or `NOVRSOC_VMS_TOKEN_FILE`. |
| `v2-adapter.env.example` | Development settings: placeholders only. |
| `worker.py` | Scanner engine and Greenbone GMP report parser, which the adapter reuses. |
| `requirements.txt`, `requirements.lock` | The supported range, and the exact versions the image ships. |
| `test_*.py`, `fixtures/` | Offline tests. They scan nothing. |

## Engines

| Engine | What it does |
|---|---|
| `disabled` | The default. Heartbeat only. |
| `tcp_connect` | Development only. Tries a TCP connection to a fixed list of ports on loopback targets, and sends no payload. |
| `greenbone_report` | Development only. Replays a Greenbone report file through the tested parser, and labels the results as a replay. |
| `nmap_service` | Production (gate G-B2). Runs `nmap -sT -sV`, the `ports` activity only: a TCP connect scan with service and version detection. It uses no raw packets, no scripts and no exploits. Results go through the tested 1.8.x parsers. It reports exposed services and versions, and per-target outcomes (`completed`, `unreachable`, `no_route`, `refused_out_of_scope`, `failed`). It does not claim vulnerabilities. |

Both development engines accept **only** loopback addresses and `*.test` and `*.localhost` names, and they check
the target again before touching it.

`nmap_service` gives nmap a target only if two conditions hold:

- the target, and every address a name resolves to, lies inside `VMS_ALLOWED_NETWORKS`;
- it lies outside the job's protected networks (the organization's scan policy).

nmap gets the checked address, never the name, so a second DNS lookup can't redirect it. The packet rate is the lower
of the policy's ceiling and `VMS_NMAP_MAX_RATE`.

Plain http is accepted only in two cases:

- to a loopback API;
- with `NOVRSOC_API_TRANSPORT=compose-internal`, to a single-label Compose service name such as `api`.

## Scope and policy

The API checks every target against the organization's approved scope:

- when a scan is requested;
- when the worker claims the job;
- for every observation at ingest.

In `authorized_scopes` mode, it also enforces the organization's scan policy:

- the policy must be enabled;
- targets must lie outside protected networks;
- a cap on targets per scan;
- weekly scan windows, checked at claim;
- a concurrency cap;
- a packet-rate ceiling, handed to the worker.

Imported assets enroll automatically only when all of these hold:

- the address is private;
- it was reported recently;
- it is unique in the organization;
- it comes from a monitoring source;
- it lies inside an approved scope.

Public, shared and stale addresses are listed with the reason and never scanned from telemetry.

Findings are deduplicated into the organization's asset inventory.

## Run (development)

```sh
pip install -r requirements.txt
set -a; . ./v2-adapter.env; set +a
python v2_adapter.py --once     # one cycle per organization credential
python -m unittest test_worker test_greenbone test_openvas_report test_v2_adapter test_nmap_engine
```

Production installation (identities, token files, profile) is gate G-B in
[`docs/public/DEPLOYMENT.md`](../../docs/public/DEPLOYMENT.md).

Enabling real scanning is gate G-B2, a separate approval. It needs:

- `NOVRSOC_VMS_SCANNING=authorized_scopes` on the API;
- a scanner host with a route to the client network, running the scanner image with `VMS_ENGINE=nmap_service` and
  `VMS_ALLOWED_NETWORKS`;
- the organization's approved scope and enabled scan policy;
- a supervised first scan of a single host.
