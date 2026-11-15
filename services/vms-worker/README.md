# VMS worker

The VMS worker carries out vulnerability scans for the Vulnerability Management module.

- **Production:** it runs on Server 2 as the Compose service `vms-worker`, under the `vms` profile, from its own
  image (`deploy/docker/vms-worker.Dockerfile`). Its only network is internal and reaches the API alone: no
  database, no internet, no client network.
- **Development:** it runs on any local host.

It authenticates with one `vms_worker` machine identity per organization, read from a token file.

**Production scanning is disabled.**

- The image defaults to `VMS_ENGINE=disabled`: heartbeat only, and no job is ever claimed.
- The image contains no scanning tool: no nmap, no nuclei, no python-gvm.
- The API refuses scans while `NOVRSOC_VMS_SCANNING=disabled`. Its only other mode, `local_test_targets`, is refused
  outside development and test.

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

Both development engines accept **only** loopback addresses and `*.test` and `*.localhost` names, and they check
the target again before touching it.

Plain http is accepted only in two cases:

- to a loopback API;
- with `NOVRSOC_API_TRANSPORT=compose-internal`, to a single-label Compose service name such as `api`.

## Scope

The API checks every target against the organization's approved scope:

- when a scan is requested;
- when the worker claims the job;
- for every observation at ingest.

Findings are deduplicated into the organization's asset inventory.

## Run (development)

```sh
pip install -r requirements.txt
set -a; . ./v2-adapter.env; set +a
python v2_adapter.py --once     # one cycle per organization credential
python -m unittest test_worker test_greenbone test_openvas_report test_v2_adapter
```

Production installation (identities, token files, profile) is gate G-B in
[`docs/public/DEPLOYMENT.md`](../../docs/public/DEPLOYMENT.md).

Enabling real scanning is a separate approval. It needs:

- a production scanning mode in the API;
- a scanning engine, and egress for the worker;
- per-organization scope approvals;
- scan windows.
