# VMS worker

The VMS worker carries out vulnerability scans for the Vulnerability Management module. It runs on a host the
platform owner operates, never on Server 1 or Server 2. It connects outbound to the API and authenticates with a
`vms_worker` machine identity, which is bound to one organization.

**Production scanning is disabled.** The API sets `NOVRSOC_VMS_SCANNING=disabled` and refuses scans in that mode.
The only other mode, `local_test_targets`, exists for development and test.

## Files

| File | Purpose |
|---|---|
| `v2_adapter.py` | Speaks the V2 worker protocol: heartbeat, claim, results, finish. It reads its token from a file. |
| `v2-adapter.env.example` | Adapter settings: placeholders only. |
| `worker.py` | Scanner engine and Greenbone GMP report parser, which the adapter reuses. |
| `test_*.py`, `fixtures/` | Offline tests. They scan nothing. |

The adapter has two engines. Both accept **only** loopback addresses and `*.test` and `*.localhost` names, and they
check the target again before they touch it.

- `tcp_connect` tries a TCP connection to a fixed list of ports. It sends no payload.
- `greenbone_report` replays a Greenbone report file through the tested parser. The results are labelled as a
  replay.

## Scope

The API checks every target against the organization's approved scope:

- before it queues a job;
- when the worker claims the job;
- when it stores the results.

Findings are deduplicated into the organization's asset inventory.

## Run (development)

```sh
pip install -r requirements.txt
set -a; . ./v2-adapter.env; set +a
python v2_adapter.py --once     # claim at most one job, run it, finish it
python -m pytest -q             # offline tests
```

Enabling the worker against real networks is a separate approval. It needs:

- a production scanning mode;
- per-organization scope approvals;
- scan windows.

See gate G-B in [`docs/public/DEPLOYMENT.md`](../../docs/public/DEPLOYMENT.md).
