# NovrSOC V2 alert forwarder

Reads Wazuh alerts from the Wazuh indexer on Server 1 and delivers them to the NovrSOC API
(`POST /api/v1/soc/ingest/alerts`). **Forwarding only:** no containment, no case creation, no SOAR, no organization
decisions. Standard library only (Python 3.9+), so it runs with the system Python on Server 1.

Status: **built and tested locally; not installed anywhere.** Installing it is gate G-A2 of
[`docs/public/DEPLOYMENT.md`](../../../docs/public/DEPLOYMENT.md). The legacy forwarder on
Server 1 is stopped and backed up; this service does not start, stop, replace or read it.

## How it works

| Concern | Behaviour |
|---|---|
| Order and position | Alerts are read in the total order (`timestamp`, Wazuh alert `id`) with `search_after`. The checkpoint (`cursor.json`, legacy v2 format) is the position of the last alert of the last **acknowledged** page |
| Settle window | Only alerts at least `FORWARDER_SETTLE_SECONDS` old are read, so late-indexed alerts are still read in order |
| Late sweep | Every `FORWARDER_LATE_EVERY` cycles the `FORWARDER_OVERLAP_SECONDS` behind the checkpoint are re-sent (bounded pages). The API counts what it already has as duplicates. It never moves the checkpoint |
| Organization | Never sent. The forwarder sends each agent's Wazuh groups (read from the manager, cached 5 min, at most 1 h stale). The API maps groups to an organization with its own table; in live mode it re-reads the groups from the manager itself. Unmapped or ambiguous alerts are quarantined by the API |
| Batches | At most 100 alerts. The `batch_id` is a hash of the page's sort positions, so a replay carries the same id |
| Acknowledgement | Only `200` with the same `batch_id`, `durable: true` and `accepted + duplicates + quarantined = batch size` moves the checkpoint. A replay returns `replayed: true` with the original counts |
| Transient failures | Network, timeout, 429, 5xx, incomplete indexer answers (failed shards), stale groups: the cycle stops, nothing moves, the next attempt is after an exponential backoff with jitter (cap 300 s) |
| Permanent failures | 401/403 (credential revoked or wrong), 409 (batch_id conflict), unreadable `cursor.json`, invalid configuration: the service exits with code 78 and systemd does not restart it |
| Invalid alerts | Checked locally first (timestamp, rule level, agent id). A 422 from the API is bisected to isolate the invalid alerts. Both are written to `dead-letters.jsonl` (id and reason only, never content) and skipped |
| Credentials | A revocable `nsk_` identity (kind `forwarder`, platform organization, scope `alerts:ingest`) read from a file. Read-only indexer and manager users. TLS always verified, with an optional CA file per service |
| Logs | JSON lines on stdout (journald). Credentials are redacted; alert content is never logged |
| Single instance | An exclusive lock on the state directory |

## Tests

```bash
python -m unittest discover -s services/edge/forwarder/tests          # 20 tests, fakes only
apps/api/.venv/Scripts/python -m pytest apps/api/tests/modules/soc/test_forwarder_contract.py   # against the real API
```

## Install (only after approval G-A2)

1. Issue the credential on the API host: `python -m app.cli create-service-identity --kind forwarder --name server1-forwarder --scope alerts:ingest --out <file>` (written once to the `--out` file and never printed; move it to `/etc/novrsoc-forwarder/forwarder.token`, mode 0400, and delete the copy).
2. Create read-only Wazuh users (indexer: read on `wazuh-alerts-*`; manager API: `agents:read`).
3. Copy `novrsoc_forwarder/` to `/opt/novrsoc-forwarder/`, `deploy/forwarder.env.example` to `/etc/novrsoc-forwarder/forwarder.env` (fill names in), and the unit to `/etc/systemd/system/`.
4. Set `FORWARDER_START_AT` from the legacy cursor backup (its `last_forwarded_timestamp`), so the window between the legacy stop and the V2 start is covered; the API deduplicates anything already delivered.
5. `sudo -u novrsoc-forwarder env $(cat /etc/novrsoc-forwarder/forwarder.env | xargs) python3 -m novrsoc_forwarder --check` must print `check_ok`.
6. `systemctl enable --now novrsoc-forwarder`; follow `journalctl -u novrsoc-forwarder -f` for `page_acknowledged`.

## Recovery

| Situation | Action |
|---|---|
| Service stopped with exit 78, `reason` mentions the credential | Revoked or wrong token. Issue a new identity, replace the token file, `systemctl start`. The checkpoint is intact |
| Exit 78, `batch_id conflict` | Two forwarders or a restored old state. Stop all forwarders, keep one state directory, start one |
| Exit 78, `cursor.json is unreadable` | Restore `cursor.json` from backup, or write `{"version": 2, "last_forwarded_timestamp": "<ISO>"}` with the last known good time minus a margin; the API deduplicates the overlap |
| Re-deliver a time range | Stop the service, set `last_forwarded_timestamp` earlier (remove `search_after`), start. Duplicates are counted, nothing is stored twice |
| Many `cycle_retry` events | Check API reachability over WireGuard, indexer health, manager health. Nothing is lost while it retries: alerts stay in the indexer |
| Dead letters | Read `dead-letters.jsonl`; fix the cause; re-deliver the range as above |

## Rollback

`systemctl disable --now novrsoc-forwarder`. The V2 forwarder never modified the legacy forwarder or its cursor, so the
legacy service can be restored from its own backup if the owner decides to (not done automatically). Alerts already
delivered to V2 stay in V2; revoke the identity with `python -m app.cli revoke-service-identity --id <uuid>`.
