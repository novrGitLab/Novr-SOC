# services/edge: Server 1 services

Small services for the security host. Each runs under its own systemd unit, and none of them is installed by
default.

| Service | What it does | Gate |
|---|---|---|
| [`forwarder/`](forwarder/) | Reads Wazuh alerts from the indexer and delivers them to the API. Forwarding only. | G-A2 |
| `threat_intel/` | TAXII 2.1 client and STIX 2.1 normalization; delivers indicators for one organization per source. | G-T1 |
| `response_bridge/` | Executes SOAR actions that are approved and signed (simulated adapter by default); returns signed receipts. | G-S1, G-S2 |

All three run on the system `python3` with the standard library and need no virtualenv. The Threat Insights feeder
also loads the dependency-free STIX validator from `packages/contracts/python` (its unit sets `PYTHONPATH`). Gates and
installation are described in
[`docs/public/DEPLOYMENT.md`](../../docs/public/DEPLOYMENT.md).

The forwarder ports only the forwarding functions of the legacy forwarder (NovrSOC@5054be3, @c0d7106). The legacy
automatic-containment engine is not part of NovrSOC.
