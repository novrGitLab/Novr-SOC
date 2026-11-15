# Shared test fixtures

Fixtures used by more than one component, so producer and consumer stay in step.

| Fixture | Producer | Consumers | Origin |
|---|---|---|---|
| `vms/openvas-observations.json` | `services/vms-worker` Greenbone parser (`test_openvas_report.py --write-backend-fixture` regenerates it) | worker parity test; V2 VMS ingestion API tests (workstream B) | byte-identical copy of the legacy backend's parity fixture (NovrSOC@5054be3) |
