# Architecture

## Components

| Component | Path | Technology | Runs on |
|---|---|---|---|
| Web app | `apps/web` | Next.js (app router), TypeScript | Server 2 |
| API | `apps/api` | FastAPI, SQLAlchemy, Pydantic v2 | Server 2 |
| Jobs worker | `apps/api/app/jobs.py` | same image as the API | Server 2 |
| Database | `packages/db` (Alembic migrations) | PostgreSQL 16 with row-level security | Server 2 |
| Shared contracts | `packages/contracts` | Pydantic models → OpenAPI and JSON Schema → generated TypeScript | build time |
| Alert forwarder | `services/edge/forwarder` | Python standard library | Server 1 |
| Threat Insights feeder | `services/edge/threat_intel` | Python standard library, TAXII 2.1 / STIX 2.1 | Server 1 |
| Response bridge | `services/edge/response_bridge` | Python standard library | Server 1 |
| NHAI worker | `apps/api/app/nhai/worker.py` | API code, local model runtime; database role `novrsoc_nhai` (least privilege) | Server 1 |
| VMS worker | `services/vms-worker` | Python, own image; scanning disabled by default | Server 2 (`vms` profile, internal network to the API only) |

The jobs worker does the timed work:

- SLA escalation;
- scheduled VMS scans;
- CNII checks;
- approval expiry;
- asset linking;
- the platform heartbeat.

The browser talks only to the web origin. The web server proxies `/api/` to the API. Workers and edge services
authenticate with machine identities: tokens bound to one organization and one role, revocable, and shown once.

## Tenancy and authorization

- Every tenant table has `org_id NOT NULL` and a row-level security policy keyed on the request's active
  organization. The API's database role cannot bypass that policy.
- Permissions are checked in the API for every route. The interface hides what a role cannot do, but it is not the
  control.
- A machine caller's organization comes from its identity, never from its payload. An alert's organization comes
  from its Wazuh agent-group mapping.
- Cross-organization access by platform staff is explicit. It is recorded in the audit log.
- CNII monitoring needs a CNII designation for the user, as well as the permission. It also needs a recorded
  authorization for each monitored asset, checked on the server.

## Asset inventory

There is one inventory per organization (`assets`, `asset_identifiers`, `asset_services`, `asset_events`). Every
source reconciles into it:

- Wazuh agents;
- VMS targets and findings;
- email domains;
- brand-protection domains;
- CNII designations;
- manual entry.

Strong identifiers merge records: agent id, MAC address, cloud id, serial number, FQDN, domain, URL. Weak identifiers
(hostname, IP address scoped to a site) only suggest a match. A conflicting identifier is recorded as an event and
never moved silently. Alerts, VMS findings and cases link to assets.

## Security operations flow

```
Wazuh ─▶ forwarder ─▶ alerts ─▶ cases (SLA, assignment, notes) ─▶ SOAR run ─▶ approval ─▶ bridge ─▶ signed receipt
                         │                                    ▲
                         └─▶ Threat Insights matches ─────────┘   NHAI drafts (explanations, recommendations: never actions)
```

SOAR rules are in [`SOAR_POLICY.md`](SOAR_POLICY.md).

## NHAI and NovrChat

NHAI tasks are queued in the database and processed asynchronously by the worker:

- alert triage;
- finding explanation;
- asset summary;
- chat answer.

Each job carries an evidence bundle built only from the organization's own records. Each output is checked against
that bundle: statements without valid citations are dropped. The model's severity is advisory and never replaces the
authoritative severity; a proposal lower than it is flagged. The output is stored as a **draft** for human review.

NovrChat answers questions with read-only, permission-checked tools over the same records. Each answer cites the
records it used. NovrChat refuses requests to act.

Every AI request, result and review is written to an append-only AI activity log.

## Data honesty

A fresh installation holds only the role and permission catalogues. When a source is not connected, the interface
says so (`unconfigured`, `unavailable`, `not permitted`) instead of showing placeholder figures. Development fixtures
and test adapters label themselves and are refused outside development and test.

## Contracts

The v1 API is additive-only. `scripts/contracts/export.py` regenerates the OpenAPI and JSON Schema documents.
`scripts/contracts/compat.py` fails on any breaking change. The web app's TypeScript types are generated from the
same schema (`npm run api:types`).
