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
  from an explicit attribution (see below), never from the alert.
- Machine identity kinds and the scopes each may hold are one definition shared by the API, the operator CLI, the
  contracts and the database: `forwarder` (platform organization only), `vms_worker`, `ti_feeder`, `collector`,
  `email_gateway`, `backup_agent`.
- Cross-organization access by platform staff is explicit. It is recorded in the audit log.
- CNII monitoring needs a CNII designation for the user, as well as the permission. It also needs a recorded
  authorization for each monitored asset, checked on the server.

## Event attribution

Every security event is stored under exactly one organization, or quarantined:

| Event | Attributed by | Quarantined when |
|---|---|---|
| From a Wazuh agent | The organization that maps the agent's groups, collection groups left out. A group maps to at most one organization. | No mapped group, groups of two organizations, or only collection groups (`collection_group_only`) |
| Received by the Wazuh manager itself (agent `000`): remote syslog | The live registration of the sender address that the manager records in `location` | The sender isn't registered, or its registration is disabled |
| Received by the Wazuh manager itself: agentless check | The live registration of the host configured on the manager | Same as remote syslog |
| The manager's own logs and modules | The platform organization (`NOVRSOC_MANAGER_EVENTS=platform`): they describe NovrSOC's own infrastructure, never a client | Only with `NOVRSOC_MANAGER_EVENTS=quarantine` |

Agent `000`'s groups and name are never used, and the hostname inside a syslog message is never trusted.

A source is registered to one organization at a time, across all organizations, with an authorization reference.
Moving it to another organization retires the old registration, which keeps its history and alert links, and only
later events go to the new organization.

Wazuh's `default` group contains every newly enrolled agent, of every organization. It is a **collection group**
(`NOVRSOC_WAZUH_COLLECTION_GROUPS`).

- It never establishes ownership, and it can't be mapped.
- A mapping left from an earlier release is ignored.
- It can't be named as a SOAR response target.

An agent in both `cybernovr` and `default` therefore belongs to the organization that maps `cybernovr`. An agent only
in `default` is quarantined until it is placed in its organization's group. `python -m app.cli attribution-audit` is a
read-only report of mappings and inconsistencies.

Quarantined events are visible to platform administrators, with the unmapped groups and unattributed sources.

## Command Center

Platform staff see every organization's alerts, assets, vulnerabilities, scans, cases, intelligence matches, NHAI
analyses, SOAR runs and approvals, and reports in one place (`/api/v1/command`).

- **How records are read.** For each organization in scope, the API switches the transaction's organization context
  and runs the query under that organization's row-level security. It labels each row with its owner, merges, and
  restores the caller's context. Nothing is copied, and there is no database function that unions tenants.
- **Who sees what.** Platform administrators (`platform:monitor`) see every organization. Platform SOC staff see their
  assigned organizations. Each view also needs its own permission, and export needs `exports:manage`.
- **Audit.** Every view and export is audited. CSV exports neutralize spreadsheet formulas.

## VMS scan policy and enrollment

An organization authorizes scanning once, with its **scan policy**, instead of approving each endpoint. The policy
records:

- an authorization reference;
- weekly windows;
- protected networks;
- caps on targets, packet rate and concurrency.

Assets imported from monitoring are enrolled automatically only when all of these hold:

- the address is private;
- it was reported within the age limit, because dynamic addresses move;
- it is unique in the organization;
- the asset comes from a source that establishes ownership;
- the address is inside an approved scope.

Public, carrier-NAT, shared and stale addresses are listed with the reason and never scanned from telemetry. A finding
on an address shared by two assets is linked to neither.

Production scanning (`authorized_scopes`) needs a scanner placed where it has a route to the client network. That is
an explicit deployment decision (gate G-B2).

## Organizations

A client organization is `active`, `suspended` or `archived`:

- **Suspended:** its members can't sign in, and nobody can switch to it.
- **Archived:** it must have no Wazuh mappings and no live sources first.

The directory and the onboarding progress are computed by the database from real configuration
(`novrsoc.org_directory()`, `novrsoc.org_onboarding()`). Analysts monitor several organizations through `operations`
assignments of their one account. Switching is audited.

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
