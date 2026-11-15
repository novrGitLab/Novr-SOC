# packages/contracts — shared, versioned contracts (v1)

**Status: v1 drafted for owner approval** (Phase 2.5 added `nhai` and `ai_gateway`, and moved AI inference out of `insights`). Pydantic v2 models are the single source. JSON Schema, OpenAPI and
TypeScript are generated from them.

| Module | Contents | Implemented in Phase 2? |
|---|---|---|
| `v1/common.py` | base classes (unknown fields rejected), error body, honest UI states, idempotency key, site-scoped address, actor/resource refs | used by the API |
| `v1/platform.py` | health, login/session, organisations, sites, audit events, service identity, CNII access check | **yes**: the API endpoints |
| `v1/collector.py` | enrollment, org-bound identity, site binding, capabilities, heartbeat, configuration, telemetry, rotation/revocation, scan connectivity, discovery | contract only (workstream C) |
| `v1/soar.py` | alert→case promotion, playbook execution, tasks, approvals (no self-approval), outcomes, retries, idempotency, audit actions; dry-run default | contract only (A) |
| `v1/vms.py` | asset identity and sources, Wazuh endpoint, SCA results, scope approvals and windows, scan jobs and results, findings lifecycle, risk score, remediation, verification | contract only (B, C) |
| `v1/insights.py` | threat insights (org-relevant only), behavioural signals (reserved) | contract only (F) |
| `v1/nhai.py` | **Novr Human-Assisted Intelligence**: alert explanation, behavioural summary, investigation assistance, case-note drafts, evidence citations, structured results, human review; org-scoped context | contract only (F); Phase 2.5 |
| `v1/ai_gateway.py` | AI Gateway: two lanes (general vs privileged security analysis), hashed revocable keys, quotas, model allowlists, usage events without prompt text | contract + tested enforcement core (`apps/api/app/ai_gateway`); no endpoint |
| `v1/protection.py` | Email Security, Brand Protection (persistent, org-owned) | contract only (D) |
| `v1/governance.py` | CNII designation, reporting, backup and restore drills | designation check implemented; rest contract only (E) |

Generated (do not edit; `scripts/contracts/export.py`):
- `openapi/novrsoc-api.v1.json`: the FastAPI HTTP API.
- `openapi/novrsoc-contracts.v1.json`: every contract model as OpenAPI components, with `x-novrsoc-direction`.
- `schemas/v1/<module>.schema.json`: JSON Schema 2020-12 per module.
- TypeScript: `apps/web/src/foundation/api/{schema,contracts}.gen.ts` (`npm run api:types`).

Invariants (tested in `tests/test_contracts.py`):
- Unknown fields are rejected.
- Machine-inbound contracts never carry an organisation.
- State-changing requests carry idempotency keys.
- Addresses are site-scoped.
- No self-approval.
- A dry run never reports success.
- Findings are verified only by evidence.
- An SCA score must match its counts.
- A CNII designation always expires.
- A restore only targets a disposable instance.
