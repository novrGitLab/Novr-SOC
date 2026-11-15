## What and why

<!-- One paragraph: what changed and why. Link the related issue. -->

Workstream: <!-- A | B | C | D | E | F | G | platform -->

## Checklist (every item is a CI gate or a review rule)

- [ ] Changes to shared foundations (`.github/CODEOWNERS`, platform owner) were reviewed by the platform owner
- [ ] New endpoints live under `/api/v1/<module>` in `app/modules/<module>/` and use `require(...)` or `current_service`. No new public route
- [ ] Every new tenant table: `org_id NOT NULL`, RLS keyed on `novrsoc.app_org()`, grants to `novrsoc_app` only, plus an `assert_tenant_isolation` test
- [ ] Migration chained on the current single head, with a conventional id `NNNN_name`, and up/down both tested
- [ ] Contracts changed additively only (`scripts/contracts/compat.py` passes). `export.py` and `npm run api:types` re-run
- [ ] No live scans, no live response actions, no production hosts, no real credentials. External systems are faked in tests
- [ ] Machine callers authenticate with `nsk_` service identities; the organisation is never taken from a payload
- [ ] AI output is evidence-cited and stays a draft until human review; no AI-triggered action
- [ ] UI pages call the API only through `src/foundation/api/client.ts` and show honest states

## Tests

<!-- Commands run and results. CI must be green. -->
