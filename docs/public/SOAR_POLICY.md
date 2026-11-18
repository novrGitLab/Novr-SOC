# SOAR policy

NovrSOC's SOAR (Security Orchestration, Automation and Response) coordinates alerts, cases, playbooks, human
approvals and authorized response actions. This policy states what it may do. The API and the database enforce
every rule below; the interface only reflects them.

## 1. Authorization

A consequential action is one of `block_ip`, `isolate_agent` or `disable_account`. It runs only when all of these
hold:

1. **Approved playbook.** It is part of a playbook version with status `approved`. The version was validated, then
   approved by a `soar:manage` holder other than its author. The database refuses self-approval.
2. **Allow-listed action.** The organization's response policy allows the action.
3. **Target from the case's own evidence.** The target comes from the case's alerts: the source IP, the agent, or an
   account named in the alert. It is never typed in or inferred.
4. **Authorized agent group.** The endpoint's NovrAgent groups are in the policy's authorized groups.
5. **Not a protected target.** The target is not one of the organization's protected targets (addresses, networks,
   agent ids, accounts). This applies to automatic and human-approved steps alike, and is checked again at dispatch.
6. **Live-mode gates.** For live mode, both the playbook's execution policy and the organization's policy allow live
   execution.
7. **Authorization, one of two kinds:**
   - **Second-person approval.** A person with `response:approve`, other than the requester, approves the step before
     its approval expires.
   - **Pre-authorization** (automatic runs only, §11). The organization's automation policy pre-authorizes the action;
     the detection confidence reaches its threshold; the hourly automatic dispatch limit is not reached. The engine
     records a policy authorization (`auth_kind = policy`) for the step instead of a person's approval.
8. **Bridge authorization.** The Server 1 execution bridge authorizes the organization, action and target
   independently. It executes at most once per request id and returns a signed receipt.

Non-consequential steps run in the engine:

- indicator enrichment from Threat Insights;
- case tasks.

Notification steps report `skipped_not_configured` until an adapter exists.

## 2. Tenant isolation

Every playbook, policy, run, step, approval and AI activity record belongs to one organization. Row-level security
keyed on the active organization stops the API from reading or changing another organization's records. A run can
use only its own organization's playbooks and cases. The bridge's tenant map refuses unknown organizations.

## 3. Permitted and prohibited actions

**Permitted:**

- The three consequential actions above, under the conditions in §1.
- Enrichment.
- Case tasks.

**Prohibited:**

- Any action not in the action list.
- Any target that is not in the case's evidence.
- Any execution without a person's approval or a recorded pre-authorization.
- Any action on a protected target.
- Self-approval.
- Execution from an AI result.
- Execution when the emergency stop is on.
- Any change to Wazuh configuration.
- Scans.
- Any action on third-party infrastructure.

## 4. Human approval

Approvals record the requester, decider, reason, decision time and expiry. Expired approvals expire their step: the
jobs worker settles them every minute. On approval, the target and the policy are checked again before dispatch.

## 5. Emergency stop

A `soar:manage` holder can turn the emergency stop on or off; a reason is required and the change is audited. While
it is on:

- no run starts;
- no approval that would dispatch is accepted;
- no step is re-dispatched.

Staff are notified when the stop is turned on.

## 6. Execution limits

| Limit | Set by | Default |
|---|---|---|
| Runs per hour | organization | 20 |
| Dispatch attempts per step | organization | 3 |
| Allowed modes (dry run, live) | each playbook version | dry run only |
| Minimum case severity | each playbook version | low |
| Runs per day | each playbook version | 20 |

## 7. Retries

A dispatch whose receipt did not arrive can be re-sent with the same request id; the bridge executes at most once.
After the dispatch attempt limit is reached, the step fails.

## 8. Rollback

NovrSOC does not reverse actions automatically. A reversal is a separate, explicitly approved action through the
same path. Every receipt states what was done, so a person can undo it. Configuration is versioned, so playbooks and
policies can be rolled back:

- approving a playbook version retires the previous one;
- retiring a version stops it from running;
- policy changes are audited with their full content.

## 9. AI

NHAI produces drafts: explanations, recommendations and proposed actions. Every recommendation carries
`requires_human_approval: true` and `executes_automatically: false`.

**AI never authorizes, approves or executes an action.** Every AI request, result, failure, recommendation, proposed
action and review is recorded append-only in the AI activity log. The SOAR operations centre labels these entries as
analysis, separately from execution.

## 10. Auditability

Every state change writes an audit event. The audit log and the AI activity log are append-only, including for the
schema owner. Covered events include:

- run requested;
- approval requested;
- approval decided;
- step executed, with its receipt;
- live mode refused;
- run refused;
- emergency stop changes;
- playbook saved, validated, submitted, approved, rejected or retired;
- self-approval refused;
- policy updated.

## 11. Policy-driven orchestration

Automation is off by default and is switched on per organization by a `soar:manage` holder (audited as
`SOAR_AUTOMATION_CHANGED`). It runs in the jobs worker, every minute, inside each organization's own transaction.
Only alerts received **after** it was switched on are considered; historical alerts are never acted on.

For each new alert, in order:

1. **Detection confidence** (deterministic, no model): base by rule level (level 13 and above: 75; 12: 70; 10 to 11:
   60; 7 to 9: 45; below 7: 30), plus a quarter of the best Threat Insights match confidence, plus 10 when the same
   rule fired on the same agent at least twice in the hour before. Capped at 100. The factors are recorded.
2. **Automatic case.** When case creation is on and the alert is at or above the configured severity, or when an
   automatic playbook matches: the alert joins the open automation case of the same agent and rule from the last 24
   hours, or a new case is opened with the organization's SLA policy.
3. **Automatic run.** Each approved, enabled playbook version marked `automatic` whose triggers match starts a run,
   under the same gate as a person: emergency stop, allowed mode, minimum case severity, runs per hour and per day.
   The mode is live only when both the playbook and the organization's policy allow live mode; otherwise dry run.
4. **Consequential steps** target the **triggering alert's** evidence. They proceed without a person only under
   pre-authorization (§1.7). Otherwise they wait for a human approval, and approvers are notified.
5. **Record.** Every decision is stored once per alert and playbook (`soar_automation_events`, unique), so a retry or
   a second worker never repeats it. A failure is recorded for that alert and never blocks the next one.

| Automation setting | Default |
|---|---|
| Automatic playbooks | off |
| Automatic cases | off; minimum severity high |
| Pre-authorized actions | none (must be allowed actions) |
| Minimum detection confidence | 80 |
| Automatic dispatches per hour | 20 |
| Protected targets | none |

The emergency stop halts automation too: matching alerts are recorded as `skipped_emergency_stop` and nothing starts.
Alerts skipped while the stop was on are not replayed when it is lifted.

## 12. Reproducible simulated `block_ip` procedure

This procedure proves the whole chain without touching any endpoint. The bridge runs with `"adapter": "simulated"`
and `"allow_live": false`.

1. **Bridge (Server 1).** `bridge.json` lists the organization under `tenants` with `"actions": ["block_ip"]` and its
   agent groups (`novrsoc-v2 soar-bridge-tenant <org>` prints the entry from the organization's policy). Keep
   `adapter: simulated`.
2. **Response policy.** Allowed actions `block_ip`; authorized groups: the organization's mapped groups; live mode
   off. Protected targets: at least the WireGuard network, both servers' public addresses and the office egress.
3. **Automation.** Automatic playbooks on; pre-authorized actions `block_ip`; minimum confidence 60 for the test.
4. **Playbook.** A version with steps `enrich_iocs` then `block_ip`, triggers `rule_ids: ["5712"]`, modes
   `dry_run`, automatic. Validated, submitted, and approved by a second manager.
5. **Alert.** A brute-force alert (rule 5712, level 10) from a documentation address such as `203.0.113.77` on an
   agent of an authorized group.
6. **Expected result** within one jobs cycle:
   - `/app/soar/automation`: `case_created` and `run_started`, confidence 60, factor "rule level 10: base 60";
   - the run: origin automatic, step `block` with authorization "pre-authorized by policy", state `dry_run`;
   - the stored request: `action block_ip`, `target 203.0.113.77`, the agent id, `mode dry_run`,
     `authorization policy`, `approved_by policy`, and the `approval_id` of the policy authorization;
   - the signed receipt: `status dry_run`, `adapter simulated`, `command firewall-drop`;
   - audit: `SOAR_AUTOMATIC_CASE`, `SOAR_AUTOMATIC_RUN`, `SOAR_POLICY_AUTHORIZED`, `SOAR_STEP_EXECUTED`.
7. **Variants.** With live mode allowed in both policies and the bridge still `simulated`, the receipt is
   `executed` with `adapter simulated`: the bridge records the command and executes nothing. With the confidence
   threshold above 60, the step waits for a person instead. With the address in a protected network, the step is
   refused.

The same procedure (with brute-force rule 5763) runs automatically in `apps/api/tests/modules/soar/test_soar_automation.py`, with the real bridge
code in-process. Live enforcement stays disabled (`allow_live: false` on the bridge, live mode off in the policy)
until this procedure and the integration checks pass on the pilot, and the owner approves.
