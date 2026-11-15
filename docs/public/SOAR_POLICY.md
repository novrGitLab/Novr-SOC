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
4. **Authorized Wazuh group.** The endpoint's Wazuh agent groups are in the policy's authorized groups.
5. **Live-mode gates.** For live mode, both the playbook's execution policy and the organization's policy allow live
   execution.
6. **Second-person approval.** A person with `response:approve`, other than the requester, approves the step before
   its approval expires.
7. **Bridge authorization.** The Server 1 execution bridge authorizes the organization, action and target
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
- Any execution without an approval.
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
