// SOAR engine API (workstream A): playbooks, policy, recommendations, runs, approvals, re-dispatch.
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, queryString, type ApiPath } from '@/foundation/api/paths';

export type Playbook = Schemas['PlaybookView'];
export type Run = Schemas['RunView'];
export type Approval = Schemas['ApprovalView'];
export type Policy = Schemas['SoarPolicyView'];

const P = {
    playbooks: '/api/v1/soar/playbooks', policy: '/api/v1/soar/policy', recs: '/api/v1/soar/recommendations',
    runs: '/api/v1/soar/runs', run: '/api/v1/soar/runs/{run_id}', approvals: '/api/v1/soar/approvals',
    decide: '/api/v1/soar/approvals/{approval_id}/decision', dispatch: '/api/v1/soar/steps/{step_id}/dispatch',
    automation: '/api/v1/soar/automation/events',
} as const satisfies Record<string, ApiPath>;

export const soarApi = {
    playbooks: (orgId: string | null) => request<Schemas['PlaybookList']>(P.playbooks, { orgId }),
    createPlaybook: (orgId: string | null, body: Schemas['PlaybookCreate']) => request<Playbook>(P.playbooks, { method: 'POST', orgId, body }),
    policy: (orgId: string | null) => request<Policy>(P.policy, { orgId }),
    setPolicy: (orgId: string | null, body: Schemas['SoarPolicyUpdate']) => request<Policy>(P.policy, { method: 'PUT', orgId, body }),
    recommendations: (orgId: string | null, caseId: string) => request<Schemas['RecommendationList']>(`${P.recs}${queryString({ case_id: caseId })}`, { orgId }),
    runs: (orgId: string | null, caseId?: string) => request<Schemas['RunList']>(`${P.runs}${queryString({ case_id: caseId })}`, { orgId }),
    run: (orgId: string | null, id: string) => request<Run>(fillPath(P.run, { run_id: id }), { orgId }),
    startRun: (orgId: string | null, body: Schemas['RunCreate']) => request<Run>(P.runs, { method: 'POST', orgId, body }),
    approvals: (orgId: string | null, pending = false) => request<Schemas['ApprovalList']>(`${P.approvals}${queryString({ pending: pending ? 'true' : undefined })}`, { orgId }),
    decide: (orgId: string | null, id: string, decision: 'approve' | 'reject', reason: string) =>
        request<Run>(fillPath(P.decide, { approval_id: id }), { method: 'POST', orgId, body: { decision, reason } satisfies Schemas['ApprovalDecisionRequest'] }),
    redispatch: (orgId: string | null, stepId: string) => request<Run>(fillPath(P.dispatch, { step_id: stepId }), { method: 'POST', orgId }),
    automationEvents: (orgId: string | null) => request<Schemas['AutomationEventList']>(`${P.automation}${queryString({ limit: 200 })}`, { orgId }),
};

/** The policy as an update body: the base fields, optionally with a new automation policy. */
export function policyBody(p: Policy, automation?: Schemas['SoarAutomationPolicy']): Schemas['SoarPolicyUpdate'] {
    return { allowed_actions: p.allowed_actions, allowed_agent_groups: p.allowed_agent_groups, live_enabled: p.live_enabled,
        approval_ttl_minutes: p.approval_ttl_minutes, max_runs_per_hour: p.max_runs_per_hour ?? 20, max_dispatch_attempts: p.max_dispatch_attempts ?? 3,
        ...(automation ? { automation } : {}) };
}
