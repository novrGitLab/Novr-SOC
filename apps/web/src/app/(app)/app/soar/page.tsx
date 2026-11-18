'use client';

// SOAR operations centre (Security Orchestration, Automation and Response). Live state of the organization's response
// workflows: active and completed runs, queued dispatches, failures, human intervention, approvals, the emergency stop,
// and one timeline in which AI analysis is labelled as analysis and never mistaken for execution. Refreshes every 10 s.
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { Brain, OctagonX, Play, ShieldCheck, Workflow } from 'lucide-react';
import { EmptyState, KpiCard, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { playbookApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, useAction } from '@/foundation/ui/module';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { useResource } from '@/foundation/ui/useResource';
import { ApprovalRow } from './ApprovalRow';
import { soarApi } from './api';

const CAT: Record<string, { label: string; cls: string }> = {
    execution: { label: 'Execution', cls: 'bg-purple-tint text-purple dark:text-white' },
    approval: { label: 'Approval', cls: 'bg-card-muted text-foreground' },
    policy: { label: 'Policy', cls: 'bg-card-muted text-foreground' },
    playbook: { label: 'Playbook', cls: 'bg-card-muted text-foreground' },
    ai_analysis: { label: 'AI analysis (not an action)', cls: 'border border-dashed border-border text-foreground-muted' },
};

export default function SoarOperationsPage() {
    const { orgId, can } = useSession();
    const [tick, setTick] = useState(0);
    useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 10_000); return () => clearInterval(t); }, []);
    const ops = useResource(useCallback(() => playbookApi.operations(orgId), [orgId, tick])); // eslint-disable-line react-hooks/exhaustive-deps
    const approvals = useResource(useCallback(() => soarApi.approvals(orgId, true), [orgId, tick])); // eslint-disable-line react-hooks/exhaustive-deps
    const [reason, setReason] = useState('');
    const act = useAction();
    const o = ops.data;

    async function toggleStop(active: boolean) {
        if (await act.run(() => playbookApi.emergencyStop(orgId, active, reason.trim()), active ? 'Emergency stop is ON.' : 'Emergency stop lifted.')) {
            setReason(''); setTick((x) => x + 1);
        }
    }

    return (
        <>
            <PageHeader title="SOAR operations centre" icon={Workflow}
                description="Security orchestration, automation and response: signals, policies, playbooks, human approvals and authorized response activity. Every consequential action needs the organization's policy, a target from the case's own evidence and either a second person's approval or the organization's pre-authorization policy; execution happens only through NovrSOAR. AI never authorizes an action." />
            {ops.error ? <ApiErrorState error={ops.error} onRetry={ops.reload} /> : !o ? <LoadingState label="Loading SOAR operations" /> : (
                <>
                    {o.emergency_stop && (
                        <div role="note" className="rounded-xl border-2 border-red bg-card p-3.5 flex items-start gap-3" data-testid="emergency-banner">
                            <OctagonX className="w-5 h-5 text-red shrink-0 mt-0.5" aria-hidden />
                            <div className="text-sm"><p className="font-bold">Emergency stop is ON</p><p className="text-xs text-foreground-muted">{o.emergency_reason} No run starts and nothing is dispatched until it is lifted.</p></div>
                        </div>
                    )}
                    <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-8 gap-3" data-testid="soar-kpis">
                        <KpiCard label="Waiting for approval" value={o.awaiting_approval} href="/app/soar/approvals" tone={o.awaiting_approval ? 'warning' : 'neutral'} />
                        <KpiCard label="Running" value={o.running} href="/app/soar/runs" />
                        <KpiCard label="Completed (24 h)" value={o.completed_24h} href="/app/soar/runs" />
                        <KpiCard label="Failed (24 h)" value={o.failed_24h} tone={o.failed_24h ? 'critical' : 'neutral'} href="/app/soar/runs" />
                        <KpiCard label="Dispatched, no receipt" value={o.dispatched_without_receipt} hint="Queued at NovrSOAR; re-send from the run" />
                        <KpiCard label="Refused by policy (24 h)" value={o.refused_24h} />
                        <KpiCard label="Need a person" value={o.human_intervention} tone={o.human_intervention ? 'warning' : 'neutral'} />
                        <KpiCard label="Runs this hour" text={`${o.runs_last_hour} / ${o.max_runs_per_hour}`} hint="Organization limit per hour" />
                    </div>
                    <p className="text-xs flex flex-wrap items-center gap-2" data-testid="soar-automation-kpis">
                        <StateTag state={o.automation_enabled ? 'ok' : 'disabled'} label={o.automation_enabled ? 'automation on' : 'automation off'} />
                        <span>Last 24 h: {o.automatic_runs_24h ?? 0} automatic run(s) · {o.policy_authorized_24h ?? 0} pre-authorized step(s) · {o.automatic_cases_24h ?? 0} automatic case(s)</span>
                        <Link className="underline" href="/app/soar/automation">Automation decisions</Link></p>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <Card className="lg:col-span-2">
                            <SectionTitle title="Live timeline" hint="Engine, approvals, policy and playbooks; AI analysis is labelled and never executes" />
                            <ol className="mt-3 divide-y divide-border max-h-[32rem] overflow-y-auto" data-testid="soar-timeline">
                                {o.timeline.length === 0 && <li><EmptyState compact title="No activity yet" body="Runs start from a case; AI analyses appear as NHAI jobs finish." /></li>}
                                {o.timeline.map((t, i) => (
                                    <li key={`${t.at}-${i}`} className="py-2 flex items-start gap-3 text-xs" data-category={t.category}>
                                        <span className="w-28 shrink-0 text-foreground-muted tabular-nums">{new Date(t.at).toLocaleTimeString('en-GB')}<span className="block">{new Date(t.at).toLocaleDateString('en-GB')}</span></span>
                                        <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold uppercase tracking-wide ${CAT[t.category]?.cls ?? ''}`}>
                                            {t.category === 'ai_analysis' ? <Brain className="inline w-3 h-3 mr-0.5" aria-hidden /> : null}{CAT[t.category]?.label ?? t.category}</span>
                                        <div className="min-w-0 flex-1"><p className="font-mono font-semibold">{t.action}</p>
                                            <p className="text-foreground-muted break-words">{t.summary || t.resource_id} · {t.actor_label}</p></div>
                                        <StateTag state={t.outcome === 'success' ? 'ok' : t.outcome} label={t.outcome} />
                                    </li>
                                ))}
                            </ol>
                        </Card>
                        <div className="space-y-4">
                            <Card>
                                <SectionTitle title="Emergency stop" hint="Blocks new runs, approvals that dispatch, and re-dispatch" />
                                <div className="mt-3 space-y-2 text-sm">
                                    <p><StateTag state={o.emergency_stop ? 'failing' : 'ok'} label={o.emergency_stop ? 'stopped' : 'not active'} /> Live execution: {o.live_enabled ? 'allowed by policy' : 'disabled (dry runs only)'}</p>
                                    {can('soar:manage') ? (
                                        <>
                                            <Field label="Reason (recorded, at least 10 characters)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} data-testid="estop-reason" /></Field>
                                            {o.emergency_stop
                                                ? <button className={btn('secondary')} disabled={act.busy || reason.trim().length < 10} onClick={() => void toggleStop(false)}><Play className="w-3.5 h-3.5" aria-hidden /> Lift the emergency stop</button>
                                                : <button className={btn('danger')} disabled={act.busy || reason.trim().length < 10} onClick={() => void toggleStop(true)} data-testid="estop-on"><OctagonX className="w-3.5 h-3.5" aria-hidden /> Stop all SOAR execution</button>}
                                        </>
                                    ) : <p className="text-xs text-foreground-muted">SOC managers (soar:manage) can stop execution.</p>}
                                    {act.notice}
                                </div>
                            </Card>
                            <Card>
                                <SectionTitle title="Playbooks" />
                                <p className="mt-2 text-sm"><ShieldCheck className="inline w-4 h-4 mr-1" aria-hidden />{o.approved_playbooks} approved and enabled; {o.pending_playbook_reviews} waiting for review.</p>
                                <Link href="/app/playbooks" className={`${btn('secondary')} mt-3`}>Manage playbooks</Link>
                            </Card>
                        </div>
                    </div>
                </>
            )}
            <Loaded title="Approvals waiting for a decision" hint="Another person decides; the requester cannot" data={approvals.data} error={approvals.error} reload={approvals.reload} testid="pending-approvals">
                {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">No approval is waiting.</p>
                    : <ul className="divide-y divide-border">{d.items.map((a) => <ApprovalRow key={a.id} a={a} onDone={() => setTick((x) => x + 1)} />)}</ul>}
            </Loaded>
            <p className="text-[11px] text-foreground-muted"><Tag>{fmt(o?.generated_at)}</Tag> Policy document: SOAR authorization, limits, emergency stop and audit are described in docs/public/SOAR_POLICY.md.</p>
        </>
    );
}
