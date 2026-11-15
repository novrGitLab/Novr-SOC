'use client';

import Link from 'next/link';
import { useCallback, useState } from 'react';
import { useParams } from 'next/navigation';
import { ArrowLeft, Workflow } from 'lucide-react';
import { Notice, PageHeader, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { errorText, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { soarApi } from '../../api';

const STEP_TONE: Record<string, 'good' | 'warning' | 'critical' | 'neutral'> = {
    succeeded: 'good', dry_run: 'good', awaiting_approval: 'warning', dispatched: 'warning', failed: 'critical', refused_by_policy: 'critical',
    rejected: 'critical', expired: 'critical', skipped_not_configured: 'neutral', pending: 'neutral',
};

export default function RunPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId, can } = useSession();
    const { data: run, error, setData } = useResource(useCallback(() => soarApi.run(orgId, id), [orgId, id]));
    const [msg, setMsg] = useState<Msg>(null);
    async function redispatch(stepId: string) {
        try { setData(await soarApi.redispatch(orgId, stepId)); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <>
            <PageHeader title={run ? `${run.playbook_name} v${run.playbook_version}` : 'Run'} icon={Workflow}
                meta={run && <><span>{run.mode === 'live' ? 'Live' : 'Dry run'}</span><span>Requested by {run.requested_by.label} · {fmt(run.created_at)}</span></>}
                actions={<Link href="/app/soar" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> SOAR</Link>} />
            <Notice msg={msg} />
            {error ? <ApiErrorState error={error} /> : !run ? <LoadingState label="Loading run" /> : (
                <Card>
                    <SectionTitle title="Steps" hint={`Run state: ${run.state.replace('_', ' ')}`} action={<Link className={btn('ghost')} href={`/app/cases/${run.case_id}`}>Case</Link>} />
                    <ol className="mt-3 divide-y divide-border" data-testid="run-steps">
                        {run.steps.map((s) => (
                            <li key={s.id} className="py-3 text-sm" data-step={s.step_key} data-state={s.state}>
                                <p className="flex flex-wrap items-center gap-2"><Tag>{s.action}</Tag>{s.target && <span className="font-mono text-xs">{s.target}</span>}
                                    <StatusPill tone={STEP_TONE[s.state] ?? 'neutral'} label={s.state.replace(/_/g, ' ')} /></p>
                                <p className="text-xs text-foreground-muted mt-1">{s.message}</p>
                                {s.receipt && (
                                    <p className="text-[11px] mt-1 font-mono break-all" data-testid="receipt">
                                        receipt: {s.receipt.status} · adapter {s.receipt.adapter} · {s.receipt.command ?? '—'} · {fmt(s.receipt.executed_at)} · request {s.receipt.request_id}{s.receipt.replayed ? ' · replayed' : ''}
                                    </p>)}
                                {s.state === 'awaiting_approval' && <Link className="text-xs underline" href="/app/soar">Waiting for approval</Link>}
                                {s.state === 'dispatched' && can('response:approve') && <button className={btn('secondary')} onClick={() => void redispatch(s.id)}>Re-send (same request id)</button>}
                            </li>
                        ))}
                    </ol>
                </Card>
            )}
        </>
    );
}
