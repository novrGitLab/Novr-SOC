'use client';

// AI activity centre: every NHAI analysis request, result, failure, recommendation, proposed action, human review and
// NovrChat exchange, from the append-only ai_activity record. This is analysis only: none of it executes anything.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Brain } from 'lucide-react';
import { PageHeader, Select } from '@/components/features/vms/kit';
import { playbookApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const KINDS = [['', 'All AI activity'], ['analysis_requested', 'Analyses requested'], ['analysis_completed', 'Analyses completed'],
    ['analysis_failed', 'Model failures'], ['recommendation', 'Recommendations'], ['proposed_action', 'Proposed actions'], ['review', 'Human reviews'],
    ['chat_question', 'NovrChat questions'], ['chat_answer', 'NovrChat answers'], ['chat_refused', 'NovrChat refusals']] as const;
type Kind = (typeof KINDS)[number][0];
const SUBJECT_HREF: Record<string, (id: string) => string> = {
    alert: (id) => `/app/alerts/${id}`, vms_finding: () => '/app/vms/findings', asset: (id) => `/app/assets/${id}`, chat_message: () => '/app/chat',
};

export default function AiActivityPage() {
    const { orgId } = useSession();
    const [kind, setKind] = useState<Kind>('');
    const res = useResource(useCallback(() => playbookApi.aiActivity(orgId, kind || undefined), [orgId, kind]));
    return (
        <>
            <PageHeader title="AI activity" icon={Brain}
                description="Every AI explanation, recommendation, investigation, model failure, proposed action and review, recorded append-only. AI analysis is distinct from response execution: nothing here ran an action, and AI never authorizes one." />
            <Select label="Show" options={KINDS} value={kind} onChange={setKind} />
            <Loaded title="Activity" hint={res.data?.note} data={res.data} error={res.error} reload={res.reload} testid="ai-activity">
                {(d) => <DataTable rows={d.items} rowKey={(r) => String(r.id)} empty="No AI activity recorded." columns={[
                    { key: 'at', header: 'When', render: (r) => <span className="text-xs whitespace-nowrap">{fmt(r.occurred_at)}</span> },
                    { key: 'k', header: 'Activity', render: (r) => <span className="text-xs font-semibold">{r.kind.replace(/_/g, ' ')}<span className="block font-normal text-foreground-muted">{r.module} · {r.task.replace(/_/g, ' ')}</span></span> },
                    { key: 's', header: 'Subject', render: (r) => (r.subject_type && SUBJECT_HREF[r.subject_type]
                        ? <Link className="text-xs underline" href={SUBJECT_HREF[r.subject_type](r.subject_id)}>{r.subject_type.replace(/_/g, ' ')}</Link>
                        : <span className="text-xs">{r.subject_type || '—'}</span>) },
                    { key: 'sum', header: 'Summary', render: (r) => <span className="text-xs">{r.summary}{r.details?.action ? <strong className="block">Proposed action: {String(r.details.action)} (requires human approval; never automatic)</strong> : null}</span> },
                    { key: 'actor', header: 'By', render: (r) => <span className="text-xs">{r.actor.label}{r.model && <span className="block text-foreground-muted">{r.model}</span>}</span> },
                    { key: 'o', header: 'Outcome', render: (r) => <StateTag state={r.outcome === 'success' ? 'ok' : r.outcome} label={r.outcome} /> },
                ]} />}
            </Loaded>
        </>
    );
}
