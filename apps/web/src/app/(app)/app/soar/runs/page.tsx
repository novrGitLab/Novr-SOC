'use client';

// Every playbook run of the organization: mode, state and the case it serves. Runs start from a case.
import Link from 'next/link';
import { useCallback } from 'react';
import { ListChecks } from 'lucide-react';
import { PageHeader, Tag } from '@/components/features/vms/kit';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { soarApi } from '../api';

export default function SoarRunsPage() {
    const { orgId } = useSession();
    const runs = useResource(useCallback(() => soarApi.runs(orgId), [orgId]));
    return (
        <>
            <PageHeader title="SOAR runs" icon={ListChecks} description="Active and completed workflows, newest first. Open a run for its steps, approvals and signed execution receipts." />
            <Loaded title="Runs" data={runs.data} error={runs.error} reload={runs.reload}>
                {(d) => <DataTable testid="soar-runs" rows={d.items} rowKey={(r) => r.id} empty="No playbook has run yet. Start one from a case." columns={[
                    { key: 'pb', header: 'Playbook', render: (r) => <Link className="font-semibold text-purple hover:underline" href={`/app/soar/runs/${r.id}`}>{r.playbook_name} v{r.playbook_version}</Link> },
                    { key: 'mode', header: 'Mode', render: (r) => <Tag>{r.mode === 'live' ? 'live' : 'dry run'}</Tag> },
                    { key: 'state', header: 'State', render: (r) => <StateTag state={r.state} /> },
                    { key: 'steps', header: 'Steps', render: (r) => <span className="text-xs">{r.steps.map((s) => s.state.replace(/_/g, ' ')).join(' · ')}</span> },
                    { key: 'case', header: 'Case', render: (r) => <Link className="text-xs underline" href={`/app/cases/${r.case_id}`}>Open case</Link> },
                    { key: 'at', header: 'Requested', className: 'hidden md:table-cell', render: (r) => <span className="text-xs text-foreground-muted">{r.requested_by.label} · {fmt(r.created_at)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
