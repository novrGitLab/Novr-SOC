'use client';

import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Sparkles } from 'lucide-react';
import { PageHeader, Tag } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { nhaiApi, type NhaiJob } from '../insights/api';
import { NhaiResult } from '../insights/AlertIntelPanel';

const TONE: Record<string, 'good' | 'warning' | 'critical' | 'neutral'> = { succeeded: 'good', queued: 'neutral', running: 'warning', failed: 'critical', timed_out: 'critical' };

export default function NhaiPage() {
    const { orgId } = useSession();
    const jobs = useResource(useCallback(() => nhaiApi.jobs(orgId), [orgId]));
    const [open, setOpen] = useState<NhaiJob | null>(null);
    return (
        <>
            <PageHeader title="Novr Human-Assisted Intelligence (NHAI)" icon={Sparkles}
                description="Asynchronous, evidence-grounded drafts for human review. Deterministic checks cap confidence, keep the NovrSIEM severity authoritative, refuse indicators that are not in the evidence and always list missing evidence. NHAI never acts." />
            <Loaded title="Jobs" data={jobs.data} error={jobs.error} reload={jobs.reload}>
                {(d) => <DataTable testid="nhai-jobs" rows={d.items} rowKey={(j) => j.id} empty="No NHAI job yet. Ask for an explanation from an alert." columns={[
                    { key: 's', header: 'Subject', render: (j) => <Link className="underline text-xs" href={`/app/alerts/${j.subject.id}`}>{j.task.replace(/_/g, ' ')}</Link> },
                    { key: 'st', header: 'Status', render: (j) => <StatusPill tone={TONE[j.status] ?? 'neutral'} label={j.status.replace('_', ' ')} /> },
                    { key: 'r', header: 'Review', render: (j) => j.result?.review ? <Tag>{j.result.review.decision}</Tag> : j.result ? <Tag>draft</Tag> : '—' },
                    { key: 'q', header: 'Requested', className: 'hidden md:table-cell', render: (j) => <span className="text-xs">{j.requested_by.label} · {fmt(j.queued_at)}</span> },
                    { key: 'o', header: '', render: (j) => j.result ? <button className="text-xs underline" onClick={() => setOpen(j)}>Open</button> : null },
                ]} />}
            </Loaded>
            {open && (
                <Card>
                    <SectionTitle title="Draft result" />
                    <div className="mt-3"><NhaiResult job={open} onChange={(j) => { setOpen(j); jobs.reload(); }} /></div>
                </Card>
            )}
        </>
    );
}
