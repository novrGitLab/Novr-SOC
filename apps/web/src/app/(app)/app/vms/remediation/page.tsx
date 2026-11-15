'use client';

// Remediation management: tasks per finding with due dates from priority, assignment and notes. A task closes only when
// a later scan verifies the fix (verification and retesting); risk acceptance cancels it with a recorded reason.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Wrench } from 'lucide-react';
import { PageHeader, PriorityBadge, Select, SeverityBadge, btn } from '@/components/features/vms/kit';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const STATUS = [['', 'All tasks'], ['open', 'Open'], ['in_progress', 'In progress'], ['done', 'Verified fixed'], ['cancelled', 'Cancelled']] as const;
const WHO = [['', 'Anyone'], ['me', 'Assigned to me'], ['unassigned', 'Unassigned']] as const;

export default function RemediationPage() {
    const { orgId, can, session } = useSession();
    const [status, setStatus] = useState<(typeof STATUS)[number][0]>('');
    const [who, setWho] = useState<(typeof WHO)[number][0]>('');
    const list = useResource(useCallback(() => vmsxApi.remediation(orgId, { status, assigned: who }), [orgId, status, who]));
    const [notes, setNotes] = useState<Record<string, string>>({});
    const act = useAction();
    return (
        <>
            <PageHeader title="Remediation and verification" icon={Wrench}
                description="Remediation tasks are created with each new finding (due 2, 7, 30 or 90 days by priority). A fix is verified only by a later scan; request a retest from the finding." />
            {act.notice}
            <div className="flex flex-wrap gap-2"><Select label="Status" options={STATUS} value={status} onChange={setStatus} /><Select label="Assignment" options={WHO} value={who} onChange={setWho} /></div>
            <Loaded title="Tasks" hint={list.data ? `${list.data.overdue} overdue · ${Object.entries(list.data.by_status).map(([k, v]) => `${v} ${k.replace('_', ' ')}`).join(' · ')}` : undefined}
                data={list.data} error={list.error} reload={list.reload} testid="remediation">
                {(d) => <DataTable rows={d.items} rowKey={(t) => t.id} empty="No remediation tasks." columns={[
                    { key: 'p', header: 'Priority', render: (t) => <PriorityBadge priority={t.priority} /> },
                    { key: 'f', header: 'Finding', render: (t) => <Link className="font-semibold text-purple hover:underline" href={`/app/vms/findings?finding=${t.finding_id}`}>{t.finding_title}<span className="block text-[11px] font-normal text-foreground-muted">{t.host}</span></Link> },
                    { key: 's', header: 'Severity', render: (t) => <SeverityBadge severity={t.severity} /> },
                    { key: 'st', header: 'Task / finding', render: (t) => <span className="text-xs"><StateTag state={t.status} /><span className="block text-foreground-muted">{t.finding_status.replace(/_/g, ' ')}</span></span> },
                    { key: 'd', header: 'Due', render: (t) => <span className={`text-xs ${t.overdue ? 'text-red font-semibold' : ''}`}>{fmt(t.due_at)}{t.overdue && ' · overdue'}</span> },
                    { key: 'a', header: 'Assignee', render: (t) => <span className="text-xs">{t.assignee_label ?? 'Unassigned'}{t.note && <span className="block text-foreground-muted">{t.note}</span>}</span> },
                    { key: 'x', header: '', render: (t) => (can('vms:manage') && (t.status === 'open' || t.status === 'in_progress') ? (
                        <span className="flex flex-wrap items-center gap-1">
                            {t.assignee_id !== session.user.id && <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => vmsxApi.updateTask(orgId, t.id, { assignee_id: session.user.id, note: '', status: null }), 'Assigned to you.').then(() => list.reload())}>Assign to me</button>}
                            <TextInput aria-label="Note" placeholder="Note" value={notes[t.id] ?? ''} onChange={(e) => setNotes({ ...notes, [t.id]: e.target.value })} className="w-32" />
                            <button className={btn('ghost')} disabled={act.busy || !(notes[t.id] ?? '').trim()} onClick={() => void act.run(() => vmsxApi.updateTask(orgId, t.id, { assignee_id: null, note: notes[t.id].trim(), status: t.status === 'open' ? 'in_progress' : null }), 'Note saved.').then(() => list.reload())}>Save note</button>
                        </span>) : null) },
                ]} />}
            </Loaded>
        </>
    );
}
