'use client';

// Shift handover: the outgoing analyst writes a summary; NovrSOC freezes the queue (unresolved alerts, open cases,
// pending approvals, SLA risk, assignments) into it; the incoming analyst acknowledges. The author cannot acknowledge.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { ArrowRightLeft } from 'lucide-react';
import { EmptyState, PageHeader, SeverityBadge, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { secopsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { Grid, StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

type Snap = Schemas['HandoverSnapshot'];

function SnapshotView({ s }: { s: Snap }) {
    return (
        <div className="space-y-3 text-xs">
            <Grid cols={4}>
                <p className="rounded-lg border border-border p-2"><strong className="block text-lg">{s.unresolved_alerts}</strong>unresolved alerts</p>
                <p className="rounded-lg border border-border p-2"><strong className="block text-lg">{s.unassigned_critical_alerts}</strong>unassigned critical alerts</p>
                <p className="rounded-lg border border-border p-2"><strong className="block text-lg">{s.open_cases}</strong>open cases</p>
                <p className="rounded-lg border border-border p-2"><strong className="block text-lg">{s.sla_breached}</strong>SLA breaches · {s.sla_at_risk.length} at risk</p>
            </Grid>
            {s.cases.length > 0 && <div><p className="font-semibold mb-1">Open cases</p><ul className="space-y-1">{s.cases.slice(0, 8).map((c) => (
                <li key={c.id}><Link className="underline" href={`/app/cases/${c.id}`}>{c.reference}</Link> <SeverityBadge severity={c.severity} /> {c.title} · {c.assignee_label ?? 'unassigned'}</li>))}</ul></div>}
            {s.top_alerts.length > 0 && <div><p className="font-semibold mb-1">Unresolved alerts</p><ul className="space-y-1">{s.top_alerts.slice(0, 8).map((a) => (
                <li key={a.id}><Link className="underline" href={`/app/alerts/${a.id}`}>{a.rule_description || 'alert'}</Link> <SeverityBadge severity={a.severity} /> {a.status} · {a.assignee_label ?? 'unassigned'}</li>))}</ul></div>}
            {s.pending_approvals.length > 0 && <div><p className="font-semibold mb-1">Pending approvals</p><ul>{s.pending_approvals.map((a) => (
                <li key={a.id}>{a.action} {a.target} · requested by {a.requested_by} · expires {fmt(a.expires_at)}</li>))}</ul></div>}
            {s.sla_at_risk.length > 0 && <div><p className="font-semibold mb-1">SLA at risk</p><ul>{s.sla_at_risk.map((c) => (
                <li key={c.case_id}><Link className="underline" href={`/app/cases/${c.case_id}`}>{c.reference}</Link> resolve by {fmt(c.resolution_due_at)}</li>))}</ul></div>}
        </div>
    );
}

export default function HandoverPage() {
    const { orgId, can, session } = useSession();
    const draft = useResource(useCallback(() => (can('handover:write') ? secopsApi.draft(orgId) : Promise.resolve(null)), [orgId, can]));
    const list = useResource(useCallback(() => secopsApi.handovers(orgId), [orgId]));
    const now = new Date();
    const [f, setF] = useState({ start: new Date(now.getTime() - 8 * 3600_000).toISOString().slice(0, 16), end: now.toISOString().slice(0, 16),
        summary: '', watch: '', incoming: '' });
    const [ack, setAck] = useState<Record<string, string>>({});
    const act = useAction();

    async function submit(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => secopsApi.submit(orgId, { shift_start: new Date(f.start).toISOString(), shift_end: new Date(f.end).toISOString(),
            summary: f.summary.trim(), watch_items: f.watch.split('\n').map((x) => x.trim()).filter(Boolean), incoming_user_id: f.incoming || null }),
            'Handover submitted; the incoming analyst has been notified.');
        if (r) { setF({ ...f, summary: '', watch: '' }); list.reload(); }
    }
    async function acknowledge(id: string) {
        if (await act.run(() => secopsApi.acknowledge(orgId, id, ack[id] ?? ''), 'Handover acknowledged.')) list.reload();
    }

    return (
        <>
            <PageHeader title="Shift handover" icon={ArrowRightLeft}
                description="Write the shift summary; NovrSOC freezes the queue into it so the incoming analyst sees exactly what was open. The incoming analyst acknowledges it." />
            {act.notice}
            {can('handover:write') && (
                <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                    <Loaded title="Current queue" hint="Frozen into the handover when you submit" data={draft.data ?? undefined} error={draft.error} reload={draft.reload}>
                        {(d) => <SnapshotView s={d.snapshot} />}
                    </Loaded>
                    <Card>
                        <SectionTitle title="Write the handover" />
                        <form onSubmit={submit} className="mt-3 grid gap-2" data-testid="handover-form">
                            <div className="grid grid-cols-2 gap-2">
                                <Field label="Shift start"><TextInput type="datetime-local" required value={f.start} onChange={(e) => setF({ ...f, start: e.target.value })} /></Field>
                                <Field label="Shift end"><TextInput type="datetime-local" required value={f.end} onChange={(e) => setF({ ...f, end: e.target.value })} /></Field>
                            </div>
                            <Field label="Summary (what happened, what is open, what to do next)">
                                <textarea required minLength={10} maxLength={8000} rows={5} className={inputCls} value={f.summary} onChange={(e) => setF({ ...f, summary: e.target.value })} data-testid="handover-summary" /></Field>
                            <Field label="Watch items (one per line)"><textarea rows={3} className={inputCls} value={f.watch} onChange={(e) => setF({ ...f, watch: e.target.value })} /></Field>
                            <Field label="Incoming analyst (optional: anyone on the team may acknowledge otherwise)">
                                <select className={selectCls} value={f.incoming} onChange={(e) => setF({ ...f, incoming: e.target.value })}>
                                    <option value="">Anyone on the team</option>
                                    {(draft.data?.recipients ?? []).map((r) => <option key={r.id} value={r.id}>{r.email} ({r.role})</option>)}
                                </select></Field>
                            <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy || f.summary.trim().length < 10}>Submit handover</button>
                        </form>
                    </Card>
                </div>
            )}
            <Loaded title="Handovers" data={list.data} error={list.error} reload={list.reload} testid="handovers">
                {(d) => d.items.length === 0 ? <EmptyState compact title="No handovers yet" /> : (
                    <ul className="space-y-4">
                        {d.items.map((h) => {
                            const mayAck = h.status === 'submitted' && h.author.id !== session.user.id && (!h.incoming_user_id || h.incoming_user_id === session.user.id) && can('handover:write');
                            return (
                                <li key={h.id} className="border border-border rounded-xl p-3 space-y-2" data-handover-id={h.id}>
                                    <p className="flex flex-wrap items-center gap-2 text-sm font-semibold">{h.author.label} → {h.incoming_label ?? 'the team'} <StateTag state={h.status} /></p>
                                    <p className="text-xs text-foreground-muted">Shift {fmt(h.shift_start)} – {fmt(h.shift_end)} · submitted {fmt(h.created_at)}
                                        {h.acknowledged_by && <> · acknowledged by {h.acknowledged_by.label} {fmt(h.acknowledged_at)}</>}</p>
                                    <p className="text-sm whitespace-pre-wrap">{h.summary}</p>
                                    {h.watch_items.length > 0 && <ul className="text-xs list-disc ml-5">{h.watch_items.map((w) => <li key={w}>{w}</li>)}</ul>}
                                    {h.acknowledgement_note && <p className="text-xs">Acknowledgement: {h.acknowledgement_note}</p>}
                                    <details><summary className="text-xs cursor-pointer text-purple">Queue at handover</summary><div className="mt-2"><SnapshotView s={h.snapshot} /></div></details>
                                    {mayAck && (
                                        <div className="flex flex-wrap items-end gap-2">
                                            <Field label="Acknowledgement note"><TextInput value={ack[h.id] ?? ''} onChange={(e) => setAck({ ...ack, [h.id]: e.target.value })} maxLength={2000} /></Field>
                                            <button className={btn('primary')} disabled={act.busy} onClick={() => void acknowledge(h.id)} data-testid="handover-ack">Acknowledge</button>
                                        </div>
                                    )}
                                </li>
                            );
                        })}
                    </ul>
                )}
            </Loaded>
        </>
    );
}
