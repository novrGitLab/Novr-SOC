'use client';

// SLA management: response and resolution targets per severity, the live state of every open case (breach indicators),
// escalation, and historical performance. A case without a policy is "no policy": it is never counted as met.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { Timer } from 'lucide-react';
import { PageHeader, SeverityBadge, btn } from '@/components/features/vms/kit';
import { ChartCard, Legend, TimeChart, type Series } from '@/components/features/vms/charts';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { secopsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

const SEVS = ['critical', 'high', 'medium', 'low'] as const;
type Sev = (typeof SEVS)[number];
type Row = { response: number; resolution: number; before: number; role: 'soc_manager' | 'super_admin'; on: boolean };
const WEEK: Series[] = [{ key: 'met', label: 'Met', token: '--vz-good' }, { key: 'breached', label: 'Breached', token: '--vz-sev-critical' }];
const mins = (m?: number | null) => (m === null || m === undefined ? '—' : m >= 1440 ? `${Math.round(m / 144) / 10} d` : m >= 60 ? `${Math.round(m / 6) / 10} h` : `${m} min`);

export default function SlaPage() {
    const { orgId, can } = useSession();
    const policies = useResource(useCallback(() => secopsApi.policies(orgId), [orgId]));
    const status = useResource(useCallback(() => secopsApi.status(orgId), [orgId]));
    const [days, setDays] = useState(30);
    const perf = useResource(useCallback(() => secopsApi.performance(orgId, days), [orgId, days]));
    const [edit, setEdit] = useState<Record<Sev, Row> | null>(null);
    const act = useAction();

    function startEdit() {
        const by = Object.fromEntries((policies.data?.items ?? []).map((p) => [p.severity, p]));
        const def: Record<Sev, [number, number]> = { critical: [15, 240], high: [60, 1440], medium: [240, 4320], low: [1440, 10080] };
        setEdit(Object.fromEntries(SEVS.map((s) => [s, by[s] ? { response: by[s].response_minutes, resolution: by[s].resolution_minutes,
            before: by[s].escalate_before_minutes, role: by[s].escalate_to_role, on: true } : { response: def[s][0], resolution: def[s][1], before: 0, role: 'soc_manager', on: false }])) as Record<Sev, Row>);
    }
    async function save(e: FormEvent) {
        e.preventDefault(); if (!edit) return;
        const list = SEVS.filter((s) => edit[s].on).map((s) => ({ severity: s, response_minutes: edit[s].response, resolution_minutes: edit[s].resolution,
            escalate_before_minutes: edit[s].before, escalate_to_role: edit[s].role }));
        if (await act.run(() => secopsApi.setPolicies(orgId, { policies: list }), 'SLA policies saved. They apply to cases created from now on.')) { setEdit(null); policies.reload(); }
    }

    return (
        <>
            <PageHeader title="SLA management" icon={Timer}
                description="Response and resolution targets per case severity, fixed on each case when it is created. Breaches escalate once to the policy's role; NovrSOC checks every minute and you can run the check now." />
            {act.notice}
            <Loaded title="Policies" data={policies.data} error={policies.error} reload={policies.reload} testid="sla-policies"
                action={can('sla:manage') && !edit ? <button className={btn('secondary')} onClick={startEdit}>Edit policies</button> : undefined}>
                {(d) => edit ? (
                    <form onSubmit={save} className="grid gap-2 text-xs">
                        {SEVS.map((s) => (
                            <div key={s} className="grid grid-cols-2 sm:grid-cols-[7rem_repeat(4,1fr)] gap-2 items-center">
                                <label className="flex items-center gap-1"><input type="checkbox" checked={edit[s].on} onChange={() => setEdit({ ...edit, [s]: { ...edit[s], on: !edit[s].on } })} /><SeverityBadge severity={s} /></label>
                                <label className="flex flex-col">Respond within (min)<input type="number" min={1} className={inputCls} value={edit[s].response} onChange={(e) => setEdit({ ...edit, [s]: { ...edit[s], response: Number(e.target.value) } })} /></label>
                                <label className="flex flex-col">Resolve within (min)<input type="number" min={1} className={inputCls} value={edit[s].resolution} onChange={(e) => setEdit({ ...edit, [s]: { ...edit[s], resolution: Number(e.target.value) } })} /></label>
                                <label className="flex flex-col">At risk before (min, 0 = 20%)<input type="number" min={0} className={inputCls} value={edit[s].before} onChange={(e) => setEdit({ ...edit, [s]: { ...edit[s], before: Number(e.target.value) } })} /></label>
                                <label className="flex flex-col">Escalate to<select className={selectCls} value={edit[s].role} onChange={(e) => setEdit({ ...edit, [s]: { ...edit[s], role: e.target.value as Row['role'] } })}>
                                    <option value="soc_manager">SOC managers</option><option value="super_admin">Platform administrators</option></select></label>
                            </div>
                        ))}
                        <div className="flex gap-2"><button className={btn('primary')} disabled={act.busy || !SEVS.some((s) => edit[s].on)}>Save</button><button type="button" className={btn('ghost')} onClick={() => setEdit(null)}>Cancel</button></div>
                    </form>
                ) : <DataTable rows={d.items} rowKey={(r) => r.severity} empty="No SLA policies: cases have no targets, and SLA performance cannot be measured." columns={[
                    { key: 's', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: 'r', header: 'Respond within', render: (r) => mins(r.response_minutes) },
                    { key: 'x', header: 'Resolve within', render: (r) => mins(r.resolution_minutes) },
                    { key: 'e', header: 'Escalation', render: (r) => <span className="text-xs">{r.escalate_before_minutes ? `${mins(r.escalate_before_minutes)} before` : '20% of the target before'} → {r.escalate_to_role.replace('_', ' ')}</span> },
                ]} />}
            </Loaded>
            <Loaded title="Open cases" hint={status.data ? Object.entries(status.data.counts).map(([k, v]) => `${v} ${k.replace('_', ' ')}`).join(' · ') : undefined}
                data={status.data} error={status.error} reload={status.reload} testid="sla-status"
                action={can('sla:manage') ? <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => secopsApi.escalate(orgId), (r) => `Checked ${r.checked}; escalated ${r.escalated}; notified ${r.notified}.`).then(() => status.reload())}>Run escalation check</button> : undefined}>
                {(d) => <DataTable rows={d.items} rowKey={(r) => r.case_id} empty="No open cases." columns={[
                    { key: 'c', header: 'Case', render: (r) => <Link className="font-semibold text-purple hover:underline" href={`/app/cases/${r.case_id}`}>{r.reference}</Link> },
                    { key: 't', header: 'Title', render: (r) => <span className="text-xs">{r.title}</span> },
                    { key: 's', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} /> },
                    { key: 'rs', header: 'Response', render: (r) => <span className="text-xs"><StateTag state={r.response_state} /><span className="block text-foreground-muted">{fmt(r.response_due_at)}</span></span> },
                    { key: 'xs', header: 'Resolution', render: (r) => <span className="text-xs"><StateTag state={r.resolution_state} /><span className="block text-foreground-muted">{fmt(r.resolution_due_at)}</span></span> },
                    { key: 'a', header: 'Assignee', render: (r) => <span className="text-xs">{r.assignee_label ?? 'Unassigned'}{r.escalated_at && <span className="block text-foreground-muted">escalated {fmt(r.escalated_at)}</span>}</span> },
                ]} />}
            </Loaded>
            <Card>
                <SectionTitle title="Historical performance" hint="Cases created in the period" action={
                    <select className={selectCls} value={days} onChange={(e) => setDays(Number(e.target.value))} aria-label="Period">
                        <option value={30}>30 days</option><option value={90}>90 days</option><option value={365}>12 months</option></select>} />
                <div className="mt-3 space-y-3" data-testid="sla-performance">
                    {perf.data?.note && <p className="text-xs text-foreground-muted">{perf.data.note}</p>}
                    {perf.data && <DataTable rows={perf.data.rows} rowKey={(r) => r.severity} columns={[
                        { key: 's', header: 'Severity', render: (r) => <SeverityBadge severity={r.severity} /> },
                        { key: 'n', header: 'Cases', render: (r) => r.cases },
                        { key: 'rm', header: 'Response met / breached', render: (r) => `${r.response_met} / ${r.response_breached}` },
                        { key: 'xm', header: 'Resolution met / breached', render: (r) => `${r.resolution_met} / ${r.resolution_breached}` },
                        { key: 'np', header: 'No policy', render: (r) => r.without_policy },
                        { key: 'mr', header: 'Median response', render: (r) => mins(r.median_response_minutes) },
                        { key: 'mx', header: 'Median resolution', render: (r) => mins(r.median_resolution_minutes) },
                    ]} />}
                </div>
            </Card>
            <ChartCard title="Weekly SLA outcome" empty={!perf.data?.weekly.length ? { title: 'No cases in the period' } : null}>
                <TimeChart data={(perf.data?.weekly ?? []).map((w) => ({ day: w.week_start, met: w.met, breached: w.breached }))} series={WEEK} kind="bar" label="Weekly SLA outcome" unit="cases" />
                <Legend series={WEEK} />
            </ChartCard>
        </>
    );
}
