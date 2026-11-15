'use client';

// Data loss recovery: what can actually be recovered, and the workflow to do it. NovrSOC's own database backups (Server 2)
// are the only connected backup system; other plans name an external provider or a manual procedure, and NovrSOC records
// the decision, progress, verification and evidence. A request without a covering backup ends "not recoverable".
import { useCallback, useState, type FormEvent } from 'react';
import { LifeBuoy } from 'lucide-react';
import { Drawer, KpiCard, PageHeader, Timeline, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { continuityApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

type Req = Schemas['RecoveryRequestView'];
const mins = (m?: number | null) => (m === null || m === undefined ? '—' : m >= 1440 ? `${Math.round(m / 144) / 10} d` : m >= 60 ? `${Math.round(m / 6) / 10} h` : `${m} min`);

function RequestDrawer({ id, plans, onClose, onChanged }: { id: string; plans: Schemas['RecoveryPlanView'][]; onClose: () => void; onChanged: () => void }) {
    const { orgId, can, session } = useSession();
    const r = useResource(useCallback(() => continuityApi.request(orgId, id), [orgId, id]));
    const [text, setText] = useState('');
    const [ref, setRef] = useState('');
    const [point, setPoint] = useState('');
    const act = useAction();
    const done = (x: unknown) => { if (x) { r.reload(); onChanged(); setText(''); } };
    const mine = r.data?.requested_by.id === session.user.id;
    return (
        <Drawer open onClose={onClose} title={r.data?.title ?? 'Recovery request'} subtitle={r.data ? `${r.data.plan_name ?? 'No plan'} · ${r.data.backup_source?.replace(/_/g, ' ') ?? ''}` : undefined}>
            {act.notice}
            <Loaded title="Request" data={r.data} error={r.error} reload={r.reload}>
                {(x: Req) => (
                    <div className="space-y-3 text-sm">
                        <p className="flex flex-wrap gap-2"><StateTag state={x.status} /><StateTag state={x.verification} label={`verification ${x.verification.replace('_', ' ')}`} /></p>
                        <p className="whitespace-pre-wrap">{x.description}</p>
                        <dl className="grid grid-cols-[10rem_1fr] gap-y-1 text-xs">
                            <dt className="text-foreground-muted">Affected data</dt><dd>{x.affected_data}</dd>
                            <dt className="text-foreground-muted">Loss detected</dt><dd>{fmt(x.loss_detected_at)}</dd>
                            <dt className="text-foreground-muted">Recovered to</dt><dd>{fmt(x.recovered_point)}</dd>
                            <dt className="text-foreground-muted">RPO achieved / target</dt><dd>{mins(x.achieved_rpo_minutes)} / {mins(x.rpo_target_minutes)}</dd>
                            <dt className="text-foreground-muted">RTO achieved / target</dt><dd>{mins(x.achieved_rto_minutes)} / {mins(x.rto_target_minutes)}</dd>
                            <dt className="text-foreground-muted">Decision</dt><dd>{x.decided_by ? `${x.decided_by.label}: ${x.decision_reason}` : '—'}</dd>
                            <dt className="text-foreground-muted">Backup reference</dt><dd>{x.backup_reference || '—'}</dd>
                        </dl>
                        <Timeline items={x.events.map((e) => ({ id: String(e.id), at: e.occurred_at, title: e.kind.replace('_', ' '), meta: `${e.actor_label} · ${fmt(e.occurred_at)}`, body: e.body }))} />
                        {can('recovery:manage') && !mine && (
                            <div className="grid gap-2 text-xs border-t border-border pt-3">
                                <Field label="Reason, note or evidence (recorded)"><TextInput value={text} onChange={(e) => setText(e.target.value)} maxLength={2000} /></Field>
                                {['submitted', 'assessing'].includes(x.status) && (
                                    <div className="flex flex-wrap gap-2 items-end">
                                        <Field label="Backup reference"><TextInput value={ref} onChange={(e) => setRef(e.target.value)} /></Field>
                                        {x.status === 'submitted' && <button className={btn('secondary')} disabled={text.trim().length < 5} onClick={() => void act.run(() => continuityApi.decide(orgId, id, { decision: 'assess', reason: text.trim(), backup_reference: ref }), 'Assessing.').then(done)}>Start assessment</button>}
                                        <button className={btn('primary')} disabled={text.trim().length < 5 || !x.plan_id} title={x.plan_id ? '' : 'A plan must cover the data'} onClick={() => void act.run(() => continuityApi.decide(orgId, id, { decision: 'approve', reason: text.trim(), backup_reference: ref }), 'Approved.').then(done)}>Approve</button>
                                        <button className={btn('secondary')} disabled={text.trim().length < 5} onClick={() => void act.run(() => continuityApi.decide(orgId, id, { decision: 'reject', reason: text.trim(), backup_reference: '' }), 'Rejected.').then(done)}>Reject</button>
                                    </div>
                                )}
                                {['submitted', 'assessing', 'approved', 'in_progress'].includes(x.status) && <button className={`${btn('ghost')} w-fit`} disabled={text.trim().length < 5}
                                    onClick={() => void act.run(() => continuityApi.decide(orgId, id, { decision: 'not_recoverable', reason: text.trim(), backup_reference: '' }), 'Recorded as not recoverable.').then(done)}>Not recoverable (no backup covers it)</button>}
                                {x.status === 'approved' && <button className={`${btn('primary')} w-fit`} disabled={text.trim().length < 3} onClick={() => void act.run(() => continuityApi.progress(orgId, id, { status: 'in_progress', note: text.trim(), evidence: [], recovered_point: null }), 'Recovery started.').then(done)}>Start recovery</button>}
                                {x.status === 'in_progress' && (
                                    <div className="flex flex-wrap gap-2 items-end">
                                        <Field label="Recovered to (point in time)"><TextInput type="datetime-local" value={point} onChange={(e) => setPoint(e.target.value)} /></Field>
                                        <button className={btn('primary')} disabled={text.trim().length < 3 || !point} onClick={() => void act.run(() => continuityApi.progress(orgId, id, { status: 'completed', note: text.trim(), recovered_point: new Date(point).toISOString(), evidence: [text.trim()] }), 'Completed; verification pending.').then(done)}>Record completion</button>
                                    </div>
                                )}
                                {x.status === 'completed' && x.verification === 'pending' && (
                                    <div className="flex gap-2">
                                        <button className={btn('primary')} disabled={text.trim().length < 5} onClick={() => void act.run(() => continuityApi.verify(orgId, id, { result: 'verified', note: text.trim() }), 'Verified.').then(done)}>Verified</button>
                                        <button className={btn('secondary')} disabled={text.trim().length < 5} onClick={() => void act.run(() => continuityApi.verify(orgId, id, { result: 'failed', note: text.trim() }), 'Verification failed.').then(done)}>Verification failed</button>
                                    </div>
                                )}
                            </div>
                        )}
                        {mine && <p className="text-[11px] text-foreground-muted">You submitted this request; another manager decides and verifies it.</p>}
                        {plans.length === 0 && <p className="text-[11px] text-foreground-muted">No recovery plan exists yet.</p>}
                    </div>
                )}
            </Loaded>
        </Drawer>
    );
}

export default function RecoveryPage() {
    const { orgId, can, session } = useSession();
    const ov = useResource(useCallback(() => continuityApi.overview(orgId), [orgId]));
    const plans = useResource(useCallback(() => continuityApi.plans(orgId), [orgId]));
    const reqs = useResource(useCallback(() => continuityApi.requests(orgId), [orgId]));
    const [open, setOpen] = useState<string | null>(null);
    const [p, setP] = useState({ name: '', scope: '', source: 'external_provider' as Schemas['RecoveryPlanCreate']['backup_source'], provider: '', rpo: 1440, rto: 480, procedure: '' });
    const [r, setR] = useState({ title: '', description: '', data: '', detected: new Date().toISOString().slice(0, 16), plan: '' });
    const act = useAction();
    const reload = () => { ov.reload(); plans.reload(); reqs.reload(); };
    const staff = ['super_admin', 'soc_manager', 'analyst'].includes(session.role);

    async function addPlan(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => continuityApi.createPlan(orgId, { name: p.name.trim(), scope: p.scope.trim(), backup_source: p.source, provider_name: p.provider.trim(),
            rpo_minutes: p.rpo, rto_minutes: p.rto, procedure: p.procedure.trim(), owning_unit: '' }), 'Plan saved.')) reload();
    }
    async function submit(e: FormEvent) {
        e.preventDefault();
        const x = await act.run(() => continuityApi.submit(orgId, { title: r.title.trim(), description: r.description.trim(), affected_data: r.data.trim(),
            loss_detected_at: new Date(r.detected).toISOString(), plan_id: r.plan || null, requested_recovery_point: null }), 'Request submitted; managers were notified.');
        if (x) { reload(); setOpen(x.id); setR({ ...r, title: '', description: '', data: '' }); }
    }
    const o = ov.data;
    return (
        <>
            <PageHeader title="Data loss recovery" icon={LifeBuoy}
                description="Recovery plans with RPO and RTO targets, recovery requests decided and verified by a second person, and the evidence behind them. NovrSOC never claims that data is recoverable without a backup that covers it." />
            {act.notice}
            <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
                <KpiCard label="Platform database backup" text={o ? (o.platform_backups.visible ? (o.platform_backups.last_succeeded_at ? fmt(o.platform_backups.last_succeeded_at) : 'none recorded') : 'platform admins only') : '…'} hint={o?.platform_backups.note} />
                <KpiCard label="Recovery plans" value={o?.plans} loading={!o && !ov.error} hint={o ? `${o.plans_untested_90d} untested in 90 days` : undefined} />
                <KpiCard label="Open requests" value={o?.open_requests} loading={!o && !ov.error} />
                <KpiCard label="RPO met / missed" text={o ? `${o.rpo_met} / ${o.rpo_missed}` : '…'} />
                <KpiCard label="RTO met / missed" text={o ? `${o.rto_met} / ${o.rto_missed}` : '…'} hint={o ? `${o.not_recoverable} not recoverable` : undefined} />
            </div>
            <Loaded title="Recovery requests" data={reqs.data} error={reqs.error} reload={reqs.reload} testid="recovery-requests">
                {(d) => <DataTable rows={d.items} rowKey={(x) => x.id} empty="No recovery requests." columns={[
                    { key: 't', header: 'Request', render: (x) => <button className="text-left" onClick={() => setOpen(x.id)}><strong className="text-purple">{x.title}</strong><span className="block text-[11px] text-foreground-muted">{x.affected_data}</span></button> },
                    { key: 's', header: 'Status', render: (x) => <StateTag state={x.status} /> },
                    { key: 'p', header: 'Plan', render: (x) => <span className="text-xs">{x.plan_name ?? '—'}</span> },
                    { key: 'v', header: 'Verification', render: (x) => <StateTag state={x.verification} /> },
                    { key: 'w', header: 'Submitted', render: (x) => <span className="text-xs">{x.requested_by.label} · {fmt(x.created_at)}</span> },
                ]} />}
            </Loaded>
            {staff && (
                <Card>
                    <SectionTitle title="Submit a recovery request" />
                    <form onSubmit={submit} className="mt-3 grid sm:grid-cols-3 gap-2 items-end text-xs">
                        <Field label="Title"><TextInput required minLength={3} value={r.title} onChange={(e) => setR({ ...r, title: e.target.value })} /></Field>
                        <Field label="Affected data"><TextInput required minLength={3} value={r.data} onChange={(e) => setR({ ...r, data: e.target.value })} /></Field>
                        <Field label="Loss detected"><TextInput type="datetime-local" required value={r.detected} onChange={(e) => setR({ ...r, detected: e.target.value })} /></Field>
                        <Field label="Plan (if one covers it)"><select className={selectCls} value={r.plan} onChange={(e) => setR({ ...r, plan: e.target.value })}>
                            <option value="">No plan / unknown</option>{(plans.data?.items ?? []).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select></Field>
                        <Field label="What happened"><textarea required minLength={10} rows={2} className={inputCls} value={r.description} onChange={(e) => setR({ ...r, description: e.target.value })} /></Field>
                        <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Submit request</button>
                    </form>
                </Card>
            )}
            <Loaded title="Recovery plans" data={plans.data} error={plans.error} reload={plans.reload} testid="recovery-plans">
                {(d) => <DataTable rows={d.items} rowKey={(x) => x.id} empty="No recovery plans." columns={[
                    { key: 'n', header: 'Plan', render: (x) => <span><strong>{x.name}</strong><span className="block text-[11px] text-foreground-muted">{x.scope}</span></span> },
                    { key: 's', header: 'Backup source', render: (x) => <span className="text-xs">{x.backup_source.replace(/_/g, ' ')}{x.provider_name && ` · ${x.provider_name}`}<span className="block text-foreground-muted">{x.execution}</span></span> },
                    { key: 't', header: 'RPO / RTO', render: (x) => <span className="text-xs">{mins(x.rpo_minutes)} / {mins(x.rto_minutes)}</span> },
                    { key: 'l', header: 'Last tested', render: (x) => <span className="text-xs">{x.last_tested_at ? fmt(x.last_tested_at) : 'never'}</span> },
                    { key: 'x', header: '', render: (x) => (can('recovery:manage') ? <button className={btn('ghost')} disabled={act.busy}
                        onClick={() => void act.run(() => continuityApi.tested(orgId, x.id, { tested_at: new Date().toISOString(), note: 'Plan exercised' }), 'Test recorded.').then(reload)}>Record a test today</button> : null) },
                ]} />}
            </Loaded>
            {can('recovery:manage') && (
                <Card>
                    <SectionTitle title="Add a recovery plan" hint="Platform database backups apply to the platform organization only" />
                    <form onSubmit={addPlan} className="mt-3 grid sm:grid-cols-4 gap-2 items-end text-xs">
                        <Field label="Name"><TextInput required minLength={3} value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} /></Field>
                        <Field label="Scope (systems and data)"><TextInput required minLength={3} value={p.scope} onChange={(e) => setP({ ...p, scope: e.target.value })} /></Field>
                        <Field label="Backup source"><select className={selectCls} value={p.source} onChange={(e) => setP({ ...p, source: e.target.value as typeof p.source })}>
                            <option value="external_provider">External provider</option><option value="manual_procedure">Manual procedure</option><option value="novrsoc_platform_backup">NovrSOC platform backup</option></select></Field>
                        <Field label="Provider"><TextInput value={p.provider} onChange={(e) => setP({ ...p, provider: e.target.value })} /></Field>
                        <Field label="RPO (min)"><TextInput type="number" min={1} value={p.rpo} onChange={(e) => setP({ ...p, rpo: Number(e.target.value) })} /></Field>
                        <Field label="RTO (min)"><TextInput type="number" min={1} value={p.rto} onChange={(e) => setP({ ...p, rto: Number(e.target.value) })} /></Field>
                        <Field label="Procedure"><TextInput value={p.procedure} onChange={(e) => setP({ ...p, procedure: e.target.value })} /></Field>
                        <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Save plan</button>
                    </form>
                </Card>
            )}
            {open && <RequestDrawer id={open} plans={plans.data?.items ?? []} onClose={() => setOpen(null)} onChanged={reload} />}
        </>
    );
}
