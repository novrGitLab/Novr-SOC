'use client';

// Playbook management: author a version (draft), validate it, submit it, and have ANOTHER soar:manage holder approve
// it; only approved, enabled versions run, and approving a version retires the previous one. Nothing is pre-defined
// and nothing runs automatically: a run is always started from a case, and consequential steps wait for approval.
import { useCallback, useState, type FormEvent } from 'react';
import { BookOpen, Plus, Trash2 } from 'lucide-react';
import { Drawer, EmptyState, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { playbookApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Action = Schemas['PlaybookStep']['action'];
const ACTIONS: { a: Action; label: string; consequential?: boolean }[] = [
    { a: 'enrich_iocs', label: 'Enrich indicators (Threat Insights)' }, { a: 'create_task', label: 'Add a task to the case' },
    { a: 'notify_email', label: 'Notify by email (no adapter configured)' }, { a: 'notify_ciso', label: 'Notify the CISO (no adapter configured)' },
    { a: 'block_ip', label: 'Block the source IP (needs approval)', consequential: true }, { a: 'isolate_agent', label: 'Isolate the endpoint (needs approval)', consequential: true },
    { a: 'disable_account', label: 'Disable an account (needs approval)', consequential: true },
];
type StepDraft = { key: string; action: Action; param: string; timeout: number };
const EMPTY = { name: '', title: '', description: '', rules: '', mitre: '', minLevel: 0, live: false, automatic: false, minSev: 'low' as 'low' | 'medium' | 'high' | 'critical', perDay: 20,
    steps: [{ key: 'enrich', action: 'enrich_iocs' as Action, param: '', timeout: 120 }] as StepDraft[] };

function VersionDrawer({ name, onClose, onChanged }: { name: string; onClose: () => void; onChanged: () => void }) {
    const { orgId, can, session } = useSession();
    const v = useResource(useCallback(() => playbookApi.versions(orgId, name), [orgId, name]));
    const act = useAction();
    const [note, setNote] = useState('');
    const step = async (fn: () => Promise<unknown>, ok: string) => { if (await act.run(fn, ok)) { v.reload(); onChanged(); } };
    return (
        <Drawer open onClose={onClose} title={`Playbook ${name}`} subtitle="Versions, validation and approval">
            {act.notice}
            <Loaded title="Versions" data={v.data} error={v.error} reload={v.reload} testid="playbook-versions">
                {(d) => (
                    <ul className="space-y-4">
                        {d.items.map((p) => (
                            <li key={p.id} className="border border-border rounded-xl p-3 space-y-2" data-version={p.version} data-status={p.status}>
                                <p className="flex flex-wrap items-center gap-2 text-sm font-semibold">v{p.version} · {p.title} <StateTag state={p.status} /></p>
                                <p className="text-xs text-foreground-muted">By {p.created_by_label || 'unknown'} · {fmt(p.created_at)}
                                    {p.approved_by && <> · approved by {p.approved_by.label} {fmt(p.approved_at)}</>}</p>
                                {p.description && <p className="text-xs">{p.description}</p>}
                                <ol className="text-xs list-decimal ml-4">{p.steps.map((s) => <li key={s.step_key}><Tag strong={['block_ip', 'isolate_agent', 'disable_account'].includes(s.action)}>{s.action}</Tag> <span className="font-mono">{s.step_key}</span>{Object.keys(s.parameters).length ? ` ${JSON.stringify(s.parameters)}` : ''}</li>)}</ol>
                                <p className="text-xs">Modes: {p.execution_policy.modes.join(', ')}{p.execution_policy.automatic ? ' · automatic' : ''} · minimum case severity {p.execution_policy.min_case_severity} · {p.execution_policy.max_runs_per_day} runs per day</p>
                                {p.validation && (
                                    <div className="text-xs space-y-1" data-testid="validation">
                                        <p><StateTag state={p.validation.valid ? 'ok' : 'failed'} label={p.validation.valid ? 'valid' : 'invalid'} /> checked {fmt(p.validation.checked_at)}</p>
                                        {p.validation.errors.map((e) => <p key={e} className="text-red">Error: {e}</p>)}
                                        {p.validation.warnings.map((w) => <p key={w} className="text-foreground-muted">Warning: {w}</p>)}
                                    </div>
                                )}
                                {p.review_note && <p className="text-xs">Review note: {p.review_note}</p>}
                                {can('soar:manage') && (
                                    <div className="flex flex-wrap gap-2 items-end">
                                        {(p.status === 'draft' || p.status === 'validated') && <button className={btn('secondary')} onClick={() => void step(() => playbookApi.validate(orgId, p.id), 'Validated.')}>Validate</button>}
                                        {p.status === 'validated' && <button className={btn('primary')} onClick={() => void step(() => playbookApi.submit(orgId, p.id), 'Submitted for approval.')}>Submit for approval</button>}
                                        {p.status === 'pending_approval' && (p.created_by_label === session.user.email
                                            ? <p className="text-[11px] text-foreground-muted">You wrote this version; another manager must review it.</p>
                                            : <>
                                                <Field label="Review note"><TextInput value={note} onChange={(e) => setNote(e.target.value)} maxLength={2000} /></Field>
                                                <button className={btn('primary')} disabled={note.trim().length < 3} onClick={() => void step(() => playbookApi.review(orgId, p.id, { decision: 'approve', note }), 'Approved.')}>Approve</button>
                                                <button className={btn('secondary')} disabled={note.trim().length < 3} onClick={() => void step(() => playbookApi.review(orgId, p.id, { decision: 'reject', note }), 'Returned to draft.')}>Reject</button>
                                            </>)}
                                        {p.status !== 'retired' && <button className={btn('ghost')} onClick={() => void step(() => playbookApi.retire(orgId, p.id), 'Retired.')}>Retire</button>}
                                    </div>
                                )}
                            </li>
                        ))}
                    </ul>
                )}
            </Loaded>
        </Drawer>
    );
}

export default function PlaybooksPage() {
    const { orgId, can } = useSession();
    const list = useResource(useCallback(() => playbookApi.list(orgId), [orgId]));
    const [open, setOpen] = useState<string | null>(null);
    const [f, setF] = useState(EMPTY);
    const act = useAction();

    async function create(e: FormEvent) {
        e.preventDefault();
        const body: Schemas['PlaybookCreate'] = {
            name: f.name.trim(), title: f.title.trim(), description: f.description.trim(),
            steps: f.steps.map((s) => ({ step_key: s.key.trim(), action: s.action, timeout_seconds: s.timeout, max_attempts: 3,
                parameters: (s.action === 'create_task' ? { title: s.param || f.title } : s.action === 'disable_account' && s.param ? { account: s.param } : {}) as Record<string, string> })),
            triggers: { rule_ids: f.rules.split(',').map((r) => r.trim()).filter(Boolean), mitre: f.mitre.split(',').map((r) => r.trim()).filter(Boolean), min_level: f.minLevel },
            execution_policy: { modes: f.live ? ['dry_run', 'live'] : ['dry_run'], min_case_severity: f.minSev, max_runs_per_day: f.perDay, automatic: f.automatic },
        };
        const r = await act.run(() => playbookApi.create(orgId, body), (p) => `Saved ${p.name} v${p.version} as a draft. Validate and submit it for approval.`);
        if (r) { list.reload(); setOpen(r.name); setF(EMPTY); }
    }
    const setStep = (i: number, s: Partial<StepDraft>) => setF({ ...f, steps: f.steps.map((x, j) => (j === i ? { ...x, ...s } : x)) });

    return (
        <>
            <PageHeader title="Playbooks" icon={BookOpen}
                description="Response playbooks, versioned. A version runs only after validation and approval by another manager. At run time a consequential step waits for a human approval, unless the version is automatic and the response policy pre-authorizes the action. No playbook is pre-defined." />
            {act.notice}
            <Loaded title="Playbooks" hint="Latest version of each" data={list.data} error={list.error} reload={list.reload} testid="playbooks">
                {(d) => d.items.length === 0 ? <EmptyState title="No playbooks yet" body="Write the first one below. NovrSOC ships none: every playbook reflects your organization's own procedures." />
                    : <DataTable rows={d.items} rowKey={(p) => p.id} columns={[
                        { key: 'n', header: 'Playbook', render: (p) => <button className="text-left" onClick={() => setOpen(p.name)}><strong className="text-purple">{p.title}</strong><span className="block text-[11px] text-foreground-muted font-mono">{p.name} v{p.version}</span></button> },
                        { key: 's', header: 'Status', render: (p) => <StateTag state={p.status} /> },
                        { key: 'st', header: 'Steps', render: (p) => <span className="flex flex-wrap gap-1">{p.steps.map((s) => <Tag key={s.step_key} strong={['block_ip', 'isolate_agent', 'disable_account'].includes(s.action)}>{s.action}</Tag>)}</span> },
                        { key: 'm', header: 'Modes', render: (p) => <span className="text-xs">{p.execution_policy.modes.join(', ')}{p.execution_policy.automatic && <Tag>automatic</Tag>}</span> },
                        { key: 'v', header: 'Validation', render: (p) => (p.validation ? <StateTag state={p.validation.valid ? 'ok' : 'failed'} label={p.validation.valid ? `valid (${p.validation.warnings.length} warning(s))` : `${p.validation.errors.length} error(s)`} /> : '—') },
                    ]} />}
            </Loaded>
            {can('soar:manage') && (
                <Card>
                    <SectionTitle title="New playbook or new version" hint="Saved as a draft; the same name creates a new version" />
                    <form onSubmit={create} className="mt-3 grid gap-3" data-testid="playbook-form">
                        <div className="grid sm:grid-cols-3 gap-2">
                            <Field label="Name (a-z, 0-9, -, _)"><TextInput required value={f.name} pattern="[a-z0-9][a-z0-9_-]{1,59}" onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
                            <Field label="Title"><TextInput required minLength={3} value={f.title} onChange={(e) => setF({ ...f, title: e.target.value })} /></Field>
                            <Field label="Description"><TextInput value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} maxLength={4000} /></Field>
                        </div>
                        <fieldset className="grid gap-2">
                            <legend className="text-xs font-semibold mb-1">Steps (in order)</legend>
                            {f.steps.map((s, i) => (
                                <div key={i} className="grid sm:grid-cols-[8rem_1fr_1fr_6rem_auto] gap-2 items-end">
                                    <Field label="Step key"><TextInput required pattern="[a-z0-9_]{2,60}" value={s.key} onChange={(e) => setStep(i, { key: e.target.value })} /></Field>
                                    <Field label="Action"><select className={selectCls} value={s.action} onChange={(e) => setStep(i, { action: e.target.value as Action })}>
                                        {ACTIONS.map((x) => <option key={x.a} value={x.a}>{x.label}</option>)}</select></Field>
                                    <Field label={s.action === 'disable_account' ? 'Account (must appear in the alerts)' : s.action === 'create_task' ? 'Task title' : 'Parameter (not used)'}>
                                        <TextInput value={s.param} disabled={!['create_task', 'disable_account'].includes(s.action)} onChange={(e) => setStep(i, { param: e.target.value })} /></Field>
                                    <Field label="Timeout (s)"><TextInput type="number" min={1} max={3600} value={s.timeout} onChange={(e) => setStep(i, { timeout: Number(e.target.value) })} /></Field>
                                    <button type="button" className={btn('ghost')} aria-label={`Remove step ${i + 1}`} disabled={f.steps.length === 1}
                                        onClick={() => setF({ ...f, steps: f.steps.filter((_, j) => j !== i) })}><Trash2 className="w-3.5 h-3.5" aria-hidden /></button>
                                </div>
                            ))}
                            <button type="button" className={`${btn('secondary')} w-fit`} disabled={f.steps.length >= 20}
                                onClick={() => setF({ ...f, steps: [...f.steps, { key: `step_${f.steps.length + 1}`, action: 'create_task', param: '', timeout: 120 }] })}>
                                <Plus className="w-3.5 h-3.5" aria-hidden /> Add step</button>
                        </fieldset>
                        <div className="grid sm:grid-cols-3 gap-2">
                            <Field label="Recommend for NovrSIEM rule ids (comma separated)"><TextInput value={f.rules} onChange={(e) => setF({ ...f, rules: e.target.value })} /></Field>
                            <Field label="Or MITRE techniques (e.g. T1110)"><TextInput value={f.mitre} onChange={(e) => setF({ ...f, mitre: e.target.value })} /></Field>
                            <Field label="Minimum rule level"><TextInput type="number" min={0} max={16} value={f.minLevel} onChange={(e) => setF({ ...f, minLevel: Number(e.target.value) })} /></Field>
                        </div>
                        <div className="grid sm:grid-cols-3 gap-2 items-end">
                            <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={f.live} onChange={() => setF({ ...f, live: !f.live })} />Allow live mode (the response policy must also allow it)</label>
                            <Field label="Minimum case severity"><select className={selectCls} value={f.minSev} onChange={(e) => setF({ ...f, minSev: e.target.value as typeof f.minSev })}>
                                {['low', 'medium', 'high', 'critical'].map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
                            <Field label="Runs per day"><TextInput type="number" min={1} max={500} value={f.perDay} onChange={(e) => setF({ ...f, perDay: Number(e.target.value) })} /></Field>
                        </div>
                        <label className="text-xs flex items-center gap-1" data-testid="playbook-automatic"><input type="checkbox" checked={f.automatic} onChange={() => setF({ ...f, automatic: !f.automatic })} />
                            Automatic: once approved, start on matching new alerts while the organization&apos;s automation is on (consequential steps proceed only if the response policy pre-authorizes them)</label>
                        <button className={`${btn('primary', 'md')} w-fit`} type="submit" disabled={act.busy}>Save draft</button>
                    </form>
                </Card>
            )}
            {open && <VersionDrawer name={open} onClose={() => setOpen(null)} onChanged={list.reload} />}
        </>
    );
}
