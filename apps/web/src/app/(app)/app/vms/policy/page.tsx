'use client';

// Scan policy and enrollment: the organization's standing scan authorization (instead of approving every endpoint) and
// what it means for each asset of the inventory. Assets imported from monitoring enroll automatically only when their
// address is private, recently reported, unique in the organization and inside an approved scope; everything else is
// listed with the reason it is not scanned. Every control is enforced by the API at queue time and again at claim.
import { sourceName } from '@/foundation/ui/names';
import { useCallback, useState, type FormEvent } from 'react';
import { ShieldCheck } from 'lucide-react';
import { PageHeader, Tag, btn, nf } from '@/components/features/vms/kit';
import { Card, StatusPill, type Tone } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Policy = Schemas['VmsScanPolicyUpdate'];
type Enrollment = Schemas['VmsEnrollmentView'];
const DAYS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
const STATUS: Record<Enrollment['status'], { label: string; tone: Tone }> = {
    enrolled: { label: 'Enrolled', tone: 'good' }, eligible: { label: 'Eligible (auto-enroll off)', tone: 'neutral' },
    excluded_protected: { label: 'Protected network', tone: 'neutral' }, outside_scope: { label: 'Outside approved scope', tone: 'neutral' },
    public_address: { label: 'Public address', tone: 'warning' }, shared_address: { label: 'Shared address', tone: 'warning' },
    stale_address: { label: 'Address not recent', tone: 'warning' }, no_address: { label: 'No address', tone: 'neutral' },
    unverified_source: { label: 'Ownership not established', tone: 'warning' }, manual_exclusion: { label: 'Excluded by a person', tone: 'neutral' },
};
const MODE: Record<Schemas['VmsScanPolicy']['installation_mode'], string> = {
    disabled: 'Scanning is disabled in this installation: the policy can be prepared, nothing is scanned.',
    local_test_targets: 'Development installation: only local test targets can be scanned.',
    authorized_scopes: 'Production scanning: scans run inside approved scopes, under this policy.',
};
const hhmm = (m: number) => `${String(Math.floor(m / 60)).padStart(2, '0')}:${String(m % 60).padStart(2, '0')}`;
const mins = (s: string) => { const [h, m] = s.split(':').map(Number); return (h || 0) * 60 + (m || 0); };

export default function ScanPolicyPage() {
    const { orgId, can } = useSession();
    const policy = useResource(useCallback(() => vmsxApi.policy(orgId), [orgId]));
    const [status, setStatus] = useState<string>('');
    const enrollments = useResource(useCallback(() => vmsxApi.enrollments(orgId, status || undefined), [orgId, status]));
    const act = useAction();
    const editable = can('vms:scope');
    return (
        <>
            <PageHeader title="Scan policy and enrollment" icon={ShieldCheck}
                description="One standing authorization for the organization: approved scopes, protected networks, scan windows and limits. Imported assets inside an approved scope are enrolled automatically; the others are listed with the reason." />
            {act.notice}
            <Loaded title="Scan policy" data={policy.data} error={policy.error} reload={policy.reload} testid="vms-policy">
                {(p) => <PolicyForm key={`${p.updated_at ?? 'new'}`} p={p} editable={editable} save={async (body) => {
                    if (await act.run(() => vmsxApi.savePolicy(orgId, body), 'Scan policy saved; enrollment re-evaluated.')) { policy.reload(); enrollments.reload(); }
                }} busy={act.busy} />}
            </Loaded>
            <Loaded title="Asset enrollment" hint="Every active asset of the inventory and whether it may be scanned" data={enrollments.data} error={enrollments.error}
                reload={enrollments.reload} testid="vms-enrollments"
                action={editable ? <button className={btn('secondary')} disabled={act.busy} data-testid="vms-evaluate"
                    onClick={() => void act.run(() => vmsxApi.evaluate(orgId), 'Enrollment re-evaluated.').then(() => enrollments.reload())}>Re-evaluate now</button> : undefined}>
                {(d) => (
                    <>
                        <div className="flex flex-wrap gap-1.5 mb-3" role="group" aria-label="Filter by enrollment status">
                            <button className={btn(status === '' ? 'primary' : 'secondary')} onClick={() => setStatus('')}>All ({nf.format(Object.values(d.by_status).reduce((a, b) => a + b, 0))})</button>
                            {Object.entries(d.by_status).map(([k, n]) => (
                                <button key={k} className={btn(status === k ? 'primary' : 'secondary')} onClick={() => setStatus(k)}>
                                    {STATUS[k as Enrollment['status']]?.label ?? k} ({nf.format(n)})</button>
                            ))}
                        </div>
                        <DataTable rows={d.items} rowKey={(e) => e.asset_id} empty="No asset in the inventory yet." columns={[
                            { key: 'a', header: 'Asset', render: (e) => <span><strong>{e.asset_name}</strong><span className="block text-[11px] text-foreground-muted">{[e.hostname, e.sources.map(sourceName).join(', ')].filter(Boolean).join(' · ')}</span></span> },
                            { key: 'ip', header: 'Address', render: (e) => <span className="font-mono text-xs">{e.address ?? '—'}</span> },
                            { key: 's', header: 'Decision', render: (e) => <span><StatusPill tone={STATUS[e.status].tone} label={STATUS[e.status].label} />
                                <span className="block text-[11px] text-foreground-muted max-w-md">{e.reason}</span></span> },
                            { key: 'sc', header: 'Scope', render: (e) => <span className="font-mono text-xs">{e.scope_value ?? '—'}</span> },
                            { key: 'l', header: 'Last scanned', render: (e) => <span className="text-xs">{fmt(e.last_scanned_at)}{e.open_findings ? <span className="block">{e.open_findings} open finding(s)</span> : null}</span> },
                            { key: 'x', header: '', render: (e) => (editable ? <ExclusionButton e={e} onDone={enrollments.reload} /> : null) },
                        ]} />
                    </>
                )}
            </Loaded>
        </>
    );
}

function ExclusionButton({ e, onDone }: { e: Enrollment; onDone: () => void }) {
    const { orgId } = useSession();
    const act = useAction();
    const [reason, setReason] = useState('');
    const [asking, setAsking] = useState(false);
    const excluded = e.status === 'manual_exclusion';
    if (!asking) return <button className={btn('secondary')} onClick={() => setAsking(true)}>{excluded ? 'Allow scanning' : 'Exclude'}</button>;
    return (
        <form className="flex items-center gap-1" onSubmit={(ev) => { ev.preventDefault(); void act.run(() => vmsxApi.exclude(orgId, e.asset_id, !excluded, reason.trim()), excluded ? 'Exclusion lifted.' : 'Asset excluded.').then((ok) => { if (ok) { setAsking(false); onDone(); } }); }}>
            <TextInput required minLength={3} placeholder="Reason (audited)" value={reason} onChange={(ev) => setReason(ev.target.value)} aria-label="Reason" />
            <button className={btn('primary')} type="submit" disabled={act.busy}>Confirm</button>
            <button className={btn('secondary')} type="button" onClick={() => setAsking(false)}>Cancel</button>
            {act.notice}
        </form>
    );
}

function PolicyForm({ p, editable, save, busy }: { p: Schemas['VmsScanPolicy']; editable: boolean; save: (b: Policy) => Promise<void>; busy: boolean }) {
    const [f, setF] = useState<Policy>(() => toUpdate(p));
    const [nets, setNets] = useState(p.protected_networks.join('\n'));
    const first = p.windows[0];
    const [win, setWin] = useState({ days: new Set(p.windows.map((w) => w.weekday)), start: hhmm(first?.start_minute ?? 60), end: hhmm(first?.end_minute ?? 300) });
    const windows = [...win.days].sort().map((d) => ({ weekday: d, start_minute: mins(win.start), end_minute: Math.max(mins(win.end), mins(win.start) + 1) }));
    function submit(e: FormEvent) {
        e.preventDefault();
        void save({ ...f, windows, protected_networks: nets.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean) });
    }
    const num = (k: keyof Policy) => (e: React.ChangeEvent<HTMLInputElement>) => setF({ ...f, [k]: Number(e.target.value) });
    return (
        <form onSubmit={submit} className="space-y-3" data-testid="vms-policy-form">
            <p className="text-xs flex flex-wrap items-center gap-2">
                <StatusPill tone={p.enabled ? 'good' : 'neutral'} label={p.enabled ? 'Policy enabled' : p.configured ? 'Policy disabled' : 'Not configured'} />
                {p.enabled && <StatusPill tone={p.in_window_now ? 'warning' : 'neutral'} label={p.in_window_now ? 'Inside a scan window now' : 'Outside the scan windows'} />}
                <span className="text-foreground-muted">{MODE[p.installation_mode]}</span>
                {p.updated_at && <span className="text-foreground-muted">Last saved {fmt(p.updated_at)}{p.updated_by_label ? ` by ${p.updated_by_label}` : ''}</span>}
            </p>
            <fieldset disabled={!editable || busy} className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">
                <Card className="!p-4 space-y-2">
                    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked, auto_enroll: e.target.checked && f.auto_enroll })} /> Scanning authorized for this organization</label>
                    <label className="flex items-center gap-2 text-sm"><input type="checkbox" checked={f.auto_enroll} disabled={!f.enabled} onChange={(e) => setF({ ...f, auto_enroll: e.target.checked })} /> Enroll eligible imported assets automatically</label>
                    <Field label="Authorization reference (contract, change ticket)"><TextInput value={f.authorization_reference} maxLength={200} onChange={(e) => setF({ ...f, authorization_reference: e.target.value })} /></Field>
                    <Field label="Enrollment activity"><select className={selectCls} value={f.enroll_activity} onChange={(e) => setF({ ...f, enroll_activity: e.target.value as Policy['enroll_activity'] })}>
                        <option value="ports">Service discovery (ports)</option><option value="discovery">Discovery</option></select></Field>
                    <Field label="Rescan every (days)"><TextInput type="number" min={1} max={90} value={f.rescan_interval_days} onChange={num('rescan_interval_days')} /></Field>
                </Card>
                <Card className="!p-4 space-y-2">
                    <p className="text-xs font-semibold">Scan windows</p>
                    <div className="flex flex-wrap gap-1">{DAYS.map((d, i) => (
                        <label key={d} className="text-xs flex items-center gap-1"><input type="checkbox" checked={win.days.has(i)} onChange={(e) => {
                            const s = new Set(win.days); if (e.target.checked) s.add(i); else s.delete(i); setWin({ ...win, days: s });
                        }} />{d}</label>))}</div>
                    <div className="flex gap-2">
                        <Field label="From"><TextInput type="time" value={win.start} onChange={(e) => setWin({ ...win, start: e.target.value })} /></Field>
                        <Field label="To"><TextInput type="time" value={win.end} onChange={(e) => setWin({ ...win, end: e.target.value })} /></Field>
                    </div>
                    <Field label="Timezone (IANA)"><TextInput value={f.timezone} onChange={(e) => setF({ ...f, timezone: e.target.value })} /></Field>
                </Card>
                <Card className="!p-4 space-y-2">
                    <Field label="Protected networks (never scanned; one per line)"><textarea className={`${selectCls} w-full font-mono text-xs h-20`} value={nets} onChange={(e) => setNets(e.target.value)} /></Field>
                    <div className="grid grid-cols-2 gap-2">
                        <Field label="Targets per scan"><TextInput type="number" min={1} max={256} value={f.max_targets_per_scan} onChange={num('max_targets_per_scan')} /></Field>
                        <Field label="Packets / second"><TextInput type="number" min={1} max={1000} value={f.max_rate_pps} onChange={num('max_rate_pps')} /></Field>
                        <Field label="Concurrent scans"><TextInput type="number" min={1} max={4} value={f.max_concurrent_scans} onChange={num('max_concurrent_scans')} /></Field>
                        <Field label="Address age limit (h)"><TextInput type="number" min={1} max={720} value={f.address_max_age_hours} onChange={num('address_max_age_hours')} /></Field>
                    </div>
                </Card>
            </fieldset>
            {editable ? <button className={btn('primary')} type="submit" disabled={busy} data-testid="vms-policy-save">Save policy</button>
                : <Tag>Read only: changing the policy needs the vms:scope permission</Tag>}
        </form>
    );
}

function toUpdate(p: Schemas['VmsScanPolicy']): Policy {
    return { enabled: p.enabled, auto_enroll: p.auto_enroll, enroll_activity: p.enroll_activity, rescan_interval_days: p.rescan_interval_days,
        protected_networks: p.protected_networks, windows: p.windows, timezone: p.timezone, max_targets_per_scan: p.max_targets_per_scan,
        max_rate_pps: p.max_rate_pps, max_concurrent_scans: p.max_concurrent_scans, address_max_age_hours: p.address_max_age_hours,
        authorization_reference: p.authorization_reference };
}
