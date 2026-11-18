'use client';

// Syslog and agentless sources of ONE organization. The Wazuh manager records the events it receives itself under
// agent 000; NovrSOC attributes them only through these registrations (the sender IP for syslog, the configured host for
// agentless). Unregistered, disabled and manager-local events are quarantined, never assigned to a tenant by default.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Plus } from 'lucide-react';
import { ConfirmDialog, Drawer, SeverityBadge, btn } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { orgApi, sourcesApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { DEVICE_TYPES, SOURCE_STATUS, deviceLabel } from './meta';

type Source = Schemas['LogSourceView'];
type Form = {
    name: string; kind: 'syslog' | 'agentless'; source_ip: string; host: string; device_type: Schemas['LogSourceCreate']['device_type'];
    vendor: string; protocol: Schemas['LogSourceCreate']['protocol']; port: string; site_id: string; network: string;
    authorization_reference: string; notes: string; enabled: boolean;
};
const EMPTY: Form = { name: '', kind: 'syslog', source_ip: '', host: '', device_type: 'firewall', vendor: '', protocol: 'udp', port: '514', site_id: '',
    network: '', authorization_reference: '', notes: '', enabled: true };

const fromSource = (s: Source): Form => ({ name: s.name, kind: s.kind, source_ip: s.source_ip ?? '', host: s.host, device_type: s.device_type, vendor: s.vendor,
    protocol: s.protocol, port: s.port ? String(s.port) : '', site_id: s.site_id ?? '', network: s.network ?? '',
    authorization_reference: s.authorization_reference, notes: s.notes, enabled: s.enabled });

export function LogSourcesPanel({ orgId, orgName, canManage }: { orgId: string; orgName: string; canManage: boolean }) {
    const { session, orgId: activeOrg } = useSession();
    const platformAdmin = session.role === 'super_admin';
    const [showRetired, setShowRetired] = useState(false);
    const list = useResource(useCallback(() => sourcesApi.list(orgId, showRetired), [orgId, showRetired]));
    const sites = useResource(useCallback(() => orgApi.sites(orgId), [orgId]));
    const others = useResource(useCallback(() => (platformAdmin ? orgApi.directory(activeOrg, { status: 'active' }) : Promise.resolve(null)), [platformAdmin, activeOrg]));
    const [editing, setEditing] = useState<Source | 'new' | null>(null);
    const [form, setForm] = useState<Form>(EMPTY);
    const [alertsOf, setAlertsOf] = useState<Source | null>(null);
    const [retiring, setRetiring] = useState<Source | null>(null);
    const [moving, setMoving] = useState<Source | null>(null);
    const [target, setTarget] = useState('');
    const act = useAction();
    const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm((f) => ({ ...f, [k]: v }));

    const save = async () => {
        const common = {
            name: form.name.trim(), device_type: form.device_type, vendor: form.vendor.trim(), protocol: form.protocol,
            port: form.port ? Number(form.port) : null, authorization_reference: form.authorization_reference.trim(), notes: form.notes, enabled: form.enabled,
        };
        if (editing === 'new') {
            await sourcesApi.create(orgId, { ...common, kind: form.kind, source_ip: form.kind === 'syslog' ? form.source_ip.trim() : null,
                host: form.kind === 'agentless' ? form.host.trim() : '', site_id: form.site_id || null, network: form.network.trim() || null });
        } else if (editing) {
            await sourcesApi.update(orgId, editing.id, { ...common, ...(editing.kind === 'syslog' ? { source_ip: form.source_ip.trim() } : { host: form.host.trim() }),
                site_id: form.site_id || null, clear_site: !form.site_id, network: form.network.trim() || null, clear_network: !form.network.trim() });
        }
        setEditing(null);
        list.reload();
    };

    return (
        <Loaded title="Syslog and agentless sources" testid="log-sources"
            hint={`Devices whose logs reach NovrSIEM directly (firewalls, routers, switches, Linux servers...). Their events go to ${orgName} only while registered and enabled here.`}
            action={canManage ? <button className={btn('primary')} data-testid="add-source" onClick={() => { setForm(EMPTY); setEditing('new'); }}><Plus className="w-3.5 h-3.5" aria-hidden />Register source</button> : undefined}
            data={list.data} error={list.error} reload={list.reload}>
            {(d) => (
                <>
                    {act.notice}
                    <label className="flex items-center gap-2 text-xs mb-2"><input type="checkbox" checked={showRetired} onChange={(e) => setShowRetired(e.target.checked)} />Show retired and reassigned sources</label>
                    <DataTable rows={d.items} rowKey={(s) => s.id} testid="log-sources-table"
                        empty="No source registered: events NovrSIEM receives from this organization's devices are quarantined." columns={[
                            { key: 'n', header: 'Source', render: (s) => <span>{s.name}<span className="block text-[11px] text-foreground-muted">{deviceLabel(s.device_type)}{s.vendor ? ` · ${s.vendor}` : ''} · {s.kind}</span></span> },
                            { key: 'm', header: 'Matches', render: (s) => <span className="font-mono text-xs">{s.kind === 'syslog' ? s.source_ip : s.host}<span className="block font-sans text-[11px] text-foreground-muted">{s.protocol}{s.port ? `/${s.port}` : ''}</span></span> },
                            { key: 'l', header: 'Site / network', className: 'hidden lg:table-cell', render: (s) => <span className="text-xs">{s.site_name ?? '—'}<span className="block font-mono text-[11px] text-foreground-muted">{s.network ?? ''}</span></span> },
                            { key: 's', header: 'Status', render: (s) => <span><StatusPill tone={SOURCE_STATUS[s.status].tone} label={SOURCE_STATUS[s.status].label} />
                                <span className="block text-[11px] text-foreground-muted mt-0.5">last event {fmt(s.last_event_at)}</span></span> },
                            { key: 'c', header: 'Events', className: 'hidden md:table-cell', render: (s) => <span className="tabular-nums">{s.event_count}</span> },
                            { key: 'a', header: '', render: (s) => (
                                <span className="flex flex-wrap gap-1 justify-end">
                                    <button className={btn('ghost')} onClick={() => setAlertsOf(s)}>Alerts</button>
                                    {canManage && !s.retired_at && <>
                                        <button className={btn('ghost')} onClick={() => { setForm(fromSource(s)); setEditing(s); }}>Edit</button>
                                        <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => sourcesApi.update(orgId, s.id, { enabled: !s.enabled }),
                                            s.enabled ? 'Disabled: its events are quarantined.' : 'Enabled.').then(() => list.reload())}>{s.enabled ? 'Disable' : 'Enable'}</button>
                                        <button className={btn('ghost')} onClick={() => setRetiring(s)}>Retire</button>
                                        {platformAdmin && <button className={btn('ghost')} onClick={() => { setTarget(''); setMoving(s); }}>Reassign</button>}
                                    </>}
                                </span>) },
                        ]} />

                    <Drawer open={editing !== null} onClose={() => setEditing(null)} title={editing === 'new' ? 'Register a source' : `Edit ${editing?.name ?? ''}`}
                        subtitle={`Organization: ${orgName}. A source is registered to one organization at a time.`}>
                        <div className="grid sm:grid-cols-2 gap-3">
                            <Field label="Name"><TextInput value={form.name} onChange={(e) => set('name', e.target.value)} /></Field>
                            <Field label="Kind"><select className={selectCls} value={form.kind} disabled={editing !== 'new'}
                                onChange={(e) => { const k = e.target.value as Form['kind']; setForm((f) => ({ ...f, kind: k, protocol: k === 'agentless' ? 'ssh' : 'udp', port: k === 'agentless' ? '22' : '514' })); }}>
                                <option value="syslog">Syslog (remote device)</option><option value="agentless">Agentless (SSH check by the manager)</option></select></Field>
                            {form.kind === 'syslog'
                                ? <Field label="Source IP (the sender address the manager sees)"><TextInput value={form.source_ip} onChange={(e) => set('source_ip', e.target.value)} /></Field>
                                : <Field label="Host (as configured on the manager)"><TextInput value={form.host} onChange={(e) => set('host', e.target.value)} /></Field>}
                            <Field label="Device type"><select className={selectCls} value={form.device_type} onChange={(e) => set('device_type', e.target.value as Form['device_type'])}>
                                {DEVICE_TYPES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
                            <Field label="Vendor"><TextInput value={form.vendor} placeholder="e.g. OPNsense" onChange={(e) => set('vendor', e.target.value)} /></Field>
                            <Field label="Protocol"><select className={selectCls} value={form.protocol} onChange={(e) => set('protocol', e.target.value as Form['protocol'])}>
                                {(form.kind === 'syslog' ? ['udp', 'tcp', 'tls'] : ['ssh']).map((p) => <option key={p}>{p}</option>)}</select></Field>
                            <Field label="Port"><TextInput inputMode="numeric" value={form.port} onChange={(e) => set('port', e.target.value.replace(/\D/g, '').slice(0, 5))} /></Field>
                            <Field label="Site"><select className={selectCls} value={form.site_id} onChange={(e) => set('site_id', e.target.value)}>
                                <option value="">No site</option>{(sites.data?.items ?? []).map((s) => <option key={s.id} value={s.id}>{s.name}{s.network_cidrs.length ? ` (${s.network_cidrs.join(', ')})` : ''}</option>)}</select></Field>
                            <Field label="Network (CIDR)"><TextInput value={form.network} placeholder="e.g. 10.10.0.0/24" onChange={(e) => set('network', e.target.value)} /></Field>
                            <Field label="Authorization reference"><TextInput value={form.authorization_reference} placeholder="contract clause or change ticket" onChange={(e) => set('authorization_reference', e.target.value)} /></Field>
                        </div>
                        <Field label="Notes"><TextInput value={form.notes} onChange={(e) => set('notes', e.target.value)} /></Field>
                        <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={form.enabled} onChange={(e) => set('enabled', e.target.checked)} />Enabled (when off, its events are quarantined)</label>
                        <div className="flex gap-2">
                            <button className={btn('primary', 'md')} disabled={act.busy || form.name.trim().length < 2 || form.authorization_reference.trim().length < 3 || (form.kind === 'syslog' ? !form.source_ip.trim() : !form.host.trim())}
                                onClick={() => void act.run(save, editing === 'new' ? 'Source registered.' : 'Source updated.')}>{editing === 'new' ? 'Register' : 'Save'}</button>
                            <button className={btn('secondary', 'md')} onClick={() => setEditing(null)}>Cancel</button>
                        </div>
                        {act.notice}
                    </Drawer>

                    <Drawer open={alertsOf !== null} onClose={() => setAlertsOf(null)} title={`Alerts from ${alertsOf?.name ?? ''}`} subtitle="The 25 most recent alerts attributed to this source">
                        {alertsOf && <SourceAlerts orgId={orgId} source={alertsOf} linkable={orgId === activeOrg} />}
                    </Drawer>

                    <ConfirmDialog open={retiring !== null} title={`Retire ${retiring?.name ?? ''}?`} tone="danger" confirmLabel="Retire"
                        body="The source is kept for history with its alerts; its future events are quarantined until a source is registered again."
                        reason={{ label: 'Reason', required: true }} onCancel={() => setRetiring(null)}
                        onConfirm={async (reason) => { const s = retiring; setRetiring(null); if (s) await act.run(() => sourcesApi.retire(orgId, s.id, reason), 'Retired.'); list.reload(); }} />

                    <Drawer open={moving !== null} onClose={() => setMoving(null)} title={`Reassign ${moving?.name ?? ''}`}
                        subtitle="The record is retired here with its history; a new one is registered in the target organization. Only events received afterwards go there.">
                        <Field label="Target organization"><select className={selectCls} value={target} onChange={(e) => setTarget(e.target.value)} data-testid="reassign-target">
                            <option value="">Choose…</option>{(others.data?.items ?? []).filter((o) => o.id !== orgId).map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
                        <ReassignForm busy={act.busy} disabled={!target} onSubmit={(reason) => void act.run(async () => {
                            if (moving) await sourcesApi.reassign(orgId, moving.id, { org_id: target, reason });
                            setMoving(null); list.reload();
                        }, 'Reassigned.')} />
                    </Drawer>
                </>
            )}
        </Loaded>
    );
}

function ReassignForm({ busy, disabled, onSubmit }: { busy: boolean; disabled: boolean; onSubmit: (reason: string) => void }) {
    const [reason, setReason] = useState('');
    return (
        <div className="space-y-2">
            <Field label="Reason (audited in both organizations)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} /></Field>
            <button className={btn('primary', 'md')} disabled={busy || disabled || reason.trim().length < 5} onClick={() => onSubmit(reason.trim())}>Reassign</button>
        </div>
    );
}

function SourceAlerts({ orgId, source, linkable }: { orgId: string; source: Source; linkable: boolean }) {
    const alerts = useResource(useCallback(() => sourcesApi.alerts(orgId, source.id), [orgId, source.id]));
    return (
        <Loaded title={`${source.event_count} event(s) in total`} data={alerts.data} error={alerts.error} reload={alerts.reload}>
            {(d) => <DataTable rows={d.items} rowKey={(a) => a.id} empty="No alert from this source yet." columns={[
                { key: 't', header: 'Observed', render: (a) => <span className="text-xs">{fmt(a.observed_at)}</span> },
                { key: 's', header: 'Severity', render: (a) => <SeverityBadge severity={a.severity} /> },
                { key: 'r', header: 'Rule', render: (a) => linkable ? <Link className="underline" href={`/app/alerts/${a.id}`}>{a.rule_description || a.rule_id}</Link> : <span>{a.rule_description || a.rule_id}</span> },
                { key: 'st', header: 'Status', render: (a) => <span className="text-xs">{a.status}</span> },
            ]} />}
        </Loaded>
    );
}
