'use client';

// Scan configuration, scheduling and operations: approved scopes (authorization references, validity), scan jobs and
// their history, recurring schedules (disabled by default), and the local VMS worker. In this release a scope may only
// name a local test target, and nothing is scanned unless the installation enables scanning.
import { useCallback, useState, type FormEvent } from 'react';
import { ScanSearch } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { vmsxApi } from '@/foundation/api/modules';
import { newIdempotencyKey } from '@/foundation/api/paths';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Activity = 'vuln_openvas' | 'ports' | 'discovery' | 'vuln_nuclei';

export default function ScansPage() {
    const { orgId, can } = useSession();
    const status = useResource(useCallback(() => vmsxApi.status(orgId), [orgId]));
    const scopes = useResource(useCallback(() => vmsxApi.scopes(orgId), [orgId]));
    const scans = useResource(useCallback(() => vmsxApi.scans(orgId), [orgId]));
    const schedules = useResource(useCallback(() => vmsxApi.schedules(orgId), [orgId]));
    const [scope, setScope] = useState({ kind: 'domain' as 'ip' | 'domain', value: '', ref: '', days: 30 });
    const [scan, setScan] = useState({ scopeId: '', targets: '', activity: 'vuln_openvas' as Activity });
    const [sch, setSch] = useState({ scopeId: '', name: '', targets: '', activity: 'vuln_openvas' as Activity, cadence: 'weekly' as 'daily' | 'weekly' | 'monthly' });
    const act = useAction();
    const all = () => { scopes.reload(); scans.reload(); schedules.reload(); };

    async function addScope(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => vmsxApi.createScope(orgId, { entry: { kind: scope.kind, value: scope.value.trim(), site_id: null }, allowed_activities: ['vuln_openvas', 'ports'],
            authorization_reference: scope.ref.trim(), valid_days: scope.days }), 'Scope approved.')) all();
    }
    async function requestScan(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => vmsxApi.createScan(orgId, { idempotency_key: newIdempotencyKey('scan'), scope_id: scan.scopeId, activity: scan.activity,
            targets: scan.targets.split(',').map((t) => t.trim()).filter(Boolean), profile: 'standard' }), 'Scan queued. The local worker claims it on its next cycle.')) scans.reload();
    }
    async function addSchedule(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => vmsxApi.createSchedule(orgId, { scope_id: sch.scopeId, name: sch.name.trim(), activity: sch.activity, cadence: sch.cadence, enabled: false,
            targets: sch.targets.split(',').map((t) => t.trim()).filter(Boolean) }), 'Schedule saved (disabled).')) schedules.reload();
    }
    const scopeOpts = (scopes.data?.items ?? []).map((s) => <option key={s.id} value={s.id}>{s.entry.value}</option>);

    return (
        <>
            <PageHeader title="Scans and schedules" icon={ScanSearch}
                description="Scans run only inside an approved, unexpired scope, by the VMS worker on Server 2, which reaches only the API. Scope is re-checked when a scan is requested, when it is claimed and for every result." />
            {status.data && <p className="text-xs flex items-center gap-2" data-testid="vms-scanning"><StatusPill tone={status.data.scanning === 'enabled' ? 'warning' : 'neutral'} label={`Scanning ${status.data.scanning}`} /> {status.data.reason}</p>}
            {act.notice}
            <div className="grid gap-5 lg:grid-cols-2">
                <Loaded title="Approved scopes" data={scopes.data} error={scopes.error} reload={scopes.reload}>
                    {(d) => (
                        <>
                            <DataTable testid="vms-scopes" rows={d.items} rowKey={(s) => s.id} empty="No scope approved." columns={[
                                { key: 'v', header: 'Scope', render: (s) => <span><Tag>{s.entry.kind}</Tag> <span className="font-mono">{s.entry.value}</span></span> },
                                { key: 'a', header: 'Activities', render: (s) => <span className="text-xs">{s.allowed_activities.join(', ')}</span> },
                                { key: 'r', header: 'Authorization', render: (s) => <span className="text-xs">{s.authorization_reference} · until {fmt(s.valid_until)}</span> },
                            ]} />
                            {can('vms:scope') && (
                                <form onSubmit={addScope} className="mt-3 flex flex-wrap items-end gap-2">
                                    <Field label="Kind"><select className={selectCls} value={scope.kind} onChange={(e) => setScope({ ...scope, kind: e.target.value as 'ip' | 'domain' })}><option value="domain">domain</option><option value="ip">ip</option></select></Field>
                                    <Field label="Local test target"><TextInput required value={scope.value} placeholder="lab.alpha.test or 127.0.0.1" onChange={(e) => setScope({ ...scope, value: e.target.value })} /></Field>
                                    <Field label="Authorization reference"><TextInput required minLength={3} value={scope.ref} onChange={(e) => setScope({ ...scope, ref: e.target.value })} /></Field>
                                    <Field label="Valid (days)"><TextInput type="number" min={1} max={365} value={scope.days} onChange={(e) => setScope({ ...scope, days: Number(e.target.value) })} /></Field>
                                    <button className={btn('primary')} type="submit" disabled={act.busy}>Approve scope</button>
                                </form>
                            )}
                        </>
                    )}
                </Loaded>
                <Loaded title="Scan operations and history" data={scans.data} error={scans.error} reload={scans.reload}>
                    {(d) => (
                        <>
                            <DataTable testid="vms-scans" rows={d.items} rowKey={(s) => s.id} empty="No scan requested." columns={[
                                { key: 't', header: 'Targets', render: (s) => <span className="font-mono text-xs">{s.targets.join(', ')}</span> },
                                { key: 'a', header: 'Activity', render: (s) => <Tag>{s.activity}</Tag> },
                                { key: 's', header: 'State', render: (s) => <span className="text-xs"><StateTag state={s.state} />{s.error ? ` (${s.error})` : ''}</span> },
                                { key: 'w', header: 'Requested / finished', render: (s) => <span className="text-xs">{fmt(s.created_at)}<span className="block text-foreground-muted">{fmt(s.finished_at)}</span></span> },
                            ]} />
                            {can('vms:scan') && (scopes.data?.items.length ?? 0) > 0 && (
                                <form onSubmit={requestScan} className="mt-3 flex flex-wrap items-end gap-2">
                                    <Field label="Scope"><select className={selectCls} required value={scan.scopeId} onChange={(e) => setScan({ ...scan, scopeId: e.target.value })}><option value="">Choose…</option>{scopeOpts}</select></Field>
                                    <Field label="Targets (comma separated)"><TextInput required value={scan.targets} onChange={(e) => setScan({ ...scan, targets: e.target.value })} /></Field>
                                    <Field label="Activity"><select className={selectCls} value={scan.activity} onChange={(e) => setScan({ ...scan, activity: e.target.value as Activity })}>
                                        <option value="vuln_openvas">vulnerability (Greenbone)</option><option value="ports">ports</option></select></Field>
                                    <button className={btn('primary')} type="submit" disabled={act.busy}>Request scan</button>
                                </form>
                            )}
                        </>
                    )}
                </Loaded>
            </div>
            <Loaded title="Schedules" hint="Recurring scans; a due schedule creates a job only where scanning is enabled" data={schedules.data} error={schedules.error} reload={schedules.reload} testid="vms-schedules">
                {(d) => (
                    <>
                        <DataTable rows={d.items} rowKey={(s) => s.id} empty="No schedules." columns={[
                            { key: 'n', header: 'Schedule', render: (s) => <span><strong>{s.name}</strong><span className="block text-[11px] text-foreground-muted">{s.cadence} · {s.activity} · {s.targets.join(', ')}</span></span> },
                            { key: 'x', header: 'What runs', render: (s) => <span className="text-xs">{s.execution}</span> },
                            { key: 'nx', header: 'Next run', render: (s) => <span className="text-xs">{fmt(s.next_run_at)}</span> },
                            { key: 'e', header: '', render: (s) => (can('vms:scope') ? <button className={btn('secondary')} disabled={act.busy}
                                onClick={() => void act.run(() => vmsxApi.toggleSchedule(orgId, s.id, !s.enabled), s.enabled ? 'Disabled.' : 'Enabled.').then(() => schedules.reload())}>{s.enabled ? 'Disable' : 'Enable'}</button>
                                : <StateTag state={s.enabled ? 'active' : 'draft'} label={s.enabled ? 'enabled' : 'disabled'} />) },
                        ]} />
                        {can('vms:scope') && (scopes.data?.items.length ?? 0) > 0 && (
                            <form onSubmit={addSchedule} className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="Name"><TextInput required minLength={3} value={sch.name} onChange={(e) => setSch({ ...sch, name: e.target.value })} /></Field>
                                <Field label="Scope"><select className={selectCls} required value={sch.scopeId} onChange={(e) => setSch({ ...sch, scopeId: e.target.value })}><option value="">Choose…</option>{scopeOpts}</select></Field>
                                <Field label="Targets"><TextInput required value={sch.targets} onChange={(e) => setSch({ ...sch, targets: e.target.value })} /></Field>
                                <Field label="Cadence"><select className={selectCls} value={sch.cadence} onChange={(e) => setSch({ ...sch, cadence: e.target.value as typeof sch.cadence })}>
                                    <option value="daily">daily</option><option value="weekly">weekly</option><option value="monthly">monthly</option></select></Field>
                                <button className={btn('primary')} type="submit" disabled={act.busy}>Save schedule</button>
                            </form>
                        )}
                    </>
                )}
            </Loaded>
            {status.data && status.data.workers.length > 0 && (
                <Loaded title="Workers" data={status.data} error={null}>
                    {(s) => <ul className="text-xs">{s.workers.map((w) => <li key={w.identity_name}>{w.identity_name} · v{w.component_version} · {w.state} · {w.stale ? 'stale' : 'reporting'} · {fmt(w.last_heartbeat_at)}</li>)}</ul>}
                </Loaded>
            )}
        </>
    );
}
