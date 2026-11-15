'use client';

// Collectors and asset discovery settings. Each collector states what actually runs in this installation: a Wazuh sync
// reads the configured connector (read-only); network discovery and cloud inventory are configuration only (network
// discovery cannot even be enabled without a recorded authorization). Reconciliation runs are listed with their outcome.
import { useCallback, useState, type FormEvent } from 'react';
import { Radio, Trash2 } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { assetsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Kind = Schemas['CollectorCreate']['kind'];

export default function CollectorsPage() {
    const { orgId, can } = useSession();
    const collectors = useResource(useCallback(() => assetsApi.collectors(orgId), [orgId]));
    const runs = useResource(useCallback(() => assetsApi.syncRuns(orgId), [orgId]));
    const [f, setF] = useState({ name: '', kind: 'wazuh_sync' as Kind, interval: 1440, ranges: '', auth: '' });
    const act = useAction();
    const reloadAll = () => { collectors.reload(); runs.reload(); };

    async function create(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => assetsApi.createCollector(orgId, { name: f.name.trim(), kind: f.kind, interval_minutes: f.interval, site_id: null,
            authorization_reference: f.auth.trim(), settings: f.ranges.trim() ? { ranges: f.ranges.split(/[\s,]+/).filter(Boolean) } : {} }), 'Collector saved (disabled).');
        if (r) { setF({ ...f, name: '', ranges: '' }); reloadAll(); }
    }

    return (
        <>
            <PageHeader title="Collectors and discovery" icon={Radio}
                description="Where the inventory comes from. Nothing here scans a network or calls a cloud API in this release: active discovery needs a separate authorization, and every collector says what it actually does." />
            {act.notice}
            <Loaded title="Collectors" data={collectors.data} error={collectors.error} reload={collectors.reload} testid="collectors">
                {(d) => <DataTable rows={d.items} rowKey={(c) => c.id} empty="No collectors configured. The Wazuh sync can still run from the inventory." columns={[
                    { key: 'n', header: 'Collector', render: (c) => <span><strong>{c.name}</strong><span className="block text-[11px] text-foreground-muted">{c.kind.replace('_', ' ')} · every {c.interval_minutes} min</span></span> },
                    { key: 'e', header: 'What runs', render: (c) => <span className="text-xs">{c.execution}</span> },
                    { key: 's', header: 'Settings', render: (c) => <span className="text-xs font-mono">{Object.keys(c.settings).length ? JSON.stringify(c.settings) : '—'}</span> },
                    { key: 'a', header: 'Authorization', render: (c) => <span className="text-xs">{c.authorization_reference || '—'}</span> },
                    { key: 'st', header: 'State', render: (c) => <span className="text-xs"><StateTag state={c.enabled ? 'active' : 'draft'} label={c.enabled ? 'enabled' : 'disabled'} />
                        <span className="block text-foreground-muted">{c.last_run_at ? `${c.last_outcome?.replace('_', ' ')} ${fmt(c.last_run_at)}` : 'never run'}</span></span> },
                    { key: 'x', header: '', render: (c) => can('assets:manage') ? (
                        <span className="flex flex-wrap gap-1">
                            <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => assetsApi.runCollector(orgId, c.id), (r) => `${r.outcome.replace('_', ' ')}: ${r.detail || `${r.observed} observed`}`).then(reloadAll)}>Run now</button>
                            <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => assetsApi.updateCollector(orgId, c.id, { enabled: !c.enabled }), c.enabled ? 'Disabled.' : 'Enabled.').then(reloadAll)}>{c.enabled ? 'Disable' : 'Enable'}</button>
                            <button className={btn('ghost')} aria-label={`Remove ${c.name}`} disabled={act.busy} onClick={() => void act.run(() => assetsApi.deleteCollector(orgId, c.id), 'Removed.').then(reloadAll)}><Trash2 className="w-3.5 h-3.5" aria-hidden /></button>
                        </span>) : null },
                ]} />}
            </Loaded>
            {can('assets:manage') && (
                <Card>
                    <SectionTitle title="Add a collector" hint="Saved disabled" />
                    <form onSubmit={create} className="mt-3 grid sm:grid-cols-5 gap-2 items-end">
                        <Field label="Name"><TextInput required minLength={2} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
                        <Field label="Kind"><select className={selectCls} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as Kind })}>
                            <option value="wazuh_sync">Wazuh agent sync</option><option value="network_discovery">Network discovery (not authorized)</option>
                            <option value="cloud_inventory">Cloud inventory (no adapter)</option><option value="manual_import">Manual import</option></select></Field>
                        <Field label="Interval (min)"><TextInput type="number" min={15} max={10080} value={f.interval} onChange={(e) => setF({ ...f, interval: Number(e.target.value) })} /></Field>
                        <Field label="Ranges (discovery, optional)"><TextInput value={f.ranges} onChange={(e) => setF({ ...f, ranges: e.target.value })} placeholder="10.0.0.0/24" /></Field>
                        <Field label="Authorization reference"><TextInput value={f.auth} onChange={(e) => setF({ ...f, auth: e.target.value })} maxLength={200} /></Field>
                        <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy || f.name.trim().length < 2}>Save collector</button>
                    </form>
                </Card>
            )}
            <Loaded title="Reconciliation runs" data={runs.data} error={runs.error} reload={runs.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(r) => r.id} empty="No run yet." columns={[
                    { key: 's', header: 'Source', render: (r) => <span className="text-xs"><Tag>{r.source}</Tag> {r.source_state.replace('_', ' ')}</span> },
                    { key: 'o', header: 'Outcome', render: (r) => <StateTag state={r.outcome === 'completed' ? 'completed' : 'unconfigured'} label={r.outcome.replace('_', ' ')} /> },
                    { key: 'c', header: 'Counts', render: (r) => <span className="text-xs">{r.observed} observed · {r.created} new · {r.updated} updated · {r.conflicts} conflicts</span> },
                    { key: 'd', header: 'Detail', render: (r) => <span className="text-xs">{r.detail}</span> },
                    { key: 'w', header: 'When', render: (r) => <span className="text-xs">{r.requested_label} · {fmt(r.started_at)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
