'use client';

// Unified asset inventory: ONE canonical identity per asset, reconciled from Wazuh agents, VMS hosts, email domains and
// manual entries. Monitoring state is derived (Wazuh agent + a VMS scan in 30 days). Identifier conflicts are never
// resolved silently: they wait here for an analyst to merge.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { Boxes, RefreshCw } from 'lucide-react';
import { EmptyState, PageHeader, SearchBox, Select, SeverityBadge, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { assetsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, initialParam, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const KINDS = [['', 'All kinds'], ['host', 'Hosts'], ['domain', 'Domains'], ['web_application', 'Web applications'], ['network_device', 'Network devices'],
    ['cloud_resource', 'Cloud resources']] as const;
const CRIT = [['', 'Any criticality'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']] as const;
const MON = [['', 'Any monitoring'], ['monitored', 'Monitored'], ['partial', 'Partially monitored'], ['unmonitored', 'Unmonitored']] as const;
type K = (typeof KINDS)[number][0]; type C = (typeof CRIT)[number][0]; type M = (typeof MON)[number][0];

export default function AssetsPage() {
    const { orgId, can, session } = useSession();
    const [kind, setKind] = useState<K>('');
    const [crit, setCrit] = useState<C>(() => (CRIT.find(([k]) => k === initialParam('criticality'))?.[0] ?? ''));
    const [mon, setMon] = useState<M>(() => (MON.find(([k]) => k === initialParam('monitoring'))?.[0] ?? ''));
    const [q, setQ] = useState('');
    const list = useResource(useCallback(() => assetsApi.list(orgId, { kind, criticality: crit, monitoring: mon, q, limit: 500 }), [orgId, kind, crit, mon, q]));
    const conflicts = useResource(useCallback(() => assetsApi.conflicts(orgId), [orgId]));
    const [f, setF] = useState({ kind: 'host' as Schemas['AssetCreate']['kind'], name: '', ip: '', fqdn: '', hostname: '', criticality: 'medium' as Schemas['AssetCreate']['criticality'], owner: '' });
    const act = useAction();

    async function add(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => assetsApi.create(orgId, { kind: f.kind, display_name: f.name.trim(), ip: f.ip.trim() || null, fqdn: f.fqdn.trim() || null,
            hostname: f.hostname.trim() || null, criticality: f.criticality, owner: f.owner.trim(), classification: 'unclassified', exposure: 'unknown', tags: [], site_id: null }),
            (a) => `Saved: ${a.display_name}. An existing identity is reused rather than duplicated.`);
        if (r) { setF({ ...f, name: '', ip: '', fqdn: '', hostname: '' }); list.reload(); }
    }

    return (
        <>
            <PageHeader title="Asset inventory" icon={Boxes}
                description={`Every asset of ${session.active_org.name}, once: Wazuh agents, VMS hosts, email domains and manual entries reconcile to one canonical identity with its source identifiers and discovery history.`}
                actions={can('assets:manage') ? <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => assetsApi.syncWazuh(orgId),
                    (r) => `Wazuh sync ${r.outcome.replace('_', ' ')}: ${r.observed} observed, ${r.created} new, ${r.conflicts} conflict(s). ${r.detail}`).then(() => list.reload())} data-testid="wazuh-sync">
                    <RefreshCw className="w-3.5 h-3.5" aria-hidden /> Sync from Wazuh</button> : undefined} />
            {act.notice}
            <div className="flex flex-wrap items-center gap-2">
                <Select label="Kind" options={KINDS} value={kind} onChange={setKind} />
                <Select label="Criticality" options={CRIT} value={crit} onChange={setCrit} />
                <Select label="Monitoring" options={MON} value={mon} onChange={setMon} />
                <SearchBox label="Search assets" placeholder="Name, hostname, IP, owner or identifier" value={q} onSubmit={setQ} />
            </div>
            <Loaded title="Assets" hint={list.data ? `${list.data.total} asset(s) · ${Object.entries(list.data.by_monitoring).map(([k, v]) => `${v} ${k}`).join(' · ')}` : undefined}
                data={list.data} error={list.error} reload={list.reload} testid="assets">
                {(d) => d.items.length === 0 ? <EmptyState title="No assets" body={q || kind || crit || mon ? 'No asset matches these filters.' : 'Sync from Wazuh, run a VMS scan or add assets by hand.'} />
                    : <DataTable testid="assets-table" rows={d.items} rowKey={(a) => a.id} columns={[
                        { key: 'n', header: 'Asset', render: (a) => <Link href={`/app/assets/${a.id}`} className="font-semibold text-purple hover:underline">{a.display_name}<span className="block text-[11px] font-normal text-foreground-muted">{a.kind.replace('_', ' ')} · {a.primary_ip ?? a.fqdn ?? a.hostname ?? ''}</span></Link> },
                        { key: 'c', header: 'Criticality', render: (a) => <SeverityBadge severity={a.criticality} /> },
                        { key: 'm', header: 'Monitoring', render: (a) => <span className="text-xs"><StateTag state={a.monitoring.state} />{a.monitoring.cnii_designated && <Tag strong>CNII</Tag>}</span> },
                        { key: 'f', header: 'Open findings', render: (a) => <span className="text-xs tabular-nums">{a.open_findings}{a.critical_findings ? ` (${a.critical_findings} critical)` : ''}</span> },
                        { key: 'al', header: 'Open alerts', render: (a) => <span className="text-xs tabular-nums">{a.open_alerts}</span> },
                        { key: 's', header: 'Sources', className: 'hidden md:table-cell', render: (a) => <span className="flex flex-wrap gap-1">{a.sources.map((s) => <Tag key={s}>{s}</Tag>)}</span> },
                        { key: 'o', header: 'Owner', className: 'hidden lg:table-cell', render: (a) => <span className="text-xs">{a.owner || '—'}{a.site_name && <span className="block text-foreground-muted">{a.site_name}</span>}</span> },
                        { key: 'l', header: 'Last seen', className: 'hidden lg:table-cell', render: (a) => <span className="text-xs text-foreground-muted">{fmt(a.last_seen_at)}</span> },
                    ]} />}
            </Loaded>
            <Loaded title="Identifier conflicts" hint="An identifier reported for one asset is already bound to another: review and merge if they are the same"
                data={conflicts.data} error={conflicts.error} reload={conflicts.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(c) => String(c.event_id)} empty="No conflicts." columns={[
                    { key: 'a', header: 'Reported for', render: (c) => <Link className="underline" href={`/app/assets/${c.asset_id}`}>{c.asset_name}</Link> },
                    { key: 'i', header: 'Identifier', render: (c) => <span className="font-mono text-xs">{c.identifier_kind}={c.identifier_value}</span> },
                    { key: 'b', header: 'Bound to', render: (c) => (c.bound_to_asset_id ? <Link className="underline" href={`/app/assets/${c.bound_to_asset_id}`}>{c.bound_to_asset_name}</Link> : '—') },
                    { key: 's', header: 'Source', render: (c) => <span className="text-xs">{c.source} · {fmt(c.occurred_at)}</span> },
                ]} />}
            </Loaded>
            {can('assets:manage') && (
                <Card>
                    <SectionTitle title="Add an asset" hint="At least one identifier: IP address, FQDN/domain or hostname" />
                    <form onSubmit={add} className="mt-3 grid sm:grid-cols-4 gap-2 items-end" data-testid="asset-form">
                        <Field label="Kind"><select className={selectCls} value={f.kind} onChange={(e) => setF({ ...f, kind: e.target.value as typeof f.kind })}>
                            {KINDS.slice(1).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
                        <Field label="Name"><TextInput required value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} maxLength={200} /></Field>
                        <Field label="IP address"><TextInput value={f.ip} onChange={(e) => setF({ ...f, ip: e.target.value })} /></Field>
                        <Field label="FQDN or domain"><TextInput value={f.fqdn} onChange={(e) => setF({ ...f, fqdn: e.target.value })} /></Field>
                        <Field label="Hostname"><TextInput value={f.hostname} onChange={(e) => setF({ ...f, hostname: e.target.value })} /></Field>
                        <Field label="Criticality"><select className={selectCls} value={f.criticality} onChange={(e) => setF({ ...f, criticality: e.target.value as typeof f.criticality })}>
                            {CRIT.slice(1).map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
                        <Field label="Owner (team or unit)"><TextInput value={f.owner} onChange={(e) => setF({ ...f, owner: e.target.value })} maxLength={200} /></Field>
                        <button className={btn('primary', 'md')} disabled={act.busy || !f.name.trim()}>Add asset</button>
                    </form>
                </Card>
            )}
        </>
    );
}
