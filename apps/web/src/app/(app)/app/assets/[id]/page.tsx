'use client';

// One canonical asset across the platform: identity and identifiers, ownership and classification, the Wazuh agent (with
// its source state), services and technologies, VMS findings next to Wazuh vulnerability detection (never merged),
// alerts, cases, SOAR runs, Threat Insights matches, CNII designation, history, trends and an NHAI summary.
import { identifierKindName, sourceName } from '@/foundation/ui/names';
import Link from 'next/link';
import { useParams } from 'next/navigation';
import { useCallback, useState, type FormEvent } from 'react';
import { ArrowLeft, Boxes } from 'lucide-react';
import { PageHeader, PriorityBadge, SeverityBadge, Tag, Timeline, btn } from '@/components/features/vms/kit';
import { ChartCard, Legend, TimeChart, type Series } from '@/components/features/vms/charts';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { assetsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { SourceBanner } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { NhaiSubjectPanel } from '../../insights/NhaiSubjectPanel';

const TREND: Series[] = [{ key: 'alerts', label: 'Alerts', token: '--vz-prog-3' }, { key: 'new_findings', label: 'New findings', token: '--vz-sev-high' },
    { key: 'resolved_findings', label: 'Verified fixed', token: '--vz-good' }];
type Upd = Schemas['AssetUpdate'];

export default function AssetDetailPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId, can } = useSession();
    const { data: d, error, reload } = useResource(useCallback(() => assetsApi.get(orgId, id), [orgId, id]));
    const [edit, setEdit] = useState<Upd | null>(null);
    const [mergeId, setMergeId] = useState('');
    const [reason, setReason] = useState('');
    const act = useAction();

    async function save(e: FormEvent) {
        e.preventDefault(); if (!edit) return;
        if (await act.run(() => assetsApi.update(orgId, id, edit), 'Asset updated.')) { setEdit(null); reload(); }
    }
    const a = d?.asset;
    return (
        <>
            <PageHeader title={a?.display_name ?? 'Asset'} icon={Boxes}
                meta={a && <><span>{a.kind.replace('_', ' ')}</span><span>first seen {fmt(a.first_seen_at)}</span><span>last seen {fmt(a.last_seen_at)}</span></>}
                actions={<Link href="/app/assets" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> Inventory</Link>} />
            {act.notice}
            {error ? <ApiErrorState error={error} onRetry={reload} /> : !d || !a ? <LoadingState label="Loading the asset" /> : (
                <>
                    {a.status === 'retired' && <Card><p className="text-sm">Retired{a.merged_into && <> and merged into <Link className="underline" href={`/app/assets/${a.merged_into}`}>another asset</Link></>}.</p></Card>}
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <Card>
                            <SectionTitle title="Identity" action={can('assets:manage') && a.status === 'active' && !edit
                                ? <button className={btn('secondary')} onClick={() => setEdit({ classification: a.classification, criticality: a.criticality, exposure: a.exposure, owner: a.owner, tags: a.tags })}>Edit</button> : undefined} />
                            {edit ? (
                                <form onSubmit={save} className="mt-3 grid gap-2 text-xs">
                                    <Field label="Classification"><select className={selectCls} value={edit.classification ?? ''} onChange={(e) => setEdit({ ...edit, classification: e.target.value as Upd['classification'] })}>
                                        {['server', 'workstation', 'network', 'domain', 'web', 'cloud', 'iot', 'unclassified'].map((x) => <option key={x}>{x}</option>)}</select></Field>
                                    <Field label="Criticality"><select className={selectCls} value={edit.criticality ?? ''} onChange={(e) => setEdit({ ...edit, criticality: e.target.value as Upd['criticality'] })}>
                                        {['critical', 'high', 'medium', 'low'].map((x) => <option key={x}>{x}</option>)}</select></Field>
                                    <Field label="Exposure"><select className={selectCls} value={edit.exposure ?? ''} onChange={(e) => setEdit({ ...edit, exposure: e.target.value as Upd['exposure'] })}>
                                        {['internet_facing', 'internal', 'unknown'].map((x) => <option key={x}>{x}</option>)}</select></Field>
                                    <Field label="Owner"><TextInput value={edit.owner ?? ''} onChange={(e) => setEdit({ ...edit, owner: e.target.value })} maxLength={200} /></Field>
                                    <Field label="Tags (comma separated, lower case)"><TextInput value={(edit.tags ?? []).join(', ')} onChange={(e) => setEdit({ ...edit, tags: e.target.value.split(',').map((t) => t.trim().toLowerCase()).filter(Boolean) })} /></Field>
                                    <div className="flex gap-2"><button className={btn('primary')} disabled={act.busy}>Save</button><button type="button" className={btn('ghost')} onClick={() => setEdit(null)}>Cancel</button></div>
                                </form>
                            ) : (
                                <dl className="mt-3 grid grid-cols-[8rem_1fr] gap-y-1.5 text-xs" data-testid="asset-identity">
                                    <dt className="text-foreground-muted">Criticality</dt><dd><SeverityBadge severity={a.criticality} /></dd>
                                    <dt className="text-foreground-muted">Classification</dt><dd>{a.classification}</dd>
                                    <dt className="text-foreground-muted">Exposure</dt><dd>{a.exposure.replace('_', ' ')}</dd>
                                    <dt className="text-foreground-muted">Owner</dt><dd>{a.owner || '—'}</dd>
                                    <dt className="text-foreground-muted">Site</dt><dd>{a.site_name ?? '—'}</dd>
                                    <dt className="text-foreground-muted">Addresses</dt><dd className="font-mono">{[a.primary_ip, a.fqdn, a.hostname].filter(Boolean).join(' · ') || '—'}</dd>
                                    <dt className="text-foreground-muted">Operating system</dt><dd>{[a.os_name, a.os_version].filter(Boolean).join(' ') || '—'}</dd>
                                    <dt className="text-foreground-muted">Monitoring</dt><dd><StateTag state={a.monitoring.state} /> {a.monitoring.last_vms_scan_at ? `scanned ${fmt(a.monitoring.last_vms_scan_at)}` : 'never scanned'}</dd>
                                    <dt className="text-foreground-muted">Tags</dt><dd className="flex flex-wrap gap-1">{a.tags.length ? a.tags.map((t) => <Tag key={t}>{t}</Tag>) : '—'}</dd>
                                    {d.cnii && <><dt className="text-foreground-muted">CNII</dt><dd><Tag strong>{String(d.cnii.sector)}</Tag> {String(d.cnii.owning_unit)} · {String(d.cnii.authorization)}</dd></>}
                                </dl>
                            )}
                        </Card>
                        <Card>
                            <SectionTitle title="Source identifiers" hint="Every identifier binds to exactly one asset" />
                            <ul className="mt-3 space-y-1 text-xs" data-testid="asset-identifiers">
                                {d.identifiers.map((i) => <li key={`${i.kind}-${i.value}-${i.site_key}`}><span className="font-mono">{identifierKindName(i.kind)}={i.value}</span> <span className="text-foreground-muted">({i.sources.join(', ')})</span></li>)}
                            </ul>
                        </Card>
                        <Card>
                            <SectionTitle title="NovrAgent" />
                            <div className="mt-3 space-y-2 text-xs" data-testid="asset-agent">
                                {!d.wazuh ? <p className="text-foreground-muted">No NovrAgent is linked to this asset: no host telemetry or configuration assessment.</p> : (
                                    <>
                                        {d.wazuh.source.state !== 'connected' && <SourceBanner source={d.wazuh.source} what="Agent data" />}
                                        <p>Agent <span className="font-mono">#{d.wazuh.agent_id}</span> {d.wazuh.name} · {d.wazuh.status ?? 'status unknown'} · {d.wazuh.agent_version ?? ''}</p>
                                        <p>Groups: {d.wazuh.groups.map((g) => <Tag key={g}>{g}</Tag>)}</p>
                                        {d.wazuh.vulnerabilities && <p>NovrAgent vulnerability detection: {d.wazuh.vulnerabilities.total ?? 'unavailable'} ({d.wazuh.vulnerabilities.critical ?? 0} critical, {d.wazuh.vulnerabilities.high ?? 0} high)</p>}
                                        {d.wazuh.sca?.policies.map((p) => <p key={p.policy_id}>SCA {p.name}: {p.score_percent}% ({p.failed} failed)</p>)}
                                        <Link className="underline" href={`/app/endpoints/${d.wazuh.agent_id}`}>Endpoint details</Link>
                                    </>
                                )}
                            </div>
                        </Card>
                    </div>
                    <Card>
                        <SectionTitle title="VMS findings" hint={d.detection_note} />
                        <div className="mt-3"><DataTable rows={d.findings} rowKey={(f) => f.id} empty="No VMS findings on this asset (an asset that was never scanned has none)." columns={[
                            { key: 't', header: 'Finding', render: (f) => <Link className="font-semibold text-purple hover:underline" href={`/app/vms/findings?finding=${f.id}`}>{f.title}</Link> },
                            { key: 's', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} /> },
                            { key: 'p', header: 'Priority', render: (f) => <PriorityBadge priority={f.priority} /> },
                            { key: 'st', header: 'Status', render: (f) => <StateTag state={f.status} /> },
                            { key: 'c', header: 'CVEs', render: (f) => <span className="text-xs font-mono">{f.cves.join(', ') || '—'}</span> },
                            { key: 'port', header: 'Port', render: (f) => f.port ?? '—' },
                        ]} /></div>
                    </Card>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <Card><SectionTitle title="Services and technologies" />
                            <div className="mt-3"><DataTable rows={d.services} rowKey={(s) => `${s.port}-${s.protocol}-${s.product}`} empty="No services recorded." columns={[
                                { key: 'p', header: 'Port', render: (s) => `${s.port}/${s.protocol || '-'}` }, { key: 'n', header: 'Service', render: (s) => s.name || '—' },
                                { key: 'pr', header: 'Product', render: (s) => `${s.product} ${s.version}`.trim() || '—' }, { key: 'src', header: 'Source', render: (s) => s.source }]} /></div></Card>
                        <Card><SectionTitle title="Alerts" />
                            <div className="mt-3"><DataTable rows={d.alerts} rowKey={(x) => x.id} empty="No alerts on this asset." columns={[
                                { key: 'r', header: 'Alert', render: (x) => <Link className="underline" href={`/app/alerts/${x.id}`}>{x.rule_description || x.rule_id}</Link> },
                                { key: 's', header: 'Severity', render: (x) => <SeverityBadge severity={x.severity} /> }, { key: 'st', header: 'Status', render: (x) => x.status },
                                { key: 'o', header: 'Observed', render: (x) => <span className="text-xs">{fmt(x.observed_at)}</span> }]} /></div></Card>
                        <Card><SectionTitle title="Cases and SOAR activity" />
                            <ul className="mt-3 text-xs space-y-1">
                                {d.cases.length === 0 && <li className="text-foreground-muted">No case involves this asset.</li>}
                                {d.cases.map((c) => <li key={c.id}><Link className="underline" href={`/app/cases/${c.id}`}>{c.reference}</Link> {c.title} <StateTag state={c.status} /></li>)}
                                {d.soar_runs.map((r) => <li key={r.run_id}>SOAR <Link className="underline" href={`/app/soar/runs/${r.run_id}`}>{r.playbook_name}</Link> ({r.mode}) <StateTag state={r.state} /></li>)}
                            </ul></Card>
                        <Card><SectionTitle title="Threat intelligence" hint="Indicator matches in this asset's alerts" />
                            <ul className="mt-3 text-xs space-y-1">
                                {d.intel.length === 0 && <li className="text-foreground-muted">No indicator matched this asset&apos;s alerts.</li>}
                                {d.intel.map((m) => <li key={m.match_id}><span className="font-mono">{m.indicator_type}={m.indicator_value}</span> confidence {m.confidence} · {m.verdict} · <Link className="underline" href={`/app/alerts/${m.alert_id}`}>alert</Link></li>)}
                            </ul></Card>
                    </div>
                    <ChartCard title="Twelve-week trend" hint="Alerts, new findings and verified fixes per week">
                        <TimeChart data={d.trend.map((t) => ({ day: t.week_start, alerts: t.alerts, new_findings: t.new_findings, resolved_findings: t.resolved_findings }))}
                            series={TREND} kind="line" stacked={false} label="Asset trend" markers />
                        <Legend series={TREND} />
                    </ChartCard>
                    <NhaiSubjectPanel title="NHAI asset summary" testid="asset-nhai" initial={d.nhai_jobs[0] ?? null} request={() => assetsApi.summarize(orgId, id)} />
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <Card><SectionTitle title="Discovery and change history" />
                            <div className="mt-3"><Timeline items={d.events.map((e) => ({ id: String(e.id), at: e.occurred_at, title: e.kind.replace(/_/g, ' '),
                                meta: `${sourceName(e.source)} · ${e.actor_label} · ${fmt(e.occurred_at)}`, body: JSON.stringify(e.details).slice(0, 300),
                                tone: e.kind === 'identifier_conflict' ? 'warning' : 'neutral' }))} /></div></Card>
                        {can('assets:manage') && a.status === 'active' && (
                            <Card><SectionTitle title="Deduplicate or retire" hint="Merging moves identifiers, services, findings and alerts here; audited" />
                                <div className="mt-3 grid gap-2 text-xs">
                                    <Field label="Duplicate asset id to merge into this one"><TextInput value={mergeId} onChange={(e) => setMergeId(e.target.value)} placeholder="UUID from the inventory or a conflict" /></Field>
                                    <Field label="Reason (recorded)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} /></Field>
                                    <div className="flex gap-2">
                                        <button className={btn('primary')} disabled={act.busy || !mergeId.trim() || reason.trim().length < 5}
                                            onClick={() => void act.run(() => assetsApi.merge(orgId, id, { source_asset_id: mergeId.trim(), reason: reason.trim() }), 'Merged.').then((r) => r && reload())}>Merge into this asset</button>
                                        <button className={btn('secondary')} disabled={act.busy || reason.trim().length < 5}
                                            onClick={() => void act.run(() => assetsApi.retire(orgId, id, reason.trim()), 'Retired.').then((r) => r && reload())}>Retire this asset</button>
                                    </div>
                                </div></Card>
                        )}
                    </div>
                </>
            )}
        </>
    );
}
