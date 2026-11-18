'use client';

import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Radar } from 'lucide-react';
import { Notice, PageHeader, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { SectionTitle } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { insightsApi } from './api';

export default function InsightsPage() {
    const { orgId, can } = useSession();
    const indicators = useResource(useCallback(() => insightsApi.indicators(orgId), [orgId]));
    const matches = useResource(useCallback(() => insightsApi.matches(orgId), [orgId]));
    const corr = useResource(useCallback(() => insightsApi.correlations(orgId, 168), [orgId]));
    const feeds = useResource(useCallback(() => insightsApi.feedRuns(orgId), [orgId]));
    const [bundle, setBundle] = useState('');
    const [source, setSource] = useState('manual-upload');
    const [msg, setMsg] = useState<Msg>(null);
    const [ctx, setCtx] = useState<Record<string, string>>({});

    async function upload() {
        setMsg(null);
        try {
            const r = await insightsApi.uploadBundle(orgId, source, JSON.parse(bundle));
            setMsg({ ok: true, text: `Stored ${r.objects_stored} STIX object(s), ${r.indicators_imported} indicator(s), ${r.relationships} relationship(s); ${r.rejected.length} rejected.` });
            indicators.reload(); feeds.reload();
        } catch (e) { setMsg({ ok: false, text: e instanceof SyntaxError ? 'The bundle is not valid JSON.' : errorText(e) }); }
    }
    async function match() {
        setMsg(null);
        try { const r = await insightsApi.runMatch(orgId, 744); setMsg({ ok: true, text: `Scanned ${r.alerts_scanned} alert(s), ${r.new_matches} new match(es).` }); matches.reload(); corr.reload(); }
        catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    async function context(id: string) {
        try { const c = await insightsApi.context(orgId, id); setCtx({ ...ctx, [id]: c.related.map((r) => `${r.relationship_type} ${r.type} "${r.name}"`).join('; ') || 'No STIX relationships.' }); }
        catch (e) { setCtx({ ...ctx, [id]: errorText(e) }); }
    }

    return (
        <>
            <PageHeader title="Threat Insights" icon={Radar} description="Indicators of this organization (from STIX 2.1 bundles or the TAXII feeder), matched deterministically against its own alerts. Nothing is shared between organizations."
                actions={can('intel:manage') ? <button className={btn('primary')} onClick={() => void match()} data-testid="ti-match">Match last 31 days</button> : undefined} />
            <Notice msg={msg} />
            <Loaded title="Matches" data={matches.data} error={matches.error} reload={matches.reload}>
                {(d) => <DataTable testid="ti-matches" rows={d.items} rowKey={(m) => m.id} empty="No matches yet." columns={[
                    { key: 'i', header: 'Indicator', render: (m) => <span><Tag>{m.indicator.type}</Tag> <span className="font-mono">{m.indicator.value}</span></span> },
                    { key: 'a', header: 'Alert', render: (m) => <Link className="underline text-xs" href={`/app/alerts/${m.alert_id}`}>Open alert</Link> },
                    { key: 'c', header: 'Confidence', render: (m) => <span title={m.confidence.reasons.join('\n')}>{m.confidence.score} ({m.confidence.band})</span> },
                    { key: 'v', header: 'Verdict', render: (m) => m.verdict },
                ]} />}
            </Loaded>
            <div className="grid gap-5 lg:grid-cols-2">
                <Loaded title="Indicators" data={indicators.data} error={indicators.error}>
                    {(d) => <DataTable testid="ti-indicators" rows={d.items} rowKey={(i) => i.id} empty="No indicators yet." columns={[
                        { key: 'v', header: 'Indicator', render: (i) => <span><Tag>{i.type}</Tag> <span className="font-mono text-xs break-all">{i.value}</span>
                            {ctx[i.id] && <span className="block text-[11px] text-foreground-muted">{ctx[i.id]}</span>}</span> },
                        { key: 'p', header: 'Provenance', render: (i) => <span className="text-xs">{i.provenance.source} · TLP:{i.tlp.toUpperCase()} · {i.confidence}</span> },
                        { key: 'x', header: '', render: (i) => <button className={btn('ghost')} onClick={() => void context(i.id)}>STIX context</button> },
                    ]} />}
                </Loaded>
                <Loaded title="Correlations (7 days)" data={corr.data} error={corr.error}>
                    {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">No alerts share an observable or agent/rule pair.</p> : (
                        <ul className="text-sm space-y-1" data-testid="ti-correlations">{d.items.slice(0, 20).map((g) => (
                            <li key={g.basis + g.key}><Tag>{g.basis.replace(/_/g, ' ')}</Tag> {g.key} — {g.alert_ids.length} alerts, max {g.max_severity}</li>))}</ul>)}
                </Loaded>
            </div>
            <div className="grid gap-5 lg:grid-cols-2">
                <Loaded title="Feed runs" hint="STIX uploads and TAXII deliveries" data={feeds.data} error={feeds.error}>
                    {(d) => <DataTable rows={d.items} rowKey={(f) => f.id} empty="No feed has delivered yet. The TAXII feeder is disabled until a source is configured." columns={[
                        { key: 's', header: 'Source', render: (f) => f.source },
                        { key: 'n', header: 'Objects', render: (f) => `${f.objects_stored}/${f.objects_received} stored, ${f.rejected} rejected` },
                        { key: 't', header: 'When', render: (f) => <span className="text-xs">{fmt(f.received_at)}</span> },
                    ]} />}
                </Loaded>
                {can('intel:manage') && (
                    <div className="rounded-2xl border border-border bg-card p-4">
                        <SectionTitle title="Upload a STIX 2.1 bundle" hint="Validated against STIX 2.1; invalid objects are rejected and listed" />
                        <div className="mt-3 grid gap-2">
                            <Field label="Source name (provenance)"><TextInput value={source} onChange={(e) => setSource(e.target.value)} pattern="[a-z0-9_.-]{2,60}" /></Field>
                            <textarea className={`${inputCls} font-mono text-xs h-32`} value={bundle} onChange={(e) => setBundle(e.target.value)} placeholder='{"type": "bundle", "objects": [...]}' aria-label="STIX bundle JSON" />
                            <button className={btn('primary', 'md')} disabled={!bundle.trim()} onClick={() => void upload()}>Upload</button>
                        </div>
                    </div>
                )}
            </div>
        </>
    );
}
