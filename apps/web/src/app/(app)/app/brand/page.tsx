'use client';

import { useCallback, useState } from 'react';
import { ShieldCheck } from 'lucide-react';
import { Notice, PageHeader, SeverityBadge, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { protectionApi } from '../protection/api';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { useRouter } from 'next/navigation';
import { request } from '@/foundation/api/client';
import { useAction } from '@/foundation/ui/module';

const TYPES = ['domain', 'brand_name', 'executive', 'social_account', 'mobile_app', 'code_repository_term'] as const;

export default function BrandPage() {
    const { orgId, can } = useSession();
    const router = useRouter();
    const act = useAction();
    const subjects = useResource(useCallback(() => protectionApi.subjects(orgId), [orgId]));
    const findings = useResource(useCallback(() => protectionApi.findings(orgId), [orgId]));
    const runs = useResource(useCallback(() => protectionApi.runs(orgId), [orgId]));
    const [form, setForm] = useState({ type: 'domain' as (typeof TYPES)[number], value: '', consent: '' });
    const [msg, setMsg] = useState<Msg>(null);
    async function add() {
        setMsg(null);
        try { await protectionApi.addSubject(orgId, { type: form.type, value: form.value.trim(), consent_reference: form.consent.trim() || null }); subjects.reload(); }
        catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    async function run(id: string) {
        setMsg(null);
        try {
            const r = await protectionApi.runMonitoring(orgId, id);
            setMsg({ ok: r.outcome === 'completed', text: r.outcome === 'completed' ? `Run completed: ${r.new_findings} new finding(s).` : 'No lookalike source is configured: nothing was checked.' });
            findings.reload(); runs.reload();
        } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    async function triage(id: string, status: 'triaged' | 'actioned' | 'dismissed') {
        try { await protectionApi.triage(orgId, id, status); findings.reload(); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <>
            {act.notice}
            <PageHeader title="Brand protection" icon={ShieldCheck} description="Watch subjects and lookalike-domain monitoring. Candidates are generated deterministically; whether one is registered comes only from the configured resolver (unconfigured = no lookups). Executive subjects need a consent reference." />
            <Notice msg={msg} />
            <Loaded title="Watch subjects" data={subjects.data} error={subjects.error}>
                {(d) => (
                    <>
                        <DataTable testid="brand-subjects" rows={d.items} rowKey={(s) => s.id} empty="No watch subject." columns={[
                            { key: 't', header: 'Type', render: (s) => <Tag>{s.type}</Tag> },
                            { key: 'v', header: 'Value', render: (s) => <span className="font-mono">{s.value}</span> },
                            { key: 'r', header: '', render: (s) => s.type === 'domain' && can('protection:manage') ? <button className={btn('secondary')} onClick={() => void run(s.id)} data-testid="brand-run">Run monitoring</button> : null },
                        ]} />
                        {can('protection:manage') && (
                            <div className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="Type"><select className={inputCls} value={form.type} onChange={(e) => setForm({ ...form, type: e.target.value as (typeof TYPES)[number] })}>{TYPES.map((t) => <option key={t}>{t}</option>)}</select></Field>
                                <Field label="Value"><TextInput value={form.value} onChange={(e) => setForm({ ...form, value: e.target.value })} /></Field>
                                {form.type === 'executive' && <Field label="Consent reference (NDPA)"><TextInput value={form.consent} onChange={(e) => setForm({ ...form, consent: e.target.value })} /></Field>}
                                <button className={btn('primary')} disabled={form.value.trim().length < 2} onClick={() => void add()}>Add subject</button>
                            </div>
                        )}
                    </>
                )}
            </Loaded>
            <Loaded title="Findings" data={findings.data} error={findings.error}>
                {(d) => <DataTable testid="brand-findings" rows={d.items} rowKey={(f) => f.id} empty="No findings." columns={[
                    { key: 's', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} /> },
                    { key: 'v', header: 'Lookalike', render: (f) => <span><span className="font-mono">{f.value}</span><span className="block text-[11px] text-foreground-muted">{f.summary} · {f.source}</span></span> },
                    { key: 'st', header: 'Status', render: (f) => <Tag>{f.status}</Tag> },
                    { key: 'a', header: '', render: (f) => <span className="flex flex-wrap gap-1">
                        {can('protection:manage') && f.status === 'new' && <>
                            <button className={btn('ghost')} onClick={() => void triage(f.id, 'actioned')}>Takedown requested</button>
                            <button className={btn('ghost')} onClick={() => void triage(f.id, 'dismissed')}>Dismiss</button></>}
                        {can('cases:write') && <button className={btn('ghost')} onClick={() => void act.run(() => request<{ case_id: string }>(`/api/v1/protection/brand/findings/${encodeURIComponent(f.id)}/case`, { method: 'POST', orgId }), 'Case opened (or the existing one linked).').then((r) => r && router.push(`/app/cases/${r.case_id}`))}>Open case</button>}
                        {can('intel:manage') && <button className={btn('ghost')} onClick={() => void act.run(() => request<{ imported: number }>(`/api/v1/protection/brand/findings/${encodeURIComponent(f.id)}/indicator`, { method: 'POST', orgId }), (r) => (r.imported ? 'Added to Threat Insights: alerts will be matched against it.' : 'Already in Threat Insights.'))}>Add to Threat Insights</button>}
                    </span> },
                ]} />}
            </Loaded>
            <Loaded title="Monitoring runs" data={runs.data} error={runs.error}>
                {(d) => <DataTable rows={d.items} rowKey={(r) => r.id} empty="No run yet." columns={[
                    { key: 'w', header: 'When', render: (r) => <span className="text-xs">{fmt(r.started_at)}</span> },
                    { key: 'o', header: 'Outcome', render: (r) => <Tag>{r.outcome ?? 'running'}</Tag> },
                    { key: 'n', header: 'New findings', render: (r) => r.new_findings },
                ]} />}
            </Loaded>
        </>
    );
}
