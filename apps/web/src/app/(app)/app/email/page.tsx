'use client';

import { useCallback, useState } from 'react';
import { Mail } from 'lucide-react';
import { Notice, PageHeader, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { protectionApi } from '../protection/api';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { useRouter } from 'next/navigation';
import { request } from '@/foundation/api/client';
import { useAction } from '@/foundation/ui/module';

export default function EmailPage() {
    const { orgId, can } = useSession();
    const router = useRouter();
    const act = useAction();
    const domains = useResource(useCallback(() => protectionApi.domains(orgId), [orgId]));
    const reports = useResource(useCallback(() => protectionApi.dmarc(orgId), [orgId]));
    const [domain, setDomain] = useState('');
    const [xml, setXml] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    async function add() {
        setMsg(null);
        try { await protectionApi.addDomain(orgId, domain.trim().toLowerCase()); setDomain(''); domains.reload(); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    async function upload() {
        setMsg(null);
        try { const r = await protectionApi.uploadDmarc(orgId, xml); setMsg({ ok: true, text: `Imported ${r.messages_total} message(s), ${r.messages_failing} failing.` }); setXml(''); reports.reload(); domains.reload(); }
        catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <>
            {act.notice}
            <PageHeader title="Email security" icon={Mail} description="Your domains and their DMARC aggregate reports. Domain ownership verification needs a DNS adapter, which is not configured, so domains stay pending. Reports are uploaded or delivered by a safe adapter; nothing here sends mail." />
            <Notice msg={msg} />
            <Loaded title="Domains" data={domains.data} error={domains.error}>
                {(d) => (
                    <>
                        <DataTable testid="email-domains" rows={d.items} rowKey={(x) => x.id} empty="No domain registered." columns={[
                            { key: 'd', header: 'Domain', render: (x) => <span className="font-mono">{x.domain}</span> },
                            { key: 'v', header: 'Verification', render: (x) => <StatusPill tone={x.verification === 'verified' ? 'good' : 'neutral'} label={x.verification} /> },
                            { key: 'txt', header: 'TXT record', className: 'hidden md:table-cell', render: (x) => <span className="text-[11px] font-mono">{x.verification_txt_name}</span> },
                            { key: 'p', header: 'DMARC policy', render: (x) => x.dmarc_policy ? <Tag>p={x.dmarc_policy}</Tag> : <span className="text-xs text-foreground-muted">unknown</span> },
                        ]} />
                        {can('protection:manage') && (
                            <div className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="Domain"><TextInput value={domain} onChange={(e) => setDomain(e.target.value)} placeholder="example.com" /></Field>
                                <button className={btn('primary')} disabled={!domain.trim()} onClick={() => void add()}>Add domain</button>
                            </div>
                        )}
                    </>
                )}
            </Loaded>
            <Loaded title="DMARC aggregate reports" data={reports.data} error={reports.error}>
                {(d) => (
                    <>
                        <DataTable testid="dmarc-reports" rows={d.items} rowKey={(x) => x.id} empty="No report imported." columns={[
                            { key: 'd', header: 'Domain', render: (x) => <span className="font-mono">{x.domain}</span> },
                            { key: 'r', header: 'Reporter', render: (x) => x.reporter },
                            { key: 'p', header: 'Period', render: (x) => <span className="text-xs">{fmt(x.period_start)} – {fmt(x.period_end)}</span> },
                            { key: 'm', header: 'Messages', render: (x) => <span>{x.messages_total} <span className={x.messages_failing ? 'text-red' : ''}>({x.messages_failing} failing)</span>
                                {x.messages_failing > 0 && can('cases:write') && <button className={`${btn('ghost')} ml-1`} onClick={() => void act.run(() => request<{ case_id: string }>(`/api/v1/protection/email/dmarc-reports/${encodeURIComponent(x.id)}/case`, { method: 'POST', orgId }), 'Case opened.').then((r) => r && router.push(`/app/cases/${r.case_id}`))}>Open case</button>}</span> },
                            { key: 's', header: 'Sources', className: 'hidden lg:table-cell', render: (x) => <span className="text-[11px]">{x.records.map((r) => `${r.source_ip}×${r.count} ${r.dkim}/${r.spf}`).join(', ')}</span> },
                        ]} />
                        {can('protection:manage') && (
                            <div className="mt-3 grid gap-2">
                                <textarea className={`${inputCls} font-mono text-xs h-28`} value={xml} onChange={(e) => setXml(e.target.value)} aria-label="DMARC aggregate report XML" placeholder="<feedback>…</feedback>" />
                                <button className={btn('primary', 'md')} disabled={xml.trim().length < 50} onClick={() => void upload()}>Import report</button>
                            </div>
                        )}
                    </>
                )}
            </Loaded>
        </>
    );
}
