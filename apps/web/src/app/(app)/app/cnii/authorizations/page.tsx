'use client';

// CNII authorization records: the reference, issuing authority, scope and validity that permit monitoring. Without an
// active record, nothing can be designated or scheduled. Revoking one stops its assets' schedules.
import { useCallback, useState, type FormEvent } from 'react';
import { FileCheck2 } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { cniiApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { CniiGate } from '../CniiGate';

type Sector = Schemas['CniiAuthorizationCreate']['sectors'][number];
const SECTORS: Sector[] = ['power', 'water', 'ict', 'finance', 'health', 'publicadmin', 'education', 'defence', 'transport', 'food', 'safety', 'industrial', 'mines'];
const day = (d: number) => new Date(Date.now() + d * 86_400_000).toISOString().slice(0, 10);

export default function CniiAuthorizationsPage() {
    const { orgId, can } = useSession();
    const list = useResource(useCallback(() => cniiApi.authorizations(orgId), [orgId]));
    const [f, setF] = useState({ ref: '', authority: '', scope: '', sectors: new Set<Sector>(), from: day(0), until: day(365), doc: '' });
    const [why, setWhy] = useState('');
    const act = useAction();

    async function create(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => cniiApi.createAuthorization(orgId, { reference: f.ref.trim(), issuing_authority: f.authority.trim(), scope_description: f.scope.trim(),
            sectors: [...f.sectors], valid_from: new Date(f.from).toISOString(), valid_until: new Date(f.until).toISOString(), document_sha256: f.doc.trim() || null }),
            'Authorization recorded.')) { list.reload(); setF({ ...f, ref: '', scope: '', doc: '' }); }
    }

    return (
        <>
            <PageHeader title="CNII authorizations" icon={FileCheck2}
                description="The authorization records that permit monitoring of designated CNII assets: who issued them, what they cover and until when. A record can only name sectors your designation covers." />
            {act.notice}
            <CniiGate data={list.data} error={list.error} reload={list.reload}>
                {(d) => (
                    <>
                        <Card>
                            <SectionTitle title="Records" />
                            <div className="mt-3"><DataTable testid="cnii-authorizations" rows={d.items} rowKey={(a) => a.id} empty="No authorization recorded." columns={[
                                { key: 'r', header: 'Reference', render: (a) => <span><strong>{a.reference}</strong><span className="block text-[11px] text-foreground-muted">{a.issuing_authority}</span></span> },
                                { key: 's', header: 'Sectors', render: (a) => <span className="flex flex-wrap gap-1">{a.sectors.map((s) => <Tag key={s}>{s}</Tag>)}</span> },
                                { key: 'sc', header: 'Scope', render: (a) => <span className="text-xs">{a.scope_description}</span> },
                                { key: 'v', header: 'Validity', render: (a) => <span className="text-xs"><StateTag state={a.state} /><span className="block text-foreground-muted">{fmt(a.valid_from)} – {fmt(a.valid_until)}</span></span> },
                                { key: 'm', header: 'Assets', render: (a) => a.monitored_assets },
                                { key: 'x', header: '', render: (a) => (can('cnii:manage') && a.state === 'active' ? (
                                    <button className={btn('ghost')} disabled={act.busy || why.trim().length < 5} title="Enter a revocation reason below first"
                                        onClick={() => void act.run(() => cniiApi.revoke(orgId, a.id, why.trim()), 'Revoked; its schedules were disabled.').then(() => list.reload())}>Revoke</button>) : a.revoked_reason ? <span className="text-xs">{a.revoked_reason}</span> : null) },
                            ]} /></div>
                            {can('cnii:manage') && <div className="mt-3 max-w-md"><Field label="Revocation reason"><TextInput value={why} onChange={(e) => setWhy(e.target.value)} maxLength={500} /></Field></div>}
                        </Card>
                        {can('cnii:manage') && (
                            <Card>
                                <SectionTitle title="Record an authorization" />
                                <form onSubmit={create} className="mt-3 grid sm:grid-cols-3 gap-2 items-end text-xs">
                                    <Field label="Reference"><TextInput required minLength={3} value={f.ref} onChange={(e) => setF({ ...f, ref: e.target.value })} /></Field>
                                    <Field label="Issuing authority"><TextInput required minLength={2} value={f.authority} onChange={(e) => setF({ ...f, authority: e.target.value })} /></Field>
                                    <Field label="Document SHA-256 (optional)"><TextInput value={f.doc} pattern="[0-9a-f]{64}" onChange={(e) => setF({ ...f, doc: e.target.value })} /></Field>
                                    <Field label="Valid from"><TextInput type="date" required value={f.from} onChange={(e) => setF({ ...f, from: e.target.value })} /></Field>
                                    <Field label="Valid until"><TextInput type="date" required value={f.until} onChange={(e) => setF({ ...f, until: e.target.value })} /></Field>
                                    <Field label="Scope"><TextInput required minLength={3} value={f.scope} onChange={(e) => setF({ ...f, scope: e.target.value })} /></Field>
                                    <fieldset className="sm:col-span-3 flex flex-wrap gap-3"><legend className="mb-1">Sectors</legend>{SECTORS.map((s) => (
                                        <label key={s} className="flex items-center gap-1"><input type="checkbox" checked={f.sectors.has(s)} onChange={() => {
                                            const n = new Set(f.sectors); if (n.has(s)) n.delete(s); else n.add(s); setF({ ...f, sectors: n });
                                        }} />{s}</label>))}</fieldset>
                                    <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy || f.sectors.size === 0}>Record authorization</button>
                                </form>
                            </Card>
                        )}
                    </>
                )}
            </CniiGate>
        </>
    );
}
