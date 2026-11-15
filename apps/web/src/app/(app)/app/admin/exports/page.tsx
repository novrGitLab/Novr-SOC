'use client';

// Authorized client data exports: one organization's records for a named recipient with a justification, a checksum and
// an expiry. Creation and every download are audited; an export can be revoked.
import { useCallback, useState, type FormEvent } from 'react';
import { Download } from 'lucide-react';
import { PageHeader, Tag, btn, downloadText } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { apiErrorFromResponse } from '@/foundation/api/errors';
import { adminxApi, exportDownloadPath } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Dataset = Schemas['DataExportCreate']['dataset'];
const DATASETS: [Dataset, string][] = [['alerts', 'Alerts'], ['cases', 'Cases'], ['vms_findings', 'VMS findings'], ['assets', 'Assets'],
    ['ti_indicators', 'Threat indicators'], ['audit_events', 'Audit events']];

export default function ExportsPage() {
    const { orgId, session } = useSession();
    const list = useResource(useCallback(() => adminxApi.exports(orgId), [orgId]));
    const [f, setF] = useState({ dataset: 'alerts' as Dataset, format: 'csv' as 'csv' | 'json', days: 30, justification: '', recipient: '', expires: 7 });
    const act = useAction();

    async function create(e: FormEvent) {
        e.preventDefault();
        const end = new Date();
        if (await act.run(() => adminxApi.createExport(orgId, { dataset: f.dataset, format: f.format, period_start: new Date(end.getTime() - f.days * 86_400_000).toISOString(),
            period_end: end.toISOString(), justification: f.justification.trim(), recipient: f.recipient.trim(), expires_in_days: f.expires }), (x) => `Export ready: ${x.row_count} row(s).`)) list.reload();
    }
    async function download(x: Schemas['DataExportView']) {
        await act.run(async () => {
            const r = await fetch(exportDownloadPath(x.id), { headers: orgId ? { 'X-Org-Id': orgId } : {}, credentials: 'same-origin', cache: 'no-store' });
            if (!r.ok) throw await apiErrorFromResponse(r);
            downloadText(`novrsoc-${x.dataset}-${x.created_at.slice(0, 10)}.${x.format}`, await r.text(), x.format === 'json' ? 'application/json' : 'text/csv;charset=utf-8');
            list.reload();
        }, 'Downloaded (audited).');
    }

    return (
        <>
            <PageHeader title="Data exports" icon={Download}
                description={`Authorized exports of ${session.active_org.name}'s records. Each one names its recipient and justification, carries a SHA-256, expires, and is audited at creation and at every download.`} />
            {act.notice}
            <Card>
                <SectionTitle title="Create an export" />
                <form onSubmit={create} className="mt-3 grid sm:grid-cols-4 gap-2 items-end text-xs" data-testid="export-form">
                    <Field label="Dataset"><select className={selectCls} value={f.dataset} onChange={(e) => setF({ ...f, dataset: e.target.value as Dataset })}>{DATASETS.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
                    <Field label="Format"><select className={selectCls} value={f.format} onChange={(e) => setF({ ...f, format: e.target.value as 'csv' | 'json' })}><option value="csv">CSV</option><option value="json">JSON</option></select></Field>
                    <Field label="Period (days)"><TextInput type="number" min={1} max={366} value={f.days} onChange={(e) => setF({ ...f, days: Number(e.target.value) })} /></Field>
                    <Field label="Expires after (days)"><TextInput type="number" min={1} max={30} value={f.expires} onChange={(e) => setF({ ...f, expires: Number(e.target.value) })} /></Field>
                    <Field label="Recipient"><TextInput required minLength={2} value={f.recipient} onChange={(e) => setF({ ...f, recipient: e.target.value })} placeholder="Client CISO office" /></Field>
                    <Field label="Justification"><TextInput required minLength={10} value={f.justification} onChange={(e) => setF({ ...f, justification: e.target.value })} /></Field>
                    <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Create export</button>
                </form>
            </Card>
            <Loaded title="Exports" hint={list.data ? `At most ${list.data.max_rows} rows per export` : undefined} data={list.data} error={list.error} reload={list.reload} testid="exports">
                {(d) => <DataTable rows={d.items} rowKey={(x) => x.id} empty="No exports." columns={[
                    { key: 'd', header: 'Dataset', render: (x) => <span><strong>{x.dataset.replace('_', ' ')}</strong> <Tag>{x.format}</Tag><span className="block text-[11px] text-foreground-muted">{fmt(x.period_start)} – {fmt(x.period_end)}</span></span> },
                    { key: 'r', header: 'Recipient and justification', render: (x) => <span className="text-xs">{x.recipient}<span className="block text-foreground-muted">{x.justification}</span></span> },
                    { key: 'n', header: 'Rows', render: (x) => `${x.row_count}${x.truncated ? ' (truncated)' : ''}` },
                    { key: 'h', header: 'SHA-256', render: (x) => <span className="font-mono text-[10px] break-all">{x.sha256}</span> },
                    { key: 's', header: 'State', render: (x) => <span className="text-xs"><StateTag state={x.state} /><span className="block text-foreground-muted">expires {fmt(x.expires_at)} · {x.downloads} download(s)</span></span> },
                    { key: 'x', header: '', render: (x) => (x.state === 'available' ? <span className="flex gap-1">
                        <button className={btn('secondary')} disabled={act.busy} onClick={() => void download(x)}>Download</button>
                        <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => adminxApi.revokeExport(orgId, x.id), 'Revoked.').then(() => list.reload())}>Revoke</button></span> : null) },
                ]} />}
            </Loaded>
        </>
    );
}
