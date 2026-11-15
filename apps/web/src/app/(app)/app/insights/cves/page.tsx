'use client';

// CVE intelligence: CVSS, EPSS and KEV per CVE, merged from the organization's imports (every import is a snapshot),
// correlated with its own open VMS findings and affected assets; checksummed CVSS/IOC evidence snapshots. Imports come
// from files an analyst obtained (records or a CISA KEV catalog) or from STIX vulnerabilities already received.
import { useCallback, useState } from 'react';
import { Database } from 'lucide-react';
import { PageHeader, SearchBox, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { intelApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

export default function CvesPage() {
    const { orgId, can } = useSession();
    const [q, setQ] = useState('');
    const [kev, setKev] = useState(false);
    const list = useResource(useCallback(() => intelApi.cves(orgId, { q: q || undefined, kev_only: kev ? 'true' : undefined }), [orgId, q, kev]));
    const snaps = useResource(useCallback(() => intelApi.snapshots(orgId), [orgId]));
    const [source, setSource] = useState('analyst-file');
    const [reason, setReason] = useState('');
    const act = useAction();

    async function importFile(file: File) {
        const text = await file.text();
        let json: unknown;
        try { json = JSON.parse(text); } catch { act.setMsg({ ok: false, text: 'The file is not JSON.' }); return; }
        const body = Array.isArray(json) ? { source, records: json as never[] }
            : (json as { vulnerabilities?: unknown }).vulnerabilities ? { source, kev_catalog: json as Record<string, unknown>, records: [] } : null;
        if (!body) { act.setMsg({ ok: false, text: 'Expected a list of CVE records or a KEV catalog with a "vulnerabilities" list.' }); return; }
        if (await act.run(() => intelApi.importCves(orgId, body), (r) => `Imported ${r.imported} record(s); ${r.skipped.length} skipped.`)) list.reload();
    }

    return (
        <>
            <PageHeader title="CVE intelligence" icon={Database}
                description="Severity and exploitation context for the CVEs your findings name. NovrSOC does not fetch feeds here; it uses the files you import and the STIX vulnerabilities the Server 1 feeder delivers." />
            {act.notice}
            <div className="flex flex-wrap items-center gap-3">
                <SearchBox label="Search CVEs" placeholder="CVE-2024-…" value={q} onSubmit={setQ} />
                <label className="text-xs flex items-center gap-1"><input type="checkbox" checked={kev} onChange={() => setKev(!kev)} />Known exploited only</label>
            </div>
            <Loaded title="CVEs" hint={list.data?.finding_cves_without_intel.length ? `${list.data.finding_cves_without_intel.length} CVE(s) in open findings have no intelligence` : undefined}
                data={list.data} error={list.error} reload={list.reload} testid="cves">
                {(d) => (
                    <>
                        <DataTable rows={d.items} rowKey={(c) => c.cve_id} empty="No CVE intelligence imported." columns={[
                            { key: 'c', header: 'CVE', render: (c) => <span className="font-mono font-semibold">{c.cve_id}</span> },
                            { key: 's', header: 'CVSS / EPSS', render: (c) => <span className="text-xs">{c.cvss_v3 ?? '—'} / {c.epss ?? '—'}</span> },
                            { key: 'k', header: 'KEV', render: (c) => (c.kev ? <Tag strong>known exploited {c.kev_added ?? ''}</Tag> : <span className="text-xs text-foreground-muted">not listed</span>) },
                            { key: 'f', header: 'Your exposure', render: (c) => <span className="text-xs">{c.open_findings} open finding(s) · {c.affected_assets} asset(s)</span> },
                            { key: 'a', header: 'Actors', render: (c) => <span className="text-xs">{c.actors.join(', ') || '—'}</span> },
                            { key: 'd', header: 'Description', render: (c) => <span className="text-xs">{c.description.slice(0, 160)}</span> },
                            { key: 'src', header: 'Source', render: (c) => <span className="text-xs">{c.source} · {c.snapshots} snapshot(s) · {fmt(c.captured_at)}</span> },
                            { key: 'x', header: '', render: (c) => (can('intel:manage') ? <button className={btn('ghost')} disabled={act.busy}
                                onClick={() => void act.run(() => intelApi.snapshot(orgId, { kind: 'cvss', subject: c.cve_id, reason: reason || 'evidence' }), (s) => `Snapshot ${s.sha256.slice(0, 12)}… captured.`).then(() => snaps.reload())}>Snapshot</button> : null) },
                        ]} />
                        {d.finding_cves_without_intel.length > 0 && <p className="mt-3 text-xs text-foreground-muted">Without intelligence: <span className="font-mono">{d.finding_cves_without_intel.join(', ')}</span></p>}
                    </>
                )}
            </Loaded>
            {can('intel:manage') && (
                <Card>
                    <SectionTitle title="Import CVE intelligence" hint="A JSON list of records, or a CISA KEV catalog JSON file" />
                    <div className="mt-3 flex flex-wrap items-end gap-2 text-xs">
                        <Field label="Source label"><TextInput value={source} onChange={(e) => setSource(e.target.value)} /></Field>
                        <Field label="File"><input type="file" accept="application/json,.json" onChange={(e) => { const file = e.target.files?.[0]; if (file) void importFile(file); e.target.value = ''; }} /></Field>
                        <button className={btn('secondary')} disabled={act.busy} onClick={() => void act.run(() => intelApi.importStix(orgId), (r) => `Derived ${r.imported} record(s) from STIX vulnerabilities.`).then(() => list.reload())}>Derive from stored STIX</button>
                        <Field label="Snapshot reason"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} /></Field>
                    </div>
                </Card>
            )}
            <Loaded title="Evidence snapshots" hint="Frozen CVSS and IOC state with a SHA-256 over the content" data={snaps.data} error={snaps.error} reload={snaps.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(s) => s.id} empty="No snapshots." columns={[
                    { key: 'k', header: 'Kind', render: (s) => <Tag>{s.kind}</Tag> },
                    { key: 's', header: 'Subject', render: (s) => <span className="font-mono text-xs">{s.subject}</span> },
                    { key: 'h', header: 'SHA-256', render: (s) => <span className="font-mono text-[11px] break-all">{s.sha256}</span> },
                    { key: 'r', header: 'Reason', render: (s) => <span className="text-xs">{s.reason || '—'}</span> },
                    { key: 'w', header: 'Captured', render: (s) => <span className="text-xs">{s.captured_label} · {fmt(s.captured_at)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
