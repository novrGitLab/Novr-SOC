'use client';

// Vulnerability findings with filters, and a detail drawer: CVE intelligence (CVSS, EPSS, KEV), the canonical asset,
// remediation, verification requests (retests resolved by scan evidence), audit history and an NHAI explanation.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Bug } from 'lucide-react';
import { Drawer, PageHeader, PriorityBadge, SearchBox, Select, SeverityBadge, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, initialParam, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { NhaiSubjectPanel } from '../../insights/NhaiSubjectPanel';

const NEXT: Record<string, string[]> = {
    open: ['acknowledged', 'in_progress', 'risk_accepted'], acknowledged: ['in_progress', 'risk_accepted'], in_progress: ['fixed_pending_verification'],
    reopened: ['in_progress', 'acknowledged'], risk_accepted: ['open'], fixed_pending_verification: [], verified: [],
};
const STATUS = [['', 'Open and closed'], ['open', 'Open'], ['acknowledged', 'Acknowledged'], ['in_progress', 'In progress'],
    ['fixed_pending_verification', 'Fixed, awaiting verification'], ['reopened', 'Reopened'], ['verified', 'Verified'], ['risk_accepted', 'Risk accepted']] as const;
const SEV = [['', 'Any severity'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low'], ['info', 'Info']] as const;
const PRI = [['', 'Any priority'], ['P1', 'P1'], ['P2', 'P2'], ['P3', 'P3'], ['P4', 'P4']] as const;

function FindingDrawer({ id, onClose, onChanged }: { id: string; onClose: () => void; onChanged: () => void }) {
    const { orgId, can } = useSession();
    const d = useResource(useCallback(() => vmsxApi.finding(orgId, id), [orgId, id]));
    const [reason, setReason] = useState('');
    const act = useAction();
    const done = (r: unknown) => { if (r) { d.reload(); onChanged(); } };
    return (
        <Drawer open onClose={onClose} title={d.data?.finding.title ?? 'Finding'} subtitle={d.data ? `${d.data.finding.host}${d.data.finding.port ? `:${d.data.finding.port}` : ''}` : undefined}>
            {act.notice}
            <Loaded title="Finding" data={d.data} error={d.error} reload={d.reload} testid="finding-detail">
                {(x) => (
                    <div className="space-y-4 text-sm">
                        <p className="flex flex-wrap items-center gap-2"><PriorityBadge priority={x.finding.priority} /><SeverityBadge severity={x.finding.severity} /><StateTag state={x.finding.status} />
                            <Tag>risk {x.finding.risk.score}</Tag>{x.finding.kev && <Tag strong>Known exploited (KEV)</Tag>}</p>
                        <p className="text-xs">Asset: {x.finding.asset_id ? <Link className="underline" href={`/app/assets/${x.finding.asset_id}`}>{x.finding.asset_name}</Link> : 'not linked'} · source {x.finding.source} · seen {x.finding.occurrences}× · first {fmt(x.finding.first_seen_at)} · last {fmt(x.finding.last_seen_at)}</p>
                        <div><p className="text-xs font-semibold mb-1">CVE intelligence</p>
                            {x.cve_intel.length === 0 && x.cves_without_intel.length === 0 && <p className="text-xs text-foreground-muted">No CVE is named by this finding.</p>}
                            <ul className="text-xs space-y-1">{x.cve_intel.map((c) => <li key={c.cve_id}><span className="font-mono">{c.cve_id}</span> CVSS {c.cvss_v3 ?? 'unknown'} · EPSS {c.epss ?? 'unknown'} · {c.kev ? 'KEV' : 'not in KEV'} · {c.source}<span className="block text-foreground-muted">{c.description}</span></li>)}</ul>
                            {x.cves_without_intel.length > 0 && <p className="text-xs text-foreground-muted">No intelligence recorded for {x.cves_without_intel.join(', ')}. <Link className="underline" href="/app/insights/cves">Import CVE intelligence</Link></p>}
                        </div>
                        {x.remediation && <p className="text-xs">Remediation: <StateTag state={x.remediation.status} /> due {fmt(x.remediation.due_at)}{x.remediation.overdue && <strong className="text-red"> overdue</strong>} · {x.remediation.assignee_label ?? 'unassigned'}{x.remediation.note && ` · ${x.remediation.note}`}</p>}
                        {can('vms:manage') && NEXT[x.finding.status]?.length > 0 && (
                            <div className="flex flex-wrap items-end gap-2">
                                <Field label="Reason (recorded)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} /></Field>
                                {NEXT[x.finding.status].map((to) => <button key={to} className={btn('secondary')} disabled={act.busy || reason.trim().length < 3}
                                    onClick={() => void act.run(() => vmsxApi.transition(orgId, id, to, reason.trim()), `Moved to ${to.replace(/_/g, ' ')}.`).then(done)}>{to.replace(/_/g, ' ')}</button>)}
                            </div>
                        )}
                        <div><p className="text-xs font-semibold mb-1">Verification and retests</p>
                            <ul className="text-xs space-y-1">{x.verifications.length === 0 ? <li className="text-foreground-muted">No retest requested.</li>
                                : x.verifications.map((v) => <li key={v.id}><StateTag state={v.status === 'verified' ? 'verified' : v.status.startsWith('blocked') ? 'unconfigured' : 'pending'} label={v.status.replace(/_/g, ' ')} /> {fmt(v.created_at)} · {v.requested_label}{v.note && ` · ${v.note}`}</li>)}</ul>
                            {can('vms:scan') && !['verified', 'risk_accepted'].includes(x.finding.status) && <button className={`${btn('secondary')} mt-2`} disabled={act.busy}
                                onClick={() => void act.run(() => vmsxApi.retest(orgId, id, reason.trim()), (r) => (r.status === 'scan_requested' ? 'Retest scan queued for the local worker.' : `Retest recorded: ${r.status.replace(/_/g, ' ')}.`)).then(done)}>Request a retest</button>}
                        </div>
                        <NhaiSubjectPanel title="NHAI explanation" testid="finding-nhai" request={() => vmsxApi.explain(orgId, id)} />
                        <details><summary className="text-xs cursor-pointer">Audit history ({x.history.length})</summary>
                            <ul className="text-xs mt-1 space-y-0.5">{x.history.map((h, i) => <li key={i}>{String(h.at)} · {String(h.action)} · {String(h.actor)}</li>)}</ul></details>
                    </div>
                )}
            </Loaded>
        </Drawer>
    );
}

export default function FindingsPage() {
    const { orgId } = useSession();
    const [status, setStatus] = useState<(typeof STATUS)[number][0]>('');
    const [sev, setSev] = useState<(typeof SEV)[number][0]>(() => (SEV.find(([k]) => k === initialParam('severity'))?.[0] ?? ''));
    const [pri, setPri] = useState<(typeof PRI)[number][0]>(() => (PRI.find(([k]) => k === initialParam('priority'))?.[0] ?? ''));
    const [q, setQ] = useState('');
    const [open, setOpen] = useState<string | null>(() => initialParam('finding') || null);
    const list = useResource(useCallback(() => vmsxApi.findings(orgId, { status, severity: sev, priority: pri, q, limit: 300 }), [orgId, status, sev, pri, q]));
    return (
        <>
            <PageHeader title="Vulnerability findings" icon={Bug}
                description="Deduplicated per host, port and check; risk-scored and prioritized; verified or reopened only by scan evidence. Wazuh package-based detection is shown on each asset, separately." />
            <div className="flex flex-wrap items-center gap-2">
                <Select label="Status" options={STATUS} value={status} onChange={setStatus} />
                <Select label="Severity" options={SEV} value={sev} onChange={setSev} />
                <Select label="Priority" options={PRI} value={pri} onChange={setPri} />
                <SearchBox label="Search findings" placeholder="Title, host or CVE id" value={q} onSubmit={setQ} />
            </div>
            <Loaded title="Findings" hint={list.data ? `${list.data.total} finding(s)` : undefined} data={list.data} error={list.error} reload={list.reload}>
                {(d) => <DataTable testid="vms-findings" rows={d.items} rowKey={(f) => f.id} empty="No findings match. Findings appear when an authorized scan delivers results." columns={[
                    { key: 'p', header: 'Priority', render: (f: Schemas['VmsFindingView']) => <span className="flex items-center gap-1"><PriorityBadge priority={f.priority} /><span className="text-xs">{f.risk.score}</span></span> },
                    { key: 't', header: 'Finding', render: (f) => <button className="text-left" onClick={() => setOpen(f.id)}><span className="font-semibold text-purple">{f.title}</span><span className="block text-[11px] text-foreground-muted">{f.host}{f.port ? `:${f.port}` : ''} · {f.cves.slice(0, 3).join(', ') || 'no CVE'}</span></button> },
                    { key: 's', header: 'Severity', render: (f) => <span className="flex items-center gap-1"><SeverityBadge severity={f.severity} />{f.kev && <Tag strong>KEV</Tag>}</span> },
                    { key: 'st', header: 'Status', render: (f) => <StateTag state={f.status} /> },
                    { key: 'a', header: 'Asset', className: 'hidden md:table-cell', render: (f) => (f.asset_id ? <Link className="text-xs underline" href={`/app/assets/${f.asset_id}`}>{f.asset_name}</Link> : <span className="text-xs text-foreground-muted">not linked</span>) },
                    { key: 'd', header: 'Due', className: 'hidden md:table-cell', render: (f) => <span className="text-xs">{fmt(f.remediation_due_at)}</span> },
                ]} />}
            </Loaded>
            <Card><SectionTitle title="How priority is set" /><p className="mt-2 text-xs text-foreground-muted">Risk = CVSS × 10 when the scanner reports a CVSS score, else a severity default; P1 ≥ 90, P2 ≥ 70, P3 ≥ 40, else P4. Due dates: P1 2 days, P2 7, P3 30, P4 90. KEV intelligence is shown next to the score; see Risk prioritization.</p></Card>
            {open && <FindingDrawer id={open} onClose={() => setOpen(null)} onChanged={list.reload} />}
        </>
    );
}
