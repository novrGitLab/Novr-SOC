'use client';

// VMS overview: scanning state (the worker runs on the owner's local host; scanning is disabled unless the installation
// enables it), open findings by priority and severity, remediation and scan activity, and the riskiest assets.
import Link from 'next/link';
import { useCallback } from 'react';
import { ShieldAlert } from 'lucide-react';
import { KpiCard, PageHeader, PriorityBadge, SeverityBadge } from '@/components/features/vms/kit';
import { BarList, ChartCard, Donut, type Token } from '@/components/features/vms/charts';
import { StatusPill } from '@/components/features/vms/ui';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

const SEV_TOKEN: Record<string, Token> = { critical: '--vz-sev-critical', high: '--vz-sev-high', medium: '--vz-sev-medium', low: '--vz-sev-low', info: '--vz-sev-info' };

export default function VmsOverviewPage() {
    const { orgId } = useSession();
    const status = useResource(useCallback(() => vmsxApi.status(orgId), [orgId]));
    const report = useResource(useCallback(() => vmsxApi.report(orgId), [orgId]));
    const risk = useResource(useCallback(() => vmsxApi.risk(orgId), [orgId]));
    const r = report.data;
    return (
        <>
            <PageHeader title="Vulnerability management" icon={ShieldAlert}
                description="Asset discovery and attack surface, scans inside approved scopes, findings with CVE intelligence and risk priority, remediation and verification by scan evidence. One shared asset inventory; no parallel VMS asset list." />
            {status.data && <p className="text-xs flex items-center gap-2" data-testid="vms-scanning"><StatusPill tone={status.data.scanning === 'enabled' ? 'warning' : 'neutral'} label={`Scanning ${status.data.scanning}`} /> {status.data.reason}</p>}
            <div className="grid grid-cols-2 xl:grid-cols-6 gap-3" data-testid="vms-kpis">
                {(['P1', 'P2', 'P3', 'P4'] as const).map((p) => <KpiCard key={p} label={`Open ${p}`} value={r ? (r.by_priority[p] ?? 0) : undefined} loading={!r && !report.error} reason="Report unavailable" href={`/app/vms/findings?priority=${p}`} />)}
                <KpiCard label="Overdue remediation" value={r?.overdue_remediation} loading={!r && !report.error} reason="Report unavailable" href="/app/vms/remediation" tone={r?.overdue_remediation ? 'serious' : 'neutral'} />
                <KpiCard label="Known exploited (KEV)" value={risk.data?.kev_findings} loading={!risk.data && !risk.error} reason="Unavailable" href="/app/vms/risk" tone={risk.data?.kev_findings ? 'critical' : 'neutral'} />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <ChartCard title="Open findings by severity" loading={!r && !report.error} empty={r && Object.keys(r.by_severity).length === 0 ? { title: 'No open findings', body: 'Findings appear when an authorized scan delivers results.' } : null}>
                    {r && <Donut label="Open findings by severity" centerLabel="open" slices={['critical', 'high', 'medium', 'low', 'info'].map((k) => ({ key: k, label: k, value: r.by_severity[k] ?? 0, token: SEV_TOKEN[k], href: `/app/vms/findings?severity=${k}` }))} />}
                </ChartCard>
                <ChartCard title="Findings by status" loading={!r && !report.error} empty={r && Object.keys(r.by_status).length === 0 ? { title: 'No findings' } : null}>
                    {r && <BarList label="Findings by status" items={Object.entries(r.by_status).map(([k, v]) => ({ key: k, label: k.replace(/_/g, ' '), value: v }))} />}
                </ChartCard>
                <ChartCard title="Scanning" hint={r ? `${r.scans_completed_30d} scan(s) completed in 30 days` : undefined}>
                    <ul className="text-xs space-y-1">{(status.data?.workers ?? []).length === 0 ? <li className="text-foreground-muted">No VMS worker has reported. The worker runs on the owner&apos;s local host.</li>
                        : status.data?.workers.map((w) => <li key={w.identity_name}>{w.identity_name} · v{w.component_version} · {w.state} · {w.stale ? 'stale' : 'reporting'} · {fmt(w.last_heartbeat_at)}</li>)}</ul>
                    <Link href="/app/vms/scans" className="mt-3 inline-block text-xs underline">Scopes, scans and schedules</Link>
                </ChartCard>
            </div>
            <Loaded title="Highest-risk findings" data={r} error={report.error} reload={report.reload}>
                {(d) => <DataTable rows={d.top_findings} rowKey={(f) => f.id} empty="No open findings." columns={[
                    { key: 'p', header: 'Priority', render: (f) => <PriorityBadge priority={f.priority} /> },
                    { key: 't', header: 'Finding', render: (f) => <Link className="font-semibold text-purple hover:underline" href={`/app/vms/findings?finding=${f.id}`}>{f.title}<span className="block text-[11px] font-normal text-foreground-muted">{f.host}{f.port ? `:${f.port}` : ''}</span></Link> },
                    { key: 's', header: 'Severity', render: (f) => <SeverityBadge severity={f.severity} /> },
                    { key: 'r', header: 'Risk', render: (f) => f.risk.score },
                    { key: 'd', header: 'Due', render: (f) => <span className="text-xs">{fmt(f.remediation_due_at)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
