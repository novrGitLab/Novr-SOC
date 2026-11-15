'use client';

// Risk prioritization: open findings by priority and severity, known exploitation (KEV) from the organization's CVE
// intelligence, internet-facing exposure, overdue remediation, and the riskiest assets. The formula is shown.
import Link from 'next/link';
import { useCallback } from 'react';
import { Target } from 'lucide-react';
import { KpiCard, PageHeader, SeverityBadge, Tag } from '@/components/features/vms/kit';
import { BarList, ChartCard } from '@/components/features/vms/charts';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

export default function RiskPage() {
    const { orgId } = useSession();
    const risk = useResource(useCallback(() => vmsxApi.risk(orgId), [orgId]));
    const r = risk.data;
    return (
        <>
            <PageHeader title="Risk prioritization" icon={Target}
                description="Which findings to fix first: priority from the scanner's evidence, raised in importance by known exploitation (KEV), internet exposure and asset criticality." />
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <KpiCard label="Open P1" value={r?.by_priority.P1 ?? (r ? 0 : undefined)} loading={!r && !risk.error} reason="Unavailable" href="/app/vms/findings?priority=P1" />
                <KpiCard label="Known exploited (KEV)" value={r?.kev_findings} loading={!r && !risk.error} reason="Unavailable" tone={r?.kev_findings ? 'critical' : 'neutral'} />
                <KpiCard label="On internet-facing assets" value={r?.internet_facing_findings} loading={!r && !risk.error} reason="Unavailable" />
                <KpiCard label="Overdue remediation" value={r?.overdue} loading={!r && !risk.error} reason="Unavailable" href="/app/vms/remediation" />
            </div>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <ChartCard title="Open findings by priority" loading={!r && !risk.error}>
                    {r && <BarList label="By priority" items={['P1', 'P2', 'P3', 'P4'].map((k) => ({ key: k, label: k, value: r.by_priority[k] ?? 0, href: `/app/vms/findings?priority=${k}` }))} />}
                </ChartCard>
                <ChartCard title="Open findings by severity" loading={!r && !risk.error}>
                    {r && <BarList label="By severity" items={['critical', 'high', 'medium', 'low', 'info'].map((k) => ({ key: k, label: k, value: r.by_severity[k] ?? 0, href: `/app/vms/findings?severity=${k}` }))} />}
                </ChartCard>
            </div>
            <Loaded title="Riskiest assets" data={r} error={risk.error} reload={risk.reload} testid="risk-assets">
                {(d) => <DataTable rows={d.assets} rowKey={(a) => a.asset_id ?? a.name} empty="No open findings." columns={[
                    { key: 'n', header: 'Asset', render: (a) => (a.asset_id ? <Link className="font-semibold text-purple hover:underline" href={`/app/assets/${a.asset_id}`}>{a.name}</Link> : <span>{a.name} <span className="text-xs text-foreground-muted">(not linked)</span></span>) },
                    { key: 'c', header: 'Criticality', render: (a) => (a.criticality ? <SeverityBadge severity={a.criticality} /> : '—') },
                    { key: 'e', header: 'Exposure', render: (a) => (a.exposure ? <Tag strong={a.exposure === 'internet_facing'}>{a.exposure.replace('_', ' ')}</Tag> : '—') },
                    { key: 'r', header: 'Max risk', render: (a) => a.max_risk },
                    { key: 'f', header: 'Open findings', render: (a) => `${a.open_findings} (${a.p1} P1, ${a.kev} KEV)` },
                ]} />}
            </Loaded>
            {r && <Card><SectionTitle title="Formula" /><p className="mt-2 text-xs text-foreground-muted">{r.formula}</p></Card>}
        </>
    );
}
