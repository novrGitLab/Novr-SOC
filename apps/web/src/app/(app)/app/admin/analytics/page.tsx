'use client';

// Platform analytics across organizations (platform administrators): counts only, from a read-only database function.
import { useCallback } from 'react';
import { BarChart3 } from 'lucide-react';
import { KpiCard, PageHeader, Tag } from '@/components/features/vms/kit';
import { BarList, ChartCard } from '@/components/features/vms/charts';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

export default function AnalyticsPage() {
    const { orgId } = useSession();
    const a = useResource(useCallback(() => adminxApi.analytics(orgId), [orgId]));
    const t = a.data?.totals;
    return (
        <>
            <PageHeader title="Platform analytics" icon={BarChart3} description="Activity and exposure across every organization the platform serves. Counts only: no tenant record leaves its organization." />
            <div className="grid grid-cols-2 lg:grid-cols-6 gap-3">
                {(['organizations', 'users', 'assets', 'alerts_7d', 'open_cases', 'critical_findings'] as const).map((k) => (
                    <KpiCard key={k} label={k.replace('_7d', ' (7 days)').replace(/_/g, ' ')} value={t?.[k]} loading={!t && !a.error} reason="Unavailable" />))}
            </div>
            <ChartCard title="Alerts in the last 7 days by organization" loading={!a.data && !a.error}>
                {a.data && <BarList label="Alerts by organization" items={a.data.organizations.map((o) => ({ key: o.org_id, label: o.org_name, value: o.alerts_7d }))} />}
            </ChartCard>
            <Loaded title="Organizations" data={a.data} error={a.error} reload={a.reload} testid="analytics">
                {(d) => <DataTable rows={d.organizations} rowKey={(o) => o.org_id} columns={[
                    { key: 'o', header: 'Organization', render: (o) => <span><strong>{o.org_name}</strong> <Tag>{o.kind}</Tag></span> },
                    { key: 'u', header: 'Users', render: (o) => o.users }, { key: 'a', header: 'Assets', render: (o) => o.assets },
                    { key: 'al', header: 'Alerts 7 d / open', render: (o) => `${o.alerts_7d} / ${o.open_alerts}` }, { key: 'c', header: 'Open cases', render: (o) => o.open_cases },
                    { key: 'f', header: 'Open findings', render: (o) => `${o.open_findings} (${o.critical_findings} critical)` },
                    { key: 'l', header: 'Last alert', render: (o) => <span className="text-xs">{fmt(o.last_alert_at)}</span> },
                    { key: 'p', header: 'Plan', render: (o) => <span className="text-xs">{o.plan_code ?? '—'} {o.subscription_status ?? ''}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
