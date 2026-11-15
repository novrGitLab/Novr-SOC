'use client';

// Asset discovery and attack surface: the shared inventory's exposure (internet-facing first), and the services and
// technologies discovered on the organization's assets. Both read the ONE asset inventory.
import Link from 'next/link';
import { useCallback } from 'react';
import { Network } from 'lucide-react';
import { PageHeader, SeverityBadge, Tag } from '@/components/features/vms/kit';
import { BarList, ChartCard } from '@/components/features/vms/charts';
import { assetsApi, vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const EXPO = { internet_facing: 0, unknown: 1, internal: 2 } as const;

export default function SurfacePage() {
    const { orgId } = useSession();
    const assets = useResource(useCallback(() => assetsApi.list(orgId, { limit: 500 }), [orgId]));
    const services = useResource(useCallback(() => vmsxApi.services(orgId), [orgId]));
    return (
        <>
            <PageHeader title="Attack surface" icon={Network}
                description="What the organization exposes: assets by exposure and criticality, and the services and technologies seen on them by scans and agents. Assets come from the shared inventory." />
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                <ChartCard title="Technologies seen" hint="Most frequent products and services" loading={!services.data && !services.error}
                    empty={services.data && Object.keys(services.data.by_product).length === 0 ? { title: 'No services recorded', body: 'Service observations arrive with authorized scans.' } : null}>
                    {services.data && <BarList label="Technologies" items={Object.entries(services.data.by_product).slice(0, 12).map(([k, v]) => ({ key: k, label: k, value: v }))} />}
                </ChartCard>
                <div className="lg:col-span-2">
                    <Loaded title="Exposure" hint="Internet-facing first" data={assets.data} error={assets.error} reload={assets.reload}>
                        {(d) => <DataTable rows={[...d.items].sort((a, b) => EXPO[a.exposure] - EXPO[b.exposure])} rowKey={(a) => a.id} empty="No assets in the inventory." columns={[
                            { key: 'n', header: 'Asset', render: (a) => <Link className="font-semibold text-purple hover:underline" href={`/app/assets/${a.id}`}>{a.display_name}</Link> },
                            { key: 'e', header: 'Exposure', render: (a) => <Tag strong={a.exposure === 'internet_facing'}>{a.exposure.replace('_', ' ')}</Tag> },
                            { key: 'c', header: 'Criticality', render: (a) => <SeverityBadge severity={a.criticality} /> },
                            { key: 'f', header: 'Open findings', render: (a) => a.open_findings },
                            { key: 'm', header: 'Scanned', render: (a) => (a.monitoring.last_vms_scan_at ? <span className="text-xs">{fmt(a.monitoring.last_vms_scan_at)}</span> : <StateTag state="unmonitored" label="never scanned" />) },
                        ]} />}
                    </Loaded>
                </div>
            </div>
            <Loaded title="Services and technologies" data={services.data} error={services.error} reload={services.reload} testid="vms-services">
                {(d) => <DataTable rows={d.items} rowKey={(s) => `${s.asset_id}-${s.port}-${s.protocol}-${s.product}`} empty="No services recorded." columns={[
                    { key: 'a', header: 'Asset', render: (s) => <Link className="underline" href={`/app/assets/${s.asset_id}`}>{s.asset_name}</Link> },
                    { key: 'p', header: 'Port', render: (s) => `${s.port}/${s.protocol || '-'}` },
                    { key: 'n', header: 'Service', render: (s) => s.name || '—' },
                    { key: 'pr', header: 'Product', render: (s) => `${s.product} ${s.version}`.trim() || '—' },
                    { key: 'src', header: 'Source', render: (s) => <span className="text-xs">{s.source} · {fmt(s.last_seen_at)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
