'use client';

// Platform health: measured component states only (database, migrations, Wazuh connectors, NHAI, the SOAR bridge, local
// VMS workers, the forwarder, queues, backups, the jobs worker). A state that cannot be established is "unknown" or
// "unconfigured", never "ok". Refreshes every 30 s.
import { useCallback, useEffect, useState } from 'react';
import { HeartPulse } from 'lucide-react';
import { PageHeader } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

export default function HealthPage() {
    const { orgId } = useSession();
    const [tick, setTick] = useState(0);
    useEffect(() => { const t = setInterval(() => setTick((x) => x + 1), 30_000); return () => clearInterval(t); }, []);
    const h = useResource(useCallback(() => adminxApi.health(orgId), [orgId, tick])); // eslint-disable-line react-hooks/exhaustive-deps
    return (
        <>
            <PageHeader title="Platform health" icon={HeartPulse} description="Component status, connectivity, service heartbeats, queues, database health and integration failures, as measured now." />
            <Loaded title="Components" hint={h.data ? `Checked ${fmt(h.data.generated_at)}` : undefined} data={h.data} error={h.error} reload={h.reload} testid="health">
                {(d) => <DataTable rows={d.components} rowKey={(c) => c.key} columns={[
                    { key: 'l', header: 'Component', render: (c) => <strong>{c.label}</strong> },
                    { key: 's', header: 'State', render: (c) => <StateTag state={c.state} /> },
                    { key: 'd', header: 'Detail', render: (c) => <span className="text-xs">{c.detail}</span> },
                    { key: 't', header: 'Checked', render: (c) => <span className="text-xs">{fmt(c.checked_at)}</span> },
                ]} />}
            </Loaded>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                <Loaded title="Queues" data={h.data} error={h.error}>
                    {(d) => <ul className="text-xs space-y-1">{Object.entries(d.queues).map(([k, v]) => <li key={k}><span className="text-foreground-muted">{k}</span> <span className="font-mono break-all">{JSON.stringify(v)}</span></li>)}</ul>}
                </Loaded>
                <Loaded title="Integration failures (24 h)" hint="Audit events with outcome failure" data={h.data} error={h.error}>
                    {(d) => (d.failures_24h.length === 0 ? <p className="text-xs text-foreground-muted">No failure recorded.</p>
                        : <ul className="text-xs">{d.failures_24h.map((f) => <li key={String(f.action)}><span className="font-mono">{String(f.action)}</span> × {String(f.count)}</li>)}</ul>)}
                </Loaded>
            </div>
            <Loaded title="NovrVMS" hint="Heartbeats from NovrVMS" data={h.data} error={h.error}>
                {(d) => (d.workers.length === 0 ? <p className="text-xs text-foreground-muted">NovrVMS has not reported.</p>
                    : <ul className="text-xs">{d.workers.map((w) => <li key={String(w.name)}>{String(w.name)} ({String(w.organization)}) · {String(w.state)} · v{String(w.version)} · {fmt(String(w.received_at))}</li>)}</ul>)}
            </Loaded>
        </>
    );
}
