'use client';

// Vulnerability reporting and audit evidence: the live VMS report, report generation (executive and technical, from the
// platform reporting centre) and the audit trail of scopes, scans, transitions, remediation and retests.
import Link from 'next/link';
import { useCallback } from 'react';
import { ClipboardCheck } from 'lucide-react';
import { KpiCard, PageHeader, btn } from '@/components/features/vms/kit';
import { vmsxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { StateTag } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

export default function VmsReportsPage() {
    const { orgId, can } = useSession();
    const report = useResource(useCallback(() => vmsxApi.report(orgId), [orgId]));
    const audit = useResource(useCallback(() => vmsxApi.audit(orgId), [orgId]));
    const r = report.data;
    return (
        <>
            <PageHeader title="VMS reporting and audit" icon={ClipboardCheck}
                description="The current vulnerability report and the audit evidence behind it. Generate dated VMS reports (executive or technical) in the reporting centre."
                actions={can('reports:manage') ? <Link className={btn('primary')} href="/app/reports">Generate a VMS report</Link> : undefined} />
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
                <KpiCard label="Open findings" value={r ? Object.values(r.by_priority).reduce((a, b) => a + b, 0) : undefined} loading={!r && !report.error} reason="Unavailable" />
                <KpiCard label="Overdue remediation" value={r?.overdue_remediation} loading={!r && !report.error} reason="Unavailable" />
                <KpiCard label="Scans completed (30 days)" value={r?.scans_completed_30d} loading={!r && !report.error} reason="Unavailable" />
                <KpiCard label="Scanning" text={r?.scanning ?? '…'} />
            </div>
            <Loaded title="Audit trail" hint="Every VMS action, append-only" data={audit.data} error={audit.error} reload={audit.reload} testid="vms-audit">
                {(d) => <DataTable rows={d.items} rowKey={(e) => String(e.id)} empty="No VMS activity recorded." columns={[
                    { key: 'w', header: 'When', render: (e) => <span className="text-xs whitespace-nowrap">{fmt(e.occurred_at)}</span> },
                    { key: 'a', header: 'Action', render: (e) => <span className="font-mono text-xs">{e.action}</span> },
                    { key: 'o', header: 'Outcome', render: (e) => <StateTag state={e.outcome === 'success' ? 'ok' : 'failed'} label={e.outcome} /> },
                    { key: 'by', header: 'By', render: (e) => <span className="text-xs">{e.actor_label || e.actor_type}</span> },
                    { key: 'r', header: 'Resource', render: (e) => <span className="text-xs font-mono">{e.resource_type}:{e.resource_id.slice(0, 12)}</span> },
                    { key: 'd', header: 'Details', render: (e) => <span className="text-xs">{JSON.stringify(e.details ?? {}).slice(0, 120)}</span> },
                ]} />}
            </Loaded>
        </>
    );
}
