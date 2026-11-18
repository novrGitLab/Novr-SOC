'use client';

// What NovrSOAR automation decided for each new alert: automatic cases opened or joined, automatic runs started, and
// every skip (emergency stop, severity, limits) or failure, with the detection confidence and how it was computed.
import Link from 'next/link';
import { useCallback } from 'react';
import { Bot } from 'lucide-react';
import { PageHeader, Tag } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { soarApi } from '../api';

const TONE: Record<string, 'good' | 'warning' | 'critical' | 'neutral'> = {
    case_created: 'good', case_joined: 'good', run_started: 'good', skipped_emergency_stop: 'critical', skipped_limit: 'warning',
    skipped_severity: 'neutral', failed: 'critical',
};

export default function AutomationPage() {
    const { orgId } = useSession();
    const ev = useResource(useCallback(() => soarApi.automationEvents(orgId), [orgId]));
    return (
        <>
            <PageHeader title="Automation" icon={Bot}
                description="Decisions NovrSOAR took by itself for new alerts. Consequential steps run only under the pre-authorization policy; the rest wait for a person." />
            <Loaded title="Automation decisions" data={ev.data} error={ev.error} reload={ev.reload} testid="soar-automation-events"
                hint={ev.data ? `Automatic playbooks ${ev.data.enabled ? 'on' : 'off'} · automatic cases ${ev.data.case_creation ? 'on' : 'off'}`
                    + (ev.data.since ? ` · since ${fmt(ev.data.since)}` : '') : undefined}>
                {(d) => (
                    <DataTable rows={d.items} rowKey={(e) => e.id} empty="No automation decision yet. Switch automation on in the response policy."
                        columns={[
                            { key: 't', header: 'When', render: (e) => <span className="text-xs">{fmt(e.created_at)}</span> },
                            { key: 'd', header: 'Decision', render: (e) => <span className="min-w-0"><StatusPill tone={TONE[e.decision] ?? 'neutral'} label={e.decision.replace(/_/g, ' ')} />
                                {e.playbook_name && <Tag>{e.playbook_name}</Tag>}<span className="block text-[11px] text-foreground-muted wrap-any">{e.detail}</span></span> },
                            { key: 'c', header: 'Confidence', render: (e) => <span className="text-xs" title={e.confidence_factors.join('\n')}>{e.confidence}
                                <span className="block text-[11px] text-foreground-muted wrap-any">{e.confidence_factors.join('; ')}</span></span> },
                            { key: 'l', header: 'Records', render: (e) => <span className="flex flex-col text-xs">
                                <Link className="underline" href={`/app/alerts/${e.alert_id}`}>Alert</Link>
                                {e.case_id && <Link className="underline" href={`/app/cases/${e.case_id}`}>Case</Link>}
                                {e.run_id && <Link className="underline" href={`/app/soar/runs/${e.run_id}`}>Run</Link>}</span> },
                        ]} />
                )}
            </Loaded>
        </>
    );
}
