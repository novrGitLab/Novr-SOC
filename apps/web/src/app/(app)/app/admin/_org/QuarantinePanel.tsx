'use client';

// Platform view of events that NO organization could be determined for. They are held here, never shown to a client and
// never assigned by default: map the group or register the source in the right organization, and new events flow.
import { useCallback } from 'react';
import { Tag } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Loaded, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';

const REASON: Record<string, string> = {
    no_organization_for_groups: 'No organization maps the agent groups', ambiguous_organization: 'Groups map to several organizations',
    unknown_log_source: 'Unregistered syslog / agentless source', log_source_disabled: 'Source disabled or organization archived',
    manager_local_event: "NovrSIEM's own event (no tenant)",
};

export function QuarantinePanel() {
    const { orgId, can } = useSession();
    const q = useResource(useCallback(() => (can('users:manage') ? adminxApi.quarantine(orgId) : Promise.resolve(null)), [orgId, can]));
    if (!can('users:manage')) return null;
    return (
        <Loaded title="Quarantined events" testid="quarantine" data={q.data} error={q.error} reload={q.reload}
            hint="Security events no organization could be determined for. They are kept here and never assigned to a tenant by default.">
            {(x) => x && (
                <div className="space-y-3 text-xs">
                    <p>{x.last_24h} in the last 24 hours · {Object.entries(x.by_reason).map(([k, v]) => `${v} ${REASON[k] ?? k.replace(/_/g, ' ')}`).join(' · ') || 'none'}</p>
                    <p className="flex flex-wrap gap-1 items-center">Unmapped NovrAgent groups seen: {x.unmapped_groups.length ? x.unmapped_groups.map((g) => <Tag key={g}>{g}</Tag>) : 'none'}</p>
                    <DataTable rows={x.unattributed_sources} rowKey={(s) => `${s.reason}:${s.value}`} testid="unattributed-sources"
                        empty="No unattributed syslog, agentless or manager event." columns={[
                            { key: 'v', header: 'Source', render: (s) => <span className="font-mono">{s.value || '(no location)'}<span className="block font-sans text-[11px] text-foreground-muted">{s.kind.replace('_', ' ')}</span></span> },
                            { key: 'r', header: 'Why', render: (s) => REASON[s.reason] ?? s.reason },
                            { key: 'n', header: 'Events', render: (s) => <span className="tabular-nums">{s.events}</span> },
                            { key: 'l', header: 'Last seen', render: (s) => fmt(s.last_seen_at) },
                        ]} />
                </div>
            )}
        </Loaded>
    );
}
