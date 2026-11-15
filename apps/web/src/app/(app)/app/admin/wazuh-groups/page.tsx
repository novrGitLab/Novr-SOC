'use client';

// Wazuh agent group mappings: which Wazuh groups belong to the ACTIVE organization. An alert's organization is decided
// only by this mapping; alerts of unmapped groups are quarantined and never shown to a client. Switch the active
// organization to map another client's groups.
import { useCallback, useState } from 'react';
import { Activity, Trash2 } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

export default function WazuhGroupsPage() {
    const { orgId, can, session } = useSession();
    const maps = useResource(useCallback(() => adminxApi.mappings(orgId), [orgId]));
    const q = useResource(useCallback(() => (can('users:manage') ? adminxApi.quarantine(orgId) : Promise.resolve(null)), [orgId, can]));
    const [group, setGroup] = useState('');
    const act = useAction();
    return (
        <>
            <PageHeader title="Wazuh group mappings" icon={Activity}
                description={`Wazuh agent groups mapped to ${session.active_org.name}. A group belongs to at most one organization; the Wazuh manager, not the alert, says which groups an agent is in.`} />
            {act.notice}
            <Loaded title="Mapped groups" data={maps.data} error={maps.error} reload={maps.reload} testid="wazuh-mappings">
                {(d) => (
                    <>
                        <DataTable rows={d.items} rowKey={(m) => m.id} empty="No groups mapped: no alert or endpoint is attributed to this organization." columns={[
                            { key: 'g', header: 'Group', render: (m) => <span className="font-mono">{m.group_name}</span> },
                            { key: 'c', header: 'Mapped', render: (m) => <span className="text-xs">{fmt(m.created_at)}</span> },
                            { key: 'x', header: '', render: (m) => (can('endpoints:manage') ? <button className={btn('ghost')} aria-label={`Unmap ${m.group_name}`} disabled={act.busy}
                                onClick={() => void act.run(() => adminxApi.removeMapping(orgId, m.id), 'Unmapped.').then(() => maps.reload())}><Trash2 className="w-3.5 h-3.5" aria-hidden /></button> : null) },
                        ]} />
                        {can('endpoints:manage') && (
                            <div className="mt-3 flex items-end gap-2">
                                <Field label="Wazuh agent group"><TextInput value={group} pattern="[A-Za-z0-9_.-]{1,128}" onChange={(e) => setGroup(e.target.value)} /></Field>
                                <button className={btn('primary')} disabled={act.busy || !group.trim()} onClick={() => void act.run(() => adminxApi.addMapping(orgId, group.trim()), 'Mapped.').then(() => { setGroup(''); maps.reload(); })}>Map group</button>
                            </div>
                        )}
                    </>
                )}
            </Loaded>
            {q.data && (
                <Loaded title="Quarantined alerts" hint="Alerts whose groups no organization maps (platform view)" data={q.data} error={q.error} reload={q.reload}>
                    {(x) => <div className="text-xs space-y-2"><p>{x.last_24h} in the last 24 hours · {Object.entries(x.by_reason).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(' · ') || 'none'}</p>
                        <p className="flex flex-wrap gap-1">Unmapped groups seen: {x.unmapped_groups.length ? x.unmapped_groups.map((g) => <Tag key={g}>{g}</Tag>) : 'none'}</p></div>}
                </Loaded>
            )}
        </>
    );
}
