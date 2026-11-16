'use client';

// Wazuh agent groups of ONE organization (the one passed in, sent as X-Org-Id). A group belongs to at most one
// organization (the database refuses a second mapping); `default` contains every agent until it is reassigned, so
// mapping it needs an explicit acknowledgement and stays flagged.
import { useCallback, useState } from 'react';
import { AlertTriangle, Trash2 } from 'lucide-react';
import { btn } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const BROAD = new Set(['default']);

export function GroupMappingsPanel({ orgId, orgName, canManage }: { orgId: string; orgName: string; canManage: boolean }) {
    const maps = useResource(useCallback(() => adminxApi.mappings(orgId), [orgId]));
    const [group, setGroup] = useState('');
    const [ack, setAck] = useState(false);
    const act = useAction();
    const broad = BROAD.has(group.trim());
    return (
        <Loaded title="Wazuh agent groups" hint={`Agents in these groups belong to ${orgName}. An agent whose groups map to two organizations is quarantined, never guessed.`}
            data={maps.data} error={maps.error} reload={maps.reload} testid="wazuh-mappings">
            {(d) => (
                <>
                    {act.notice}
                    <DataTable rows={d.items} rowKey={(m) => m.id} empty="No group mapped: no agent's alert is attributed to this organization." columns={[
                        { key: 'g', header: 'Group', render: (m) => <span className="font-mono">{m.group_name}{m.broad && (
                            <span className="ml-2 inline-flex items-center gap-1 text-[11px] font-sans font-semibold text-[var(--vz-warning,#b45309)]" title="Every Wazuh agent is in this group until it is reassigned">
                                <AlertTriangle className="w-3 h-3" aria-hidden />broad group</span>)}</span> },
                        { key: 'c', header: 'Mapped', render: (m) => <span className="text-xs">{fmt(m.created_at)}</span> },
                        { key: 'x', header: '', render: (m) => (canManage ? <button className={btn('ghost')} aria-label={`Unmap ${m.group_name}`} disabled={act.busy}
                            onClick={() => void act.run(() => adminxApi.removeMapping(orgId, m.id), 'Unmapped.').then(() => maps.reload())}><Trash2 className="w-3.5 h-3.5" aria-hidden /></button> : null) },
                    ]} />
                    {canManage && (
                        <div className="mt-3 space-y-2">
                            <div className="flex flex-wrap items-end gap-2">
                                <Field label="Wazuh agent group"><TextInput value={group} pattern="[A-Za-z0-9_.-]{1,128}" onChange={(e) => { setGroup(e.target.value); setAck(false); }} /></Field>
                                <button className={btn('primary')} disabled={act.busy || !group.trim() || (broad && !ack)} data-testid="map-group"
                                    onClick={() => void act.run(() => adminxApi.addMapping(orgId, group.trim(), broad && ack), 'Mapped.').then((r) => { if (r) { setGroup(''); setAck(false); maps.reload(); } })}>Map group</button>
                            </div>
                            {broad && (
                                <label className="flex items-start gap-2 text-xs rounded-lg border border-border bg-card-muted p-2 max-w-2xl">
                                    <input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} className="mt-0.5" data-testid="ack-broad" />
                                    <span>Every Wazuh agent is in <span className="font-mono">{group.trim()}</span> until it is moved to another group. Mapping it attributes every agent that is in
                                        no other mapped group to {orgName}, including agents enrolled later for another client until they are reassigned. I confirm this manager only
                                        serves {orgName}, or that new agents are always assigned their own group first.</span>
                                </label>
                            )}
                        </div>
                    )}
                </>
            )}
        </Loaded>
    );
}
