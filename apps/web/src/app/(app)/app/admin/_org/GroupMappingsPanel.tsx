'use client';

// Wazuh agent groups of ONE organization (the one passed in, sent as X-Org-Id). A group belongs to at most one
// organization (the database refuses a second mapping). Collection groups (`default`: every new agent of every
// organization lands there) can never establish ownership: the API refuses to map them, and a mapping left from an
// earlier release is shown as ignored.
import { useCallback, useState } from 'react';
import { AlertTriangle, Trash2 } from 'lucide-react';
import { btn } from '@/components/features/vms/kit';
import { adminxApi } from '@/foundation/api/modules';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const COLLECTION = new Set(['default']);   // a hint only: the API applies the installation's configured list

export function GroupMappingsPanel({ orgId, orgName, canManage }: { orgId: string; orgName: string; canManage: boolean }) {
    const maps = useResource(useCallback(() => adminxApi.mappings(orgId), [orgId]));
    const [group, setGroup] = useState('');
    const act = useAction();
    const collection = COLLECTION.has(group.trim());
    return (
        <Loaded title="NovrAgent groups" hint={`Agents in these groups belong to ${orgName}. An agent whose groups map to two organizations is quarantined, never guessed.`}
            data={maps.data} error={maps.error} reload={maps.reload} testid="agent-group-mappings">
            {(d) => (
                <>
                    {act.notice}
                    <DataTable rows={d.items} rowKey={(m) => m.id} empty="No group mapped: no agent's alert is attributed to this organization." columns={[
                        { key: 'g', header: 'Group', render: (m) => <span className="font-mono">{m.group_name}{m.collection && (
                            <span className="ml-2 inline-flex items-center gap-1 text-[11px] font-sans font-semibold text-[var(--vz-warning,#b45309)]"
                                title="A collection group holds agents of every organization: this mapping never makes an agent this organization's" data-testid="collection-group">
                                <AlertTriangle className="w-3 h-3" aria-hidden />collection group: ignored for attribution; remove it</span>)}</span> },
                        { key: 'c', header: 'Mapped', render: (m) => <span className="text-xs">{fmt(m.created_at)}</span> },
                        { key: 'x', header: '', render: (m) => (canManage ? <button className={btn('ghost')} aria-label={`Unmap ${m.group_name}`} disabled={act.busy}
                            onClick={() => void act.run(() => adminxApi.removeMapping(orgId, m.id), 'Unmapped.').then(() => maps.reload())}><Trash2 className="w-3.5 h-3.5" aria-hidden /></button> : null) },
                    ]} />
                    {canManage && (
                        <div className="mt-3 space-y-2">
                            <div className="flex flex-wrap items-end gap-2">
                                <Field label="NovrAgent group"><TextInput value={group} pattern="[A-Za-z0-9_.-]{1,128}" onChange={(e) => setGroup(e.target.value)} /></Field>
                                <button className={btn('primary')} disabled={act.busy || !group.trim() || collection} data-testid="map-group"
                                    onClick={() => void act.run(() => adminxApi.addMapping(orgId, group.trim(), false), 'Mapped.').then((r) => { if (r) { setGroup(''); maps.reload(); } })}>Map group</button>
                            </div>
                            {collection && (
                                <p className="text-xs rounded-lg border border-border bg-card-muted p-2 max-w-2xl" data-testid="collection-hint">
                                    <span className="font-mono">{group.trim()}</span> is a collection group: every newly enrolled agent, of every organization, is placed in it, so it can
                                    never show that an agent belongs to {orgName}. Put {orgName}&apos;s agents in a group of their own and map that group.</p>
                            )}
                        </div>
                    )}
                </>
            )}
        </Loaded>
    );
}
