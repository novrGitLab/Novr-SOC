'use client';

// Machine identities of ONE organization: forwarders (platform organization), VMS workers, TAXII feeders, collectors.
// Each kind holds only its own scope (the API refuses anything else); the credential is shown once and stored hashed.
import { useCallback, useState } from 'react';
import { btn } from '@/components/features/vms/kit';
import { Card, StatusPill } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { orgApi } from '@/foundation/api/modules';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Kind = Schemas['ServiceIdentityCreate']['kind'];
// Mirrors novrsoc_contracts.v1.platform.SERVICE_KIND_SCOPES (the API is the authority and refuses any other scope).
const KIND_SCOPE: Partial<Record<Kind, string>> = { vms_worker: 'vms:worker', ti_feeder: 'intel:ingest', forwarder: 'alerts:ingest', email_gateway: 'email:verdicts' };

export function IdentitiesPanel({ orgId, orgName, canManage }: { orgId: string; orgName: string; canManage: boolean }) {
    const idents = useResource(useCallback(() => orgApi.identities(orgId), [orgId]));
    const [kind, setKind] = useState<Kind>('vms_worker');
    const [name, setName] = useState('');
    const [secret, setSecret] = useState<string | null>(null);
    const act = useAction();
    return (
        <Loaded title="Machine identities" hint={`Credentials bound to ${orgName}. Revocation takes effect immediately.`} data={idents.data} error={idents.error}
            reload={idents.reload} testid="admin-identities">
            {(d) => (
                <>
                    {act.notice}
                    {secret && <Card><p className="text-sm font-bold">Copy this now: it will not be shown again</p><p className="font-mono text-xs break-all mt-1" data-testid="one-time-secret">{secret}</p>
                        <button className={btn('secondary')} onClick={() => setSecret(null)}>I have stored it</button></Card>}
                    <DataTable rows={d.items} rowKey={(i) => i.id} empty="No machine identity." columns={[
                        { key: 'n', header: 'Identity', render: (i) => <span>{i.name}<span className="block text-[11px] text-foreground-muted">{i.kind} · {i.scopes.join(', ') || 'no scope'}</span></span> },
                        { key: 's', header: 'Status', render: (i) => <StatusPill tone={i.status === 'active' ? 'good' : 'neutral'} label={i.status} /> },
                        { key: 'u', header: 'Last used', className: 'hidden md:table-cell', render: (i) => <span className="text-xs">{fmt(i.last_used_at)}</span> },
                        { key: 'a', header: '', render: (i) => (canManage && i.status === 'active'
                            ? <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => orgApi.revokeIdentity(orgId, i.id), 'Revoked.').then(() => idents.reload())}>Revoke</button> : null) },
                    ]} />
                    {canManage && (
                        <div className="mt-3 flex flex-wrap items-end gap-2">
                            <Field label="Kind"><select className={selectCls} value={kind} onChange={(e) => setKind(e.target.value as Kind)}>
                                {Object.keys(KIND_SCOPE).map((k) => <option key={k} value={k}>{k}</option>)}</select></Field>
                            <Field label="Name"><TextInput value={name} onChange={(e) => setName(e.target.value)} /></Field>
                            <button className={btn('primary')} disabled={act.busy || name.trim().length < 2} onClick={() => void act.run(async () => {
                                const r = await orgApi.issueIdentity(orgId, { kind, name: name.trim(), scopes: [KIND_SCOPE[kind] as string], site_id: null });
                                setSecret(`Credential for ${r.identity.name} (${r.identity.kind}): ${r.credential}`); setName(''); idents.reload();
                            })}>Issue credential</button>
                        </div>
                    )}
                </>
            )}
        </Loaded>
    );
}
