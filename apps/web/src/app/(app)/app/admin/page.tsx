'use client';

import { useCallback, useState } from 'react';
import { Users } from 'lucide-react';
import { Notice, PageHeader, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { Card, StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { OnboardingPanel } from './OnboardingPanel';
import { adminApi } from './api';

const ROLES = ['analyst', 'soc_manager', 'executive', 'portal_user', 'super_admin'] as const;
const KINDS: Record<string, string> = { vms_worker: 'vms:worker', ti_feeder: 'intel:ingest', forwarder: 'alerts:ingest', email_gateway: 'email:verdicts' };

export default function AdminPage() {
    const { orgId, can, session } = useSession();
    const orgs = useResource(useCallback(() => (can('users:manage') ? adminApi.orgs(orgId) : Promise.resolve({ items: [] })), [orgId, can]));
    const users = useResource(useCallback(() => (can('users:manage') ? adminApi.users(orgId) : Promise.resolve({ items: [] })), [orgId, can]));
    const idents = useResource(useCallback(() => adminApi.identities(orgId), [orgId]));
    const backups = useResource(useCallback(() => (can('backups:read') ? adminApi.backups(orgId) : Promise.resolve({ items: [] })), [orgId, can]));
    const [secret, setSecret] = useState<string | null>(null);
    const [org, setOrg] = useState({ slug: '', name: '' });
    const [user, setUser] = useState({ email: '', role: 'analyst' as (typeof ROLES)[number] });
    const [ident, setIdent] = useState({ kind: 'vms_worker', name: '' });
    const [msg, setMsg] = useState<Msg>(null);
    const run = async (fn: () => Promise<unknown>, ok?: string) => { setMsg(null); try { await fn(); if (ok) setMsg({ ok: true, text: ok }); } catch (e) { setMsg({ ok: false, text: errorText(e) }); } };

    return (
        <>
            <PageHeader title="Organizations and onboarding" icon={Users} description={`Client organizations, onboarding progress, users, machine identities and backups for ${session.active_org.name}. Switch the active organization (top bar) to onboard a client. Secrets (temporary passwords, machine credentials) are shown once and stored only as hashes.`} />
            {can('users:manage') && <OnboardingPanel />}
            <Notice msg={msg} />
            {secret && <Card><p className="text-sm font-bold">Copy this now — it will not be shown again</p><p className="font-mono text-xs break-all mt-1" data-testid="one-time-secret">{secret}</p>
                <button className={btn('secondary')} onClick={() => setSecret(null)}>I have stored it</button></Card>}
            {can('users:manage') && (
                <div className="grid gap-5 lg:grid-cols-2">
                    <Loaded title="Organizations" data={orgs.data} error={orgs.error}>
                        {(d) => (<>
                            <DataTable testid="admin-orgs" rows={d.items} rowKey={(o) => o.id} columns={[
                                { key: 'n', header: 'Organization', render: (o) => <span>{o.name}<span className="block text-[11px] font-mono text-foreground-muted">{o.slug}</span></span> },
                                { key: 'k', header: 'Kind', render: (o) => <Tag>{o.kind}</Tag> }, { key: 's', header: 'Status', render: (o) => o.status }]} />
                            <div className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="Slug"><TextInput value={org.slug} onChange={(e) => setOrg({ ...org, slug: e.target.value })} /></Field>
                                <Field label="Name"><TextInput value={org.name} onChange={(e) => setOrg({ ...org, name: e.target.value })} /></Field>
                                <button className={btn('primary')} disabled={!org.slug || !org.name} onClick={() => void run(async () => { await adminApi.createOrg(orgId, org); orgs.reload(); }, 'Organization created.')}>Create</button>
                            </div></>)}
                    </Loaded>
                    <Loaded title="Users of this organization" data={users.data} error={users.error}>
                        {(d) => (<>
                            <DataTable testid="admin-users" rows={d.items} rowKey={(u) => u.id} columns={[
                                { key: 'e', header: 'User', render: (u) => <span>{u.email}<span className="block text-[11px] text-foreground-muted">{u.role} · last sign-in {fmt(u.last_login_at)}</span></span> },
                                { key: 's', header: 'Status', render: (u) => <StatusPill tone={u.status === 'active' ? 'good' : 'neutral'} label={u.locked ? 'locked' : u.status} /> },
                                { key: 'a', header: '', render: (u) => u.id === session.user.id ? null : <span className="flex flex-wrap gap-1">
                                    <button className={btn('ghost')} onClick={() => void run(async () => {
                                        await adminApi.setStatus(orgId, u.id, u.status === 'active' ? 'disabled' : 'active'); users.reload(); })}>{u.status === 'active' ? 'Disable' : 'Enable'}</button>
                                    <button className={btn('ghost')} onClick={() => void run(async () => { const r = await adminApi.resetPassword(orgId, u.id);
                                        setSecret(`New temporary password for ${r.user.email}: ${r.temporary_password} (shown once; their sessions were signed out and they must change it at sign-in)`); users.reload(); })}>Reset password</button>
                                </span> },
                            ]} />
                            <div className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="Email"><TextInput type="email" value={user.email} onChange={(e) => setUser({ ...user, email: e.target.value })} /></Field>
                                <Field label="Role"><select className={inputCls} value={user.role} onChange={(e) => setUser({ ...user, role: e.target.value as (typeof ROLES)[number] })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select></Field>
                                <button className={btn('primary')} disabled={!user.email.includes('@')} onClick={() => void run(async () => {
                                    const r = await adminApi.createUser(orgId, { email: user.email, role: user.role, display_name: '', access_scope: 'home' });
                                    setSecret(`Temporary password for ${r.user.email}: ${r.temporary_password} (shown once; they must change it at first sign-in)`); users.reload(); })}>Create user</button>
                            </div></>)}
                    </Loaded>
                </div>
            )}
            {can('service_identities:manage') && (
                <Loaded title="Machine identities" hint="Forwarders, local VMS workers, TAXII feeders. Revocation takes effect immediately." data={idents.data} error={idents.error}>
                    {(d) => (<>
                        <DataTable testid="admin-identities" rows={d.items} rowKey={(i) => i.id} empty="No machine identity." columns={[
                            { key: 'n', header: 'Identity', render: (i) => <span>{i.name}<span className="block text-[11px] text-foreground-muted">{i.kind} · {i.scopes.join(', ') || 'no scope'}</span></span> },
                            { key: 's', header: 'Status', render: (i) => <StatusPill tone={i.status === 'active' ? 'good' : 'neutral'} label={i.status} /> },
                            { key: 'u', header: 'Last used', className: 'hidden md:table-cell', render: (i) => <span className="text-xs">{fmt(i.last_used_at)}</span> },
                            { key: 'a', header: '', render: (i) => i.status === 'active' ? <button className={btn('ghost')} onClick={() => void run(async () => { await adminApi.revoke(orgId, i.id); idents.reload(); })}>Revoke</button> : null },
                        ]} />
                        <div className="mt-3 flex flex-wrap items-end gap-2">
                            <Field label="Kind"><select className={inputCls} value={ident.kind} onChange={(e) => setIdent({ ...ident, kind: e.target.value })}>{Object.keys(KINDS).map((k) => <option key={k}>{k}</option>)}</select></Field>
                            <Field label="Name"><TextInput value={ident.name} onChange={(e) => setIdent({ ...ident, name: e.target.value })} /></Field>
                            <button className={btn('primary')} disabled={!ident.name} onClick={() => void run(async () => {
                                const r = await adminApi.issue(orgId, { kind: ident.kind as never, name: ident.name, scopes: [KINDS[ident.kind]], site_id: null });
                                setSecret(`Credential for ${r.identity.name}: ${r.credential}`); idents.reload(); })}>Issue credential</button>
                        </div></>)}
                </Loaded>
            )}
            {can('backups:read') && (
                <Loaded title="Backups" hint="Encrypted logical dumps and restore drills (python -m app.cli backup / restore-drill)" data={backups.data} error={backups.error}>
                    {(d) => <DataTable testid="admin-backups" rows={d.items} rowKey={(b) => b.id} empty="No backup has run in this installation." columns={[
                        { key: 'w', header: 'Started', render: (b) => <span className="text-xs">{fmt(b.started_at)}</span> },
                        { key: 's', header: 'Status', render: (b) => <StatusPill tone={b.status === 'succeeded' ? 'good' : b.status === 'failed' ? 'critical' : 'neutral'} label={b.status} /> },
                        { key: 'z', header: 'Size', render: (b) => b.size_bytes ? `${Math.round(b.size_bytes / 1024)} KiB` : '—' },
                        { key: 'd', header: 'Restore drill', render: (b) => b.last_drill_status ? <span className="text-xs">{b.last_drill_status} · {fmt(b.last_drill_at)}</span> : <span className="text-xs text-foreground-muted">never drilled</span> },
                    ]} />}
                </Loaded>
            )}
        </>
    );
}
