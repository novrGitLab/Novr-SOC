'use client';

// Users and teams: analyst onboarding (a user with a one-time temporary password, changed at first sign-in), role and
// organization assignments (operations or reporting access to client organizations), and analyst teams.
import { useCallback, useState, type FormEvent } from 'react';
import { UserCog } from 'lucide-react';
import { Drawer, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { adminApi } from '../api';

type User = Schemas['AdminUser'];
const ROLES = ['analyst', 'soc_manager', 'executive', 'portal_user', 'super_admin'] as const;

function Assignments({ user, onClose }: { user: User; onClose: () => void }) {
    const { orgId } = useSession();
    const ms = useResource(useCallback(() => adminxApi.memberships(orgId, user.id), [orgId, user.id]));
    const orgs = useResource(useCallback(() => adminApi.orgs(orgId), [orgId]));
    const [org, setOrg] = useState('');
    const [scope, setScope] = useState<'operations' | 'reporting'>(user.role === 'executive' ? 'reporting' : 'operations');
    const act = useAction();
    return (
        <Drawer open onClose={onClose} title={user.email} subtitle={`${user.role} · organization access`}>
            {act.notice}
            <Loaded title="Organizations" data={ms.data} error={ms.error} reload={ms.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(m) => m.org_id} columns={[
                    { key: 'o', header: 'Organization', render: (m) => m.org_name }, { key: 's', header: 'Access', render: (m) => <Tag>{m.access_scope}</Tag> },
                    { key: 'x', header: '', render: (m) => (m.access_scope === 'home' ? null : <button className={btn('ghost')} disabled={act.busy}
                        onClick={() => void act.run(() => adminxApi.revokeMembership(orgId, user.id, m.org_id), 'Assignment removed.').then(() => ms.reload())}>Remove</button>) },
                ]} />}
            </Loaded>
            <div className="mt-4 flex flex-wrap items-end gap-2 text-xs">
                <Field label="Assign to"><select className={selectCls} value={org} onChange={(e) => setOrg(e.target.value)}>
                    <option value="">Choose a client organization…</option>{(orgs.data?.items ?? []).filter((o) => o.kind === 'client').map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
                <Field label="Access"><select className={selectCls} value={scope} onChange={(e) => setScope(e.target.value as typeof scope)}>
                    <option value="operations" disabled={user.role === 'executive'}>operations</option><option value="reporting">reporting (read-only)</option></select></Field>
                <button className={btn('primary')} disabled={act.busy || !org} onClick={() => void act.run(() => adminxApi.grant(orgId, user.id, { org_id: org, access_scope: scope }), 'Assigned.').then(() => ms.reload())}>Assign</button>
            </div>
        </Drawer>
    );
}

export default function UsersPage() {
    const { orgId, session } = useSession();
    const users = useResource(useCallback(() => adminApi.users(orgId), [orgId]));
    const teams = useResource(useCallback(() => adminxApi.teams(orgId), [orgId]));
    const [nu, setNu] = useState({ email: '', role: 'analyst' as (typeof ROLES)[number] });
    const [secret, setSecret] = useState<string | null>(null);
    const [open, setOpen] = useState<User | null>(null);
    const [team, setTeam] = useState('');
    const [member, setMember] = useState<Record<string, string>>({});
    const act = useAction();

    async function createUser(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => adminApi.createUser(orgId, { email: nu.email.trim(), role: nu.role, display_name: '', access_scope: 'home' }), 'User created.');
        if (r) { setSecret(r.temporary_password); setNu({ ...nu, email: '' }); users.reload(); }
    }

    return (
        <>
            <PageHeader title="Users and teams" icon={UserCog}
                description={`Analyst onboarding and role management for ${session.active_org.name}. A new user receives a one-time temporary password and must change it at first sign-in. Assign analysts to client organizations here.`} />
            {act.notice}
            {secret && <Card><p className="text-sm font-bold">Temporary password: copy it now, it will not be shown again</p><p className="font-mono text-xs break-all mt-1" data-testid="one-time-secret">{secret}</p>
                <button className={`${btn('secondary')} mt-2`} onClick={() => setSecret(null)}>I have stored it</button></Card>}
            <Loaded title="Users" data={users.data} error={users.error} reload={users.reload} testid="users">
                {(d) => <DataTable rows={d.items} rowKey={(u) => u.id} empty="No users." columns={[
                    { key: 'e', header: 'User', render: (u) => <span><strong>{u.email}</strong><span className="block text-[11px] text-foreground-muted">{u.access_scope}</span></span> },
                    { key: 'r', header: 'Role', render: (u) => <Tag>{u.role}</Tag> },
                    { key: 's', header: 'Status', render: (u) => <StateTag state={u.status === 'active' ? 'active' : 'revoked'} label={u.locked ? 'locked' : u.status} /> },
                    { key: 'l', header: 'Last sign-in', render: (u) => <span className="text-xs">{fmt(u.last_login_at)}</span> },
                    { key: 'x', header: '', render: (u) => <button className={btn('ghost')} onClick={() => setOpen(u)}>Organizations</button> },
                ]} />}
            </Loaded>
            <Card>
                <SectionTitle title="Onboard a user" />
                <form onSubmit={createUser} className="mt-3 flex flex-wrap items-end gap-2 text-xs">
                    <Field label="Email"><TextInput type="email" required value={nu.email} onChange={(e) => setNu({ ...nu, email: e.target.value })} /></Field>
                    <Field label="Role"><select className={selectCls} value={nu.role} onChange={(e) => setNu({ ...nu, role: e.target.value as typeof nu.role })}>
                        {ROLES.map((r) => <option key={r} value={r}>{r.replace('_', ' ')}</option>)}</select></Field>
                    <button className={btn('primary')} disabled={act.busy}>Create user</button>
                </form>
            </Card>
            <Loaded title="Teams" data={teams.data} error={teams.error} reload={teams.reload} testid="teams"
                action={<span className="flex items-end gap-2"><TextInput aria-label="New team name" placeholder="New team name" value={team} onChange={(e) => setTeam(e.target.value)} />
                    <button className={btn('secondary')} disabled={act.busy || team.trim().length < 2} onClick={() => void act.run(() => adminxApi.createTeam(orgId, { name: team.trim(), description: '' }), 'Team created.').then(() => { setTeam(''); teams.reload(); })}>Create team</button></span>}>
                {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">No teams.</p> : (
                    <ul className="grid sm:grid-cols-2 gap-3">
                        {d.items.map((t) => (
                            <li key={t.id} className="border border-border rounded-xl p-3 text-xs space-y-2">
                                <p className="font-semibold text-sm">{t.name}</p>
                                <ul>{t.members.map((m) => <li key={m.user_id} className="flex items-center gap-2">{m.email} <Tag>{m.team_role}</Tag>
                                    <button className={btn('ghost')} onClick={() => void act.run(() => adminxApi.removeMember(orgId, t.id, m.user_id), 'Removed.').then(() => teams.reload())}>Remove</button></li>)}</ul>
                                <div className="flex gap-2"><select className={selectCls} value={member[t.id] ?? ''} onChange={(e) => setMember({ ...member, [t.id]: e.target.value })} aria-label="Add member">
                                    <option value="">Add a member…</option>{(users.data?.items ?? []).map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}</select>
                                    <button className={btn('secondary')} disabled={!member[t.id]} onClick={() => void act.run(() => adminxApi.addMember(orgId, t.id, { user_id: member[t.id], team_role: 'member' }), 'Added.').then(() => teams.reload())}>Add</button></div>
                            </li>
                        ))}
                    </ul>
                )}
            </Loaded>
            {open && <Assignments user={open} onClose={() => setOpen(null)} />}
        </>
    );
}
