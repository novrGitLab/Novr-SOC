'use client';

// One organization (platform administrators). Its own data is read through the regular module APIs with this
// organization as X-Org-Id: the API re-validates the switch (audited) and the database's row-level security applies, so
// nothing here can show another organization's records. A suspended or archived organization cannot be switched into;
// its data tabs say so and Settings can reactivate it.
import { sourceName } from '@/foundation/ui/names';
import Link from 'next/link';
import { useParams, useRouter } from 'next/navigation';
import { useCallback, useState, type ReactNode } from 'react';
import { ArrowLeftRight, Building2, CheckCircle2, Circle } from 'lucide-react';
import { ConfirmDialog, PageHeader, SearchBox, btn, nf } from '@/components/features/vms/kit';
import { Card, StatusPill, Unavailable } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { adminxApi, assetsApi, orgApi, secopsApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { Grid, StateTag, initialParam, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { GroupMappingsPanel } from '../../_org/GroupMappingsPanel';
import { IdentitiesPanel } from '../../_org/IdentitiesPanel';
import { LogSourcesPanel } from '../../_org/LogSourcesPanel';
import { HEALTH, ONBOARDING_STEPS, ORG_STATUS, ORG_TABS, type OrgTab } from '../../_org/meta';

type Org = Schemas['OrgDetail'];

export default function OrganizationPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId, session, switchOrg, can } = useSession();
    const router = useRouter();
    const [tab, setTabState] = useState<OrgTab>(() => (ORG_TABS.some(([k]) => k === initialParam('tab')) ? initialParam('tab') as OrgTab : 'overview'));
    const org = useResource(useCallback(() => orgApi.detail(orgId, id), [orgId, id]));
    const setTab = (t: OrgTab) => {
        setTabState(t);
        try { window.history.replaceState(null, '', `${window.location.pathname}${t === 'overview' ? '' : `?tab=${t}`}`); } catch { /* ignore */ }
    };
    const openAs = (href: string) => { switchOrg(id); router.push(href); };

    if (session.role !== 'super_admin' || !can('users:manage')) {
        return <><PageHeader title="Organization" icon={Building2} /><Card><Unavailable reason="Organization management is for platform administrators." /></Card></>;
    }
    return (
        <>
            <PageHeader title={org.data?.name ?? 'Organization'} icon={Building2}
                description={org.data ? <>{org.data.slug} · {org.data.kind === 'platform' ? 'platform organization' : 'client organization'} · created {fmt(org.data.created_at)}</> : undefined}
                meta={<Link href="/app/admin" className="text-xs underline text-foreground-muted">All organizations</Link>}
                actions={org.data?.status === 'active' && id !== orgId
                    ? <button className={btn('secondary')} data-testid="switch-to-org" onClick={() => openAs('/app')}><ArrowLeftRight className="w-3.5 h-3.5" aria-hidden />Switch to this organization</button> : undefined} />
            <nav aria-label="Organization sections" role="tablist" className="flex gap-1 overflow-x-auto border-b border-border -mt-2 mb-2" data-testid="org-tabs">
                {ORG_TABS.map(([k, label]) => (
                    <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} data-tab={k}
                        className={`px-3 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors ${tab === k ? 'border-purple text-purple font-semibold' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>{label}</button>
                ))}
            </nav>
            <Loaded title="" data={org.data} error={org.error} reload={org.reload} testid="org-detail">
                {(o) => {
                    const scoped = (node: ReactNode) => (o.status === 'active' ? node
                        : <Card><Unavailable reason={`${o.name} is ${o.status}: its data cannot be opened. Reactivate it in Settings to manage it.`} /></Card>);
                    switch (tab) {
                        case 'overview': return <Overview o={o} go={setTab} />;
                        case 'users': return scoped(<UsersTab o={o} />);
                        case 'assets': return scoped(<AssetsTab o={o} openAs={openAs} />);
                        case 'integrations': return scoped(<>
                            <GroupMappingsPanel orgId={o.id} orgName={o.name} canManage={can('endpoints:manage')} />
                            <LogSourcesPanel orgId={o.id} orgName={o.name} canManage={can('endpoints:manage')} />
                            <IdentitiesPanel orgId={o.id} orgName={o.name} canManage={can('service_identities:manage')} />
                        </>);
                        case 'policies': return scoped(<PoliciesTab o={o} openAs={openAs} />);
                        case 'billing': return <BillingTab o={o} />;
                        case 'audit': return scoped(<AuditTab o={o} />);
                        case 'settings': return <SettingsTab o={o} onChange={org.setData} />;
                    }
                }}
            </Loaded>
        </>
    );
}

function Tile({ label, value, sub }: { label: string; value: ReactNode; sub?: ReactNode }) {
    return (
        <div className="bg-card border border-border rounded-2xl p-4">
            <p className="text-[11px] font-semibold text-foreground-muted">{label}</p>
            <p className="mt-2 text-[24px] leading-none font-black tabular-nums text-foreground">{value}</p>
            {sub && <p className="mt-2 text-[11px] text-foreground-muted">{sub}</p>}
        </div>
    );
}

function Overview({ o, go }: { o: Org; go: (t: OrgTab) => void }) {
    const i = o.integrations;
    return (
        <>
            <Grid cols={4}>
                <Tile label="Status" value={<StatusPill tone={ORG_STATUS[o.status].tone} label={ORG_STATUS[o.status].label} />} sub={o.status_reason || undefined} />
                <Tile label="Members" value={nf.format(o.users)} sub="home and assigned accounts" />
                <Tile label="Assets" value={nf.format(o.assets)} sub={`${i.wazuh_agents} NovrAgent(s) · ${o.sites} site(s)`} />
                <Tile label="Security events (7 days)" value={nf.format(o.alerts_7d)} sub={`${o.open_cases} open case(s) · last ${fmt(i.last_alert_at)}`} />
            </Grid>
            <Card>
                <div className="flex flex-wrap items-center justify-between gap-2">
                    <h2 className="text-sm font-black">Integration health</h2>
                    <StatusPill tone={HEALTH[i.health].tone} label={HEALTH[i.health].label} />
                </div>
                <p className="text-xs text-foreground-muted mt-1">{i.wazuh_groups} NovrAgent group(s) · {i.log_sources} source(s), {i.log_sources_receiving} receiving, {i.log_sources_never} without any event,
                    {' '}{i.log_sources_disabled} disabled · {i.service_identities} machine identit{i.service_identities === 1 ? 'y' : 'ies'}</p>
                {i.notes.length > 0 && <ul className="mt-2 text-xs list-disc pl-5 space-y-0.5">{i.notes.map((n) => <li key={n}>{n}</li>)}</ul>}
                <button className={`${btn('ghost')} mt-2`} onClick={() => go('integrations')}>Open integrations</button>
            </Card>
            <Card>
                <h2 className="text-sm font-black">Onboarding: {o.onboarding.completed} of {o.onboarding.total}</h2>
                <p className="text-xs text-foreground-muted">Each step is read from the organization&apos;s configuration. Optional steps do not count; one of them is enough for telemetry.</p>
                <ol className="mt-3 grid sm:grid-cols-2 lg:grid-cols-3 gap-2 text-xs" data-testid="onboarding">
                    {Object.entries(o.onboarding.steps).map(([k, done]) => {
                        const meta = ONBOARDING_STEPS[k];
                        const optional = o.onboarding.optional_steps.includes(k);
                        return (
                            <li key={k} className="flex items-start gap-2 rounded-lg border border-border p-2" data-done={done}>
                                {done ? <CheckCircle2 className="w-4 h-4 text-[var(--vz-good)] shrink-0" aria-hidden /> : <Circle className="w-4 h-4 text-foreground-muted shrink-0" aria-hidden />}
                                <span className="min-w-0">
                                    <button className={`text-left ${done ? '' : 'font-semibold underline'}`} onClick={() => go(meta?.tab ?? 'overview')}>{meta?.label ?? k}{optional ? ' (optional)' : ''}</button>
                                    <span className="block text-[11px] text-foreground-muted">{meta?.hint}</span>
                                </span>
                                <span className="sr-only">{done ? 'done' : 'to do'}</span>
                            </li>
                        );
                    })}
                </ol>
            </Card>
        </>
    );
}

function UsersTab({ o }: { o: Org }) {
    const { orgId } = useSession();
    const users = useResource(useCallback(() => orgApi.users(o.id), [o.id]));
    const teams = useResource(useCallback(() => adminxApi.teams(o.id), [o.id]));
    const [q, setQ] = useState('');
    const found = useResource(useCallback(() => (q.length >= 2 ? orgApi.searchUsers(orgId, q) : Promise.resolve(null)), [orgId, q]));
    const [newUser, setNewUser] = useState({ email: '', role: 'analyst' as Schemas['AdminUserCreate']['role'] });
    const [team, setTeam] = useState('');
    const [secret, setSecret] = useState<string | null>(null);
    const act = useAction();
    const members = new Set((users.data?.items ?? []).map((u) => u.id));
    return (
        <>
            {act.notice}
            {secret && <Card><p className="text-sm font-bold">Copy this now: it will not be shown again</p><p className="font-mono text-xs break-all mt-1" data-testid="one-time-secret">{secret}</p>
                <button className={btn('secondary')} onClick={() => setSecret(null)}>I have stored it</button></Card>}
            <Loaded title="Members" hint="Home accounts of this organization and analysts or executives assigned to it" data={users.data} error={users.error} reload={users.reload} testid="org-members">
                {(d) => <DataTable rows={d.items} rowKey={(u) => u.id} empty="No member yet." columns={[
                    { key: 'e', header: 'User', render: (u) => <span>{u.email}<span className="block text-[11px] text-foreground-muted">{u.role} · last sign-in {fmt(u.last_login_at)}</span></span> },
                    { key: 's', header: 'Access', render: (u) => <span className="text-xs">{u.access_scope === 'home' ? 'Home organization' : u.access_scope === 'operations' ? 'Assigned: operations' : 'Assigned: reporting (read-only)'}</span> },
                    { key: 'st', header: 'Status', render: (u) => <StatusPill tone={u.status === 'active' ? 'good' : 'neutral'} label={u.locked ? 'locked' : u.status} /> },
                    { key: 'a', header: '', render: (u) => (u.access_scope !== 'home' ? <button className={btn('ghost')} disabled={act.busy}
                        onClick={() => void act.run(() => adminxApi.revokeMembership(orgId, u.id, o.id), 'Assignment removed.').then(() => users.reload())}>Remove assignment</button> : null) },
                ]} />}
            </Loaded>
            <Card>
                <h2 className="text-sm font-black">Assign an existing user</h2>
                <p className="text-xs text-foreground-muted">The same account gains access to {o.name}: no duplicate account, one password. Analysts and managers get operations access; executives read-only reporting access. Switching is audited.</p>
                <div className="mt-2"><SearchBox value={q} onSubmit={setQ} placeholder="E-mail or name (at least 2 characters)" label="Find a user" /></div>
                {found.data && <DataTable rows={found.data.items} rowKey={(u) => u.id} empty="No user matches." columns={[
                    { key: 'e', header: 'User', render: (u) => <span>{u.email}<span className="block text-[11px] text-foreground-muted">{u.role ?? 'no role'} · home: {u.home_org_name ?? 'none'}</span></span> },
                    { key: 'm', header: 'Organizations', className: 'hidden md:table-cell', render: (u) => <span className="text-xs">{u.memberships.map((m) => `${m.org_name} (${m.access_scope})`).join(', ')}</span> },
                    { key: 'a', header: '', render: (u) => members.has(u.id) ? <span className="text-xs text-foreground-muted">Already a member</span>
                        : u.role === 'super_admin' || u.role === 'portal_user' ? <span className="text-xs text-foreground-muted">Cannot be assigned</span>
                        : <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => adminxApi.grant(orgId, u.id,
                            { org_id: o.id, access_scope: u.role === 'executive' ? 'reporting' : 'operations' }), `${u.email} assigned to ${o.name}.`).then(() => { users.reload(); found.reload(); })}>
                            Assign ({u.role === 'executive' ? 'reporting' : 'operations'})</button> },
                ]} />}
            </Card>
            <Card>
                <h2 className="text-sm font-black">Create a new account in {o.name}</h2>
                <div className="mt-2 flex flex-wrap items-end gap-2">
                    <Field label="E-mail"><TextInput type="email" value={newUser.email} onChange={(e) => setNewUser({ ...newUser, email: e.target.value })} /></Field>
                    <Field label="Role"><select className={selectCls} value={newUser.role} onChange={(e) => setNewUser({ ...newUser, role: e.target.value as typeof newUser.role })}>
                        {(['analyst', 'soc_manager', 'executive', 'portal_user'] as const).map((r) => <option key={r}>{r}</option>)}</select></Field>
                    <button className={btn('primary')} disabled={act.busy || !newUser.email.includes('@')} onClick={() => void act.run(async () => {
                        const r = await orgApi.createUser(o.id, { email: newUser.email.trim(), role: newUser.role, display_name: '', access_scope: 'home' });
                        setSecret(`Temporary password for ${r.user.email}: ${r.temporary_password} (shown once; it must be changed at first sign-in)`);
                        setNewUser({ ...newUser, email: '' }); users.reload();
                    })}>Create account</button>
                </div>
            </Card>
            <Loaded title="Teams" data={teams.data} error={teams.error} reload={teams.reload}>
                {(d) => (<>
                    <DataTable rows={d.items} rowKey={(t) => t.id} empty="No team." columns={[
                        { key: 'n', header: 'Team', render: (t) => t.name },
                        { key: 'm', header: 'Members', render: (t) => <span className="text-xs">{t.members.map((m) => m.email).join(', ') || '—'}</span> },
                    ]} />
                    <div className="mt-3 flex items-end gap-2">
                        <Field label="New team"><TextInput value={team} onChange={(e) => setTeam(e.target.value)} /></Field>
                        <button className={btn('primary')} disabled={act.busy || team.trim().length < 2} onClick={() => void act.run(() => adminxApi.createTeam(o.id, { name: team.trim(), description: '' }), 'Team created.')
                            .then(() => { setTeam(''); teams.reload(); })}>Create team</button>
                    </div>
                </>)}
            </Loaded>
        </>
    );
}

function AssetsTab({ o, openAs }: { o: Org; openAs: (href: string) => void }) {
    const eps = useResource(useCallback(() => orgApi.endpoints(o.id), [o.id]));
    const sites = useResource(useCallback(() => orgApi.sites(o.id), [o.id]));
    const runs = useResource(useCallback(() => assetsApi.syncRuns(o.id), [o.id]));
    const act = useAction();
    return (
        <>
            {act.notice}
            <Grid cols={3}>
                <Tile label="Assets in the inventory" value={nf.format(o.assets)} sub={<button className="underline" onClick={() => openAs('/app/assets')}>Open the asset inventory as {o.name}</button>} />
                <Tile label="NovrAgents reconciled" value={nf.format(o.integrations.wazuh_agents)} sub={`${o.integrations.wazuh_groups} mapped group(s)`} />
                <Tile label="Sites" value={nf.format(o.sites)} sub={<button className="underline" onClick={() => openAs('/app/sites')}>Manage sites and networks</button>} />
            </Grid>
            <Loaded title="Discovered endpoints" hint="Agents of the mapped NovrAgent groups, from the NovrSIEM connector" data={eps.data} error={eps.error} reload={eps.reload} testid="org-endpoints">
                {(d) => (<>
                    <p className="text-xs mb-2">Source: <StateTag state={d.source.state} /> {d.source.detail ? <span className="text-foreground-muted">{d.source.detail}</span> : null}
                        {' '}· {Object.entries(d.by_status).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(' · ') || 'no agent'}</p>
                    <DataTable rows={d.items.slice(0, 100)} rowKey={(e) => e.agent_id} empty={d.mapped_groups ? 'No agent in the mapped groups.' : 'No NovrAgent group is mapped: map one in Integrations.'} columns={[
                        { key: 'a', header: 'Agent', render: (e) => <span>{e.name}<span className="block font-mono text-[11px] text-foreground-muted">{e.agent_id} · {e.ip ?? 'no address'}</span></span> },
                        { key: 's', header: 'Status', render: (e) => <StateTag state={e.status === 'active' ? 'active' : e.status} /> },
                        { key: 'g', header: 'Groups', className: 'hidden md:table-cell', render: (e) => <span className="font-mono text-xs">{e.groups.join(', ')}</span> },
                        { key: 'k', header: 'Last keep-alive', className: 'hidden lg:table-cell', render: (e) => <span className="text-xs">{fmt(e.last_keepalive_at)}</span> },
                    ]} />
                </>)}
            </Loaded>
            <Loaded title="Inventory synchronization" hint="Reconciliation runs into the organization's asset inventory"
                action={<button className={btn('primary')} disabled={act.busy} onClick={() => void act.run(() => assetsApi.syncWazuh(o.id), (r) => `Sync ${r.outcome}: ${r.observed} observed, ${r.created} new.`).then(() => runs.reload())}>Sync NovrAgents now</button>}
                data={runs.data} error={runs.error} reload={runs.reload}>
                {(d) => <DataTable rows={d.items.slice(0, 10)} rowKey={(r) => r.id} empty="No synchronization has run." columns={[
                    { key: 't', header: 'Started', render: (r) => <span className="text-xs">{fmt(r.started_at)}</span> },
                    { key: 's', header: 'Source', render: (r) => <span className="text-xs">{sourceName(r.source)} · {r.source_state}</span> },
                    { key: 'o', header: 'Outcome', render: (r) => <StateTag state={r.outcome === 'completed' ? 'completed' : r.outcome === 'failed' ? 'failed' : 'unconfigured'} label={r.outcome.replace(/_/g, ' ')} /> },
                    { key: 'n', header: 'Observed / new', render: (r) => <span className="tabular-nums text-xs">{r.observed} / {r.created}{r.conflicts ? ` · ${r.conflicts} conflict(s)` : ''}</span> },
                ]} />}
            </Loaded>
            <Loaded title="Sites and networks" data={sites.data} error={sites.error} reload={sites.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(s) => s.id} empty="No site defined." columns={[
                    { key: 'n', header: 'Site', render: (s) => <span>{s.name}<span className="block text-[11px] text-foreground-muted">{s.description}</span></span> },
                    { key: 'c', header: 'Networks', render: (s) => <span className="font-mono text-xs">{s.network_cidrs.join(', ') || '—'}</span> },
                ]} />}
            </Loaded>
        </>
    );
}

function PoliciesTab({ o, openAs }: { o: Org; openAs: (href: string) => void }) {
    const sla = useResource(useCallback(() => secopsApi.policies(o.id), [o.id]));
    const soar = useResource(useCallback(() => orgApi.soarPolicy(o.id), [o.id]));
    return (
        <>
            <Loaded title="SLA policies" action={<button className={btn('secondary')} onClick={() => openAs('/app/sla')}>Edit as {o.name}</button>} data={sla.data} error={sla.error} reload={sla.reload}>
                {(d) => <DataTable rows={d.items} rowKey={(p) => p.severity} empty="No SLA policy: cases of this organization carry no response target." columns={[
                    { key: 's', header: 'Severity', render: (p) => p.severity },
                    { key: 'r', header: 'First response', render: (p) => `${p.response_minutes} min` },
                    { key: 'x', header: 'Resolution', render: (p) => `${p.resolution_minutes} min` },
                    { key: 'e', header: 'Escalates to', render: (p) => p.escalate_to_role.replace('_', ' ') },
                ]} />}
            </Loaded>
            <Loaded title="SOAR response policy" action={<button className={btn('secondary')} onClick={() => openAs('/app/soar/policy')}>Edit as {o.name}</button>} data={soar.data} error={soar.error} reload={soar.reload}>
                {(p) => (
                    <dl className="grid sm:grid-cols-2 gap-x-6 gap-y-2 text-xs">
                        <div><dt className="text-foreground-muted">Allowed actions</dt><dd>{p.allowed_actions.join(', ') || 'none (nothing can be approved)'}</dd></div>
                        <div><dt className="text-foreground-muted">Authorized NovrAgent groups</dt><dd className="font-mono">{p.allowed_agent_groups.join(', ') || 'none'}</dd></div>
                        <div><dt className="text-foreground-muted">Live execution</dt><dd>{p.live_enabled ? 'allowed (after approval)' : 'off: dry runs only'}</dd></div>
                        <div><dt className="text-foreground-muted">Emergency stop</dt><dd>{p.emergency_stop ? `ON since ${fmt(p.emergency_at)}` : 'off'}</dd></div>
                        <div><dt className="text-foreground-muted">Approval validity</dt><dd>{p.approval_ttl_minutes} min</dd></div>
                    </dl>
                )}
            </Loaded>
        </>
    );
}

function BillingTab({ o }: { o: Org }) {
    const { orgId } = useSession();
    const bill = useResource(useCallback(() => adminxApi.billing(orgId), [orgId]));
    const [plan, setPlan] = useState('');
    const [status, setStatus] = useState<Schemas['SubscriptionSet']['status']>('active');
    const act = useAction();
    return (
        <Loaded title="Plan and subscription" hint="Administrative records only: no payment provider is configured and no payment is taken" data={bill.data} error={bill.error} reload={bill.reload}>
            {(d) => {
                const row = d.organizations.find((r) => r.org_id === o.id);
                return (
                    <>
                        {act.notice}
                        <dl className="grid sm:grid-cols-3 gap-3 text-xs">
                            <div><dt className="text-foreground-muted">Plan</dt><dd className="font-semibold">{row?.plan_name ?? 'none recorded'}</dd></div>
                            <div><dt className="text-foreground-muted">Status</dt><dd>{row?.status ?? '—'}{row?.renews_at ? ` · renews ${fmt(row.renews_at)}` : ''}</dd></div>
                            <div><dt className="text-foreground-muted">Usage</dt><dd>{row ? `${row.users} user(s)${row.max_users ? ` of ${row.max_users}` : ''} · ${row.assets} asset(s)${row.max_assets ? ` of ${row.max_assets}` : ''}` : '—'}</dd></div>
                        </dl>
                        {row && row.over_limit.length > 0 && <p className="text-xs mt-2">Over the plan&apos;s limits: {row.over_limit.join(', ')}</p>}
                        <div className="mt-3 flex flex-wrap items-end gap-2">
                            <Field label="Plan"><select className={selectCls} value={plan} onChange={(e) => setPlan(e.target.value)}>
                                <option value="">Choose…</option>{d.plans.filter((p) => p.active).map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}</select></Field>
                            <Field label="Status"><select className={selectCls} value={status} onChange={(e) => setStatus(e.target.value as typeof status)}>
                                {(['trial', 'active', 'past_due', 'cancelled'] as const).map((s) => <option key={s}>{s}</option>)}</select></Field>
                            <button className={btn('primary')} disabled={act.busy || !plan} onClick={() => void act.run(() => adminxApi.setSubscription(orgId, { org_id: o.id, plan_id: plan, status, notes: '', renews_at: null }), 'Subscription recorded.')
                                .then(() => bill.reload())}>Record subscription</button>
                        </div>
                        {d.plans.length === 0 && <p className="text-xs mt-2 text-foreground-muted">No plan exists yet: create one in <Link className="underline" href="/app/admin/billing">Billing</Link>.</p>}
                    </>
                );
            }}
        </Loaded>
    );
}

function AuditTab({ o }: { o: Org }) {
    const ev = useResource(useCallback(() => adminxApi.audit(o.id, { limit: 100 }), [o.id]));
    return (
        <Loaded title="Audit activity" hint="The 100 most recent audit events of this organization" data={ev.data} error={ev.error} reload={ev.reload} testid="org-audit">
            {(d) => <DataTable rows={d.items} rowKey={(e) => String(e.id)} empty="No audit event." columns={[
                { key: 't', header: 'When', render: (e) => <span className="text-xs">{fmt(e.occurred_at)}</span> },
                { key: 'a', header: 'Action', render: (e) => <span className="font-mono text-xs">{e.action}</span> },
                { key: 'w', header: 'Actor', render: (e) => <span className="text-xs">{e.actor_label || e.actor_type}</span> },
                { key: 'o', header: 'Outcome', render: (e) => <StateTag state={e.outcome === 'success' ? 'ok' : e.outcome === 'denied' ? 'refused' : 'failed'} label={e.outcome} /> },
                { key: 'r', header: 'Resource', className: 'hidden md:table-cell', render: (e) => <span className="text-xs">{e.resource_type} {e.resource_id}</span> },
            ]} />}
        </Loaded>
    );
}

function SettingsTab({ o, onChange }: { o: Org; onChange: (o: Org) => void }) {
    const { orgId } = useSession();
    const [f, setF] = useState({ name: o.name, contact_name: o.contact_name, contact_email: o.contact_email, timezone: o.timezone, notes: o.notes });
    const [next, setNext] = useState<Schemas['OrgStatusChange']['status'] | null>(null);
    const act = useAction();
    const actions: [Schemas['OrgStatusChange']['status'], string][] = o.kind === 'platform' ? [] : o.status === 'active'
        ? [['suspended', 'Suspend'], ['archived', 'Archive']] : [['active', 'Reactivate'], ...(o.status === 'suspended' ? [['archived', 'Archive'] as [Schemas['OrgStatusChange']['status'], string]] : [])];
    return (
        <>
            {act.notice}
            <Card>
                <h2 className="text-sm font-black">Profile</h2>
                <div className="mt-2 grid sm:grid-cols-2 gap-3">
                    <Field label="Name"><TextInput value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
                    <Field label="Slug (permanent)"><TextInput value={o.slug} disabled /></Field>
                    <Field label="Contact name"><TextInput value={f.contact_name} onChange={(e) => setF({ ...f, contact_name: e.target.value })} /></Field>
                    <Field label="Contact e-mail"><TextInput type="email" value={f.contact_email} onChange={(e) => setF({ ...f, contact_email: e.target.value })} /></Field>
                    <Field label="Time zone"><TextInput value={f.timezone} onChange={(e) => setF({ ...f, timezone: e.target.value })} /></Field>
                    <Field label="Notes"><TextInput value={f.notes} onChange={(e) => setF({ ...f, notes: e.target.value })} /></Field>
                </div>
                <button className={`${btn('primary')} mt-3`} disabled={act.busy || !f.name.trim()} data-testid="save-org"
                    onClick={() => void act.run(async () => { const r = await orgApi.update(orgId, o.id, { ...f, name: f.name.trim() }); onChange(r); }, 'Saved.')}>Save profile</button>
            </Card>
            <Card>
                <h2 className="text-sm font-black">Status: {ORG_STATUS[o.status].label}</h2>
                <p className="text-xs text-foreground-muted mt-1">Suspended: its members cannot sign in or switch to it and nobody can open its data; telemetry keeps arriving.
                    Archived: kept for the record; it must first have no NovrAgent group mapping and no live source, so no event can reach it. Every change needs a reason and is audited.</p>
                {o.status_reason && <p className="text-xs mt-1">Last reason: {o.status_reason}{o.archived_at ? ` · archived ${fmt(o.archived_at)}` : ''}</p>}
                {o.kind === 'platform' ? <p className="text-xs mt-2">The platform organization is always active.</p> : (
                    <div className="mt-3 flex gap-2">{actions.map(([s, label]) => <button key={s} className={btn(s === 'active' ? 'primary' : 'secondary')} onClick={() => setNext(s)}>{label}</button>)}</div>
                )}
            </Card>
            <ConfirmDialog open={next !== null} title={`${next === 'active' ? 'Reactivate' : next === 'suspended' ? 'Suspend' : 'Archive'} ${o.name}?`}
                tone={next === 'active' ? 'primary' : 'danger'} confirmLabel="Confirm" reason={{ label: 'Reason (audited)', required: true }}
                body={next === 'archived' ? 'Remove its NovrAgent group mappings and retire or reassign its sources first.' : next === 'suspended' ? 'Its members lose access until it is reactivated.' : 'Its members regain access.'}
                onCancel={() => setNext(null)}
                onConfirm={async (reason) => { const s = next; setNext(null); if (s) await act.run(async () => { const r = await orgApi.setStatus(orgId, o.id, { status: s, reason }); onChange(r); }, 'Status changed.'); }} />
        </>
    );
}
