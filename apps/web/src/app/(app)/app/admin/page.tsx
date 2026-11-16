'use client';

// Organization directory (platform administrators): every organization with its status, onboarding progress, assets,
// endpoints, sources and integration health, all computed by the API from real configuration (novrsoc.org_directory()).
// Other roles with access to this page see their own organization's machine identities, as before.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Building2, Plus } from 'lucide-react';
import { Drawer, PageHeader, SearchBox, Select, btn, nf } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { orgApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { adminApi } from './api';
import { IdentitiesPanel } from './_org/IdentitiesPanel';
import { QuarantinePanel } from './_org/QuarantinePanel';
import { HEALTH, ONBOARDING_STEPS, ORG_STATUS, orgHref } from './_org/meta';

const STATUS = [['', 'Any status'], ['active', 'Active'], ['suspended', 'Suspended'], ['archived', 'Archived']] as const;
const HEALTHS = [['', 'Any health'], ['ok', 'Healthy'], ['attention', 'Needs attention'], ['not_configured', 'Not configured'], ['inactive', 'Inactive']] as const;
const EMPTY = { slug: '', name: '', contact_name: '', contact_email: '', timezone: 'Africa/Lagos' };

export default function OrganizationsPage() {
    const { session, orgId, can } = useSession();
    const platformAdmin = session.role === 'super_admin' && can('users:manage');
    const [q, setQ] = useState('');
    const [status, setStatus] = useState<(typeof STATUS)[number][0]>('');
    const [health, setHealth] = useState<(typeof HEALTHS)[number][0]>('');
    const dir = useResource(useCallback(() => (platformAdmin ? orgApi.directory(orgId, { q: q || undefined, status: status || undefined, health: health || undefined })
        : Promise.resolve(null)), [platformAdmin, orgId, q, status, health]));
    const backups = useResource(useCallback(() => (can('backups:read') ? adminApi.backups(orgId) : Promise.resolve({ items: [] })), [orgId, can]));
    const [creating, setCreating] = useState(false);
    const [form, setForm] = useState(EMPTY);
    const act = useAction();

    if (!platformAdmin) {
        return (
            <>
                <PageHeader title="Organizations" icon={Building2} description={`Organization management is for platform administrators. Machine identities of ${session.active_org.name}:`} />
                {can('service_identities:manage') && <IdentitiesPanel orgId={orgId} orgName={session.active_org.name} canManage />}
            </>
        );
    }
    return (
        <>
            <PageHeader title="Organizations" icon={Building2}
                description="Every client and the platform organization, with onboarding, assets, telemetry and integration health from their real configuration. Open one to manage it."
                actions={<button className={btn('primary')} data-testid="new-org" onClick={() => { setForm(EMPTY); setCreating(true); }}><Plus className="w-3.5 h-3.5" aria-hidden />New organization</button>} />
            {act.notice}
            <div className="flex flex-wrap items-end gap-2">
                <SearchBox value={q} onSubmit={setQ} placeholder="Name, slug or contact e-mail" label="Search organizations" />
                <Select value={status} onChange={setStatus} options={STATUS} label="Status" />
                <Select value={health} onChange={setHealth} options={HEALTHS} label="Integration health" />
            </div>
            <Loaded title="Directory" data={dir.data} error={dir.error} reload={dir.reload} testid="org-directory"
                hint={dir.data ? `${dir.data.total} organization(s) · generated ${fmt(dir.data.generated_at)}` : undefined}>
                {(d) => d && <DataTable rows={d.items} rowKey={(o) => o.id} testid="admin-orgs" empty="No organization matches." columns={[
                    { key: 'n', header: 'Organization', render: (o) => <Link href={orgHref(o.id)} className="font-semibold hover:text-purple" data-testid="org-link">{o.name}
                        <span className="block text-[11px] font-mono font-normal text-foreground-muted">{o.slug}{o.kind === 'platform' ? ' · platform' : ''}</span></Link> },
                    { key: 's', header: 'Status', render: (o) => <StatusPill tone={ORG_STATUS[o.status].tone} label={ORG_STATUS[o.status].label} /> },
                    { key: 'o', header: 'Onboarding', render: (o) => <Onboarding done={o.onboarding_completed} total={o.onboarding_total} next={o.next_step} href={o.next_step ? orgHref(o.id, ONBOARDING_STEPS[o.next_step]?.tab) : undefined} /> },
                    { key: 'a', header: 'Assets', className: 'hidden md:table-cell', render: (o) => <span className="tabular-nums">{nf.format(o.assets)}<span className="block text-[11px] text-foreground-muted">{o.integrations.wazuh_agents} Wazuh agent(s)</span></span> },
                    { key: 't', header: 'Telemetry', className: 'hidden lg:table-cell', render: (o) => <span className="text-xs">{o.integrations.wazuh_groups} group(s) · {o.integrations.log_sources} source(s)
                        <span className="block text-[11px] text-foreground-muted">{o.integrations.log_sources_receiving} receiving · last event {fmt(o.integrations.last_alert_at)}</span></span> },
                    { key: 'h', header: 'Integrations', render: (o) => <span title={o.integrations.notes.join('\n')}><StatusPill tone={HEALTH[o.integrations.health].tone} label={HEALTH[o.integrations.health].label} /></span> },
                    { key: 'u', header: 'Users', className: 'hidden md:table-cell', render: (o) => <span className="tabular-nums">{o.users}</span> },
                ]} />}
            </Loaded>
            <QuarantinePanel />
            {can('backups:read') && (
                <Loaded title="Platform backups" hint="Encrypted logical dumps and restore drills" data={backups.data} error={backups.error}>
                    {(d) => <DataTable rows={d.items} rowKey={(b) => b.id} testid="admin-backups" empty="No backup has run in this installation." columns={[
                        { key: 'w', header: 'Started', render: (b) => <span className="text-xs">{fmt(b.started_at)}</span> },
                        { key: 's', header: 'Status', render: (b) => <StatusPill tone={b.status === 'succeeded' ? 'good' : b.status === 'failed' ? 'critical' : 'neutral'} label={b.status} /> },
                        { key: 'd', header: 'Restore drill', render: (b) => b.last_drill_status ? <span className="text-xs">{b.last_drill_status} · {fmt(b.last_drill_at)}</span> : <span className="text-xs text-foreground-muted">never drilled</span> },
                    ]} />}
                </Loaded>
            )}
            <Drawer open={creating} onClose={() => setCreating(false)} title="New client organization" subtitle="The slug is permanent; everything else can be edited later.">
                <div className="grid sm:grid-cols-2 gap-3">
                    <Field label="Name"><TextInput value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} /></Field>
                    <Field label="Slug (a-z, 0-9, -)"><TextInput value={form.slug} pattern="[a-z0-9][a-z0-9-]{1,62}" onChange={(e) => setForm({ ...form, slug: e.target.value.toLowerCase() })} /></Field>
                    <Field label="Contact name"><TextInput value={form.contact_name} onChange={(e) => setForm({ ...form, contact_name: e.target.value })} /></Field>
                    <Field label="Contact e-mail"><TextInput type="email" value={form.contact_email} onChange={(e) => setForm({ ...form, contact_email: e.target.value })} /></Field>
                    <Field label="Time zone"><TextInput value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} /></Field>
                </div>
                <button className={btn('primary', 'md')} disabled={act.busy || !form.name.trim() || !/^[a-z0-9][a-z0-9-]{1,62}$/.test(form.slug)}
                    onClick={() => void act.run(async () => { const o = await orgApi.create(orgId, { ...form, name: form.name.trim() }); setCreating(false); dir.reload(); return o; },
                        (o) => `Organization ${o.name} created. Open it to continue onboarding.`)}>Create</button>
                {act.notice}
            </Drawer>
        </>
    );
}

function Onboarding({ done, total, next, href }: { done: number; total: number; next?: string | null; href?: string }) {
    const pct = total ? Math.round((done / total) * 100) : 0;
    return (
        <span className="block min-w-32">
            <span className="flex items-center gap-2 text-xs tabular-nums"><span className="h-1.5 flex-1 rounded-full bg-card-muted overflow-hidden" aria-hidden>
                <span className="block h-full rounded-full bg-purple" style={{ width: `${pct}%` }} /></span>{done}/{total}</span>
            {next && href ? <Link href={href} className="block text-[11px] text-foreground-muted hover:text-purple underline">Next: {ONBOARDING_STEPS[next]?.label ?? next}</Link>
                : <span className="block text-[11px] text-foreground-muted">Complete</span>}
        </span>
    );
}
