'use client';

// Platform administration of ONE organization's portal: its address and branding, invitations for its administrators
// and members (the link is shown once), and its provisioned agent group. The API enforces every rule; these panels only
// collect input and show the answer.
import { useCallback, useState, type FormEvent } from 'react';
import { Copy, ImageUp, Trash2 } from 'lucide-react';
import { Tag, btn } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { orgApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

const ROLES: readonly (readonly [Schemas['InvitationCreate']['role'], string])[] = [
    ['soc_manager', 'Organization administrator'], ['analyst', 'Security analyst'], ['executive', 'Executive (read only)'], ['portal_user', 'Portal user']];

export function PortalBrandingPanel({ orgId, orgName }: { orgId: string; orgName: string }) {
    const { orgId: active } = useSession();
    const v = useResource(useCallback(() => orgApi.portal(active, orgId), [active, orgId]));
    return (
        <Loaded title="Portal and branding" hint="One shared NovrSOC deployment; the address only selects this organization's branding and who may sign in there"
            data={v.data} error={v.error} reload={v.reload} testid="org-portal">
            {(d) => <PortalForm key={`${d.portal_subdomain}-${d.logo_sha256}-${d.primary_color}`} d={d} orgId={orgId} orgName={orgName} onSaved={v.setData} />}
        </Loaded>
    );
}

function PortalForm({ d, orgId, orgName, onSaved }: { d: Schemas['OrgPortalView']; orgId: string; orgName: string; onSaved: (v: Schemas['OrgPortalView']) => void }) {
    const { orgId: active } = useSession();
    const act = useAction();
    const [f, setF] = useState({ sub: d.portal_subdomain ?? '', enabled: d.portal_enabled, name: d.display_name === orgName ? '' : d.display_name,
                                 primary: d.primary_color ?? '#4f46e5', secondary: d.secondary_color ?? '#0ea5e9', colors: !!d.primary_color });
    async function save(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => orgApi.setPortal(active, orgId, { portal_subdomain: f.sub.trim().toLowerCase() || null, portal_enabled: f.enabled,
            display_name: f.name.trim(), primary_color: f.colors ? f.primary : null, secondary_color: f.colors ? f.secondary : null }), 'Portal saved.');
        if (r) onSaved(r);
    }
    async function upload(file: File | undefined) {
        if (!file) return;
        const data = await new Promise<string>((ok, no) => { const rd = new FileReader(); rd.onload = () => ok(String(rd.result).split(',', 2)[1] ?? ''); rd.onerror = no; rd.readAsDataURL(file); });
        const r = await act.run(() => orgApi.setLogo(active, orgId, { content_type: file.type as Schemas['LogoUpload']['content_type'], data_base64: data }), 'Logo saved.');
        if (r) onSaved(r);
    }
    return (
        <form onSubmit={save} className="space-y-3" data-testid="portal-form">
            {act.notice}
            <p className="text-xs flex flex-wrap items-center gap-2">
                <StatusPill tone={d.portal_enabled ? 'good' : 'neutral'} label={d.portal_enabled ? 'Portal enabled' : 'Portal off'} />
                {d.url && <a className="underline font-mono" href={d.url} target="_blank" rel="noreferrer">{d.url}</a>}
                {d.warnings.map((w) => <span key={w} className="text-foreground-muted">{w}</span>)}
            </p>
            <div className="flex flex-wrap items-end gap-2">
                <Field label="Subdomain"><TextInput value={f.sub} pattern="[a-z0-9]([a-z0-9-]{0,38}[a-z0-9])?" placeholder="cybernovr" onChange={(e) => setF({ ...f, sub: e.target.value })} /></Field>
                <label className="flex items-center gap-2 text-sm pb-2"><input type="checkbox" checked={f.enabled} onChange={(e) => setF({ ...f, enabled: e.target.checked })} />Portal enabled</label>
                <Field label="Display name"><TextInput value={f.name} maxLength={120} placeholder={orgName} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
            </div>
            <div className="flex flex-wrap items-end gap-3">
                <label className="flex items-center gap-2 text-sm pb-2"><input type="checkbox" checked={f.colors} onChange={(e) => setF({ ...f, colors: e.target.checked })} />Brand colors</label>
                <Field label="Primary"><input type="color" disabled={!f.colors} value={f.primary} onChange={(e) => setF({ ...f, primary: e.target.value })} aria-label="Primary color" /></Field>
                <Field label="Secondary"><input type="color" disabled={!f.colors} value={f.secondary} onChange={(e) => setF({ ...f, secondary: e.target.value })} aria-label="Secondary color" /></Field>
                {f.colors && <span className="text-xs rounded-md px-2 py-1 font-semibold" style={{ background: f.primary, color: d.text_on_primary ?? '#ffffff' }}>Sign in</span>}
            </div>
            <div className="flex flex-wrap items-center gap-2">
                {d.has_logo && <Tag>Logo set</Tag>}
                <label className={btn('secondary')}><ImageUp className="w-3.5 h-3.5" aria-hidden />Upload logo (PNG, JPEG, WebP; 256 KB)
                    <input type="file" accept="image/png,image/jpeg,image/webp" className="sr-only" onChange={(e) => void upload(e.target.files?.[0])} /></label>
                {d.has_logo && <button type="button" className={btn('ghost')} onClick={() => void act.run(() => orgApi.removeLogo(active, orgId), 'Logo removed.').then((r) => { if (r) onSaved(r); })}>
                    <Trash2 className="w-3.5 h-3.5" aria-hidden />Remove logo</button>}
            </div>
            <button className={btn('primary')} type="submit" disabled={act.busy} data-testid="portal-save">Save portal</button>
        </form>
    );
}

export function InvitationsPanel({ orgId }: { orgId: string }) {
    const { orgId: active } = useSession();
    const list = useResource(useCallback(() => orgApi.invitations(active, orgId), [active, orgId]));
    const act = useAction();
    const [f, setF] = useState({ email: '', role: 'soc_manager' as Schemas['InvitationCreate']['role'] });
    const [link, setLink] = useState<string | null>(null);
    async function invite(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => orgApi.invite(active, orgId, { email: f.email.trim(), role: f.role }), 'Invitation created. Send the link below to the person; it is shown only once.');
        if (r) { setLink(r.link); setF({ ...f, email: '' }); list.reload(); }
    }
    return (
        <Loaded title="Invitations" hint="An invited administrator creates their own account on the organization's portal" data={list.data} error={list.error} reload={list.reload} testid="org-invitations">
            {(d) => (
                <>
                    {act.notice}
                    {link && (
                        <div className="flex items-start gap-2 mb-3" data-testid="invite-link">
                            <pre className="flex-1 text-[11px] font-mono whitespace-pre-wrap break-all bg-card-muted border border-border rounded-lg p-2">{link}</pre>
                            <button className={btn('secondary')} onClick={() => void navigator.clipboard?.writeText(link)}><Copy className="w-3.5 h-3.5" aria-hidden />Copy</button>
                        </div>
                    )}
                    <form onSubmit={invite} className="flex flex-wrap items-end gap-2 mb-3">
                        <Field label="Email"><TextInput type="email" required value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} /></Field>
                        <Field label="Role"><select className={selectCls} value={f.role} onChange={(e) => setF({ ...f, role: e.target.value as typeof f.role })}>
                            {ROLES.map(([k, l]) => <option key={k} value={k}>{l}</option>)}</select></Field>
                        <button className={btn('primary')} type="submit" disabled={act.busy}>Invite</button>
                    </form>
                    <DataTable rows={d.items} rowKey={(i) => i.id} empty="No invitation yet." columns={[
                        { key: 'e', header: 'Email', render: (i) => <span>{i.email}<span className="block text-[11px] text-foreground-muted">{ROLES.find(([k]) => k === i.role)?.[1]}</span></span> },
                        { key: 's', header: 'State', render: (i) => <StatusPill tone={i.state === 'accepted' ? 'good' : i.state === 'open' ? 'warning' : 'neutral'} label={i.state} /> },
                        { key: 'w', header: 'Expires', render: (i) => <span className="text-xs">{fmt(i.accepted_at ?? i.expires_at)}</span> },
                        { key: 'x', header: '', render: (i) => (i.state === 'open' ? <button className={btn('ghost')} disabled={act.busy}
                            onClick={() => void act.run(() => orgApi.revokeInvite(active, orgId, i.id), 'Invitation revoked.').then(() => list.reload())}>Revoke</button> : null) },
                    ]} />
                </>
            )}
        </Loaded>
    );
}

export function AgentGroupPanel({ orgId }: { orgId: string }) {
    const { orgId: active } = useSession();
    const g = useResource(useCallback(() => orgApi.agentGroup(active, orgId), [active, orgId]));
    const act = useAction();
    return (
        <Loaded title="Agent group" hint="Generated by NovrSOC: an unguessable name, used by this organization's NovrAgent installers" data={g.data} error={g.error} reload={g.reload} testid="org-agent-group">
            {(d) => (
                <>
                    {act.notice}
                    {d.provisioned ? <p className="text-sm">Provisioned <span className="font-mono">{d.group_name}</span> · {fmt(d.created_at)}
                        <span className="block text-xs text-foreground-muted" data-testid="group-on-manager">
                            {d.on_manager === true ? 'Present on the NovrSIEM manager.' : d.on_manager === false ? `Not on the NovrSIEM manager yet. ${d.manager_detail}` : d.manager_detail}</span></p>
                        : <button className={btn('primary')} disabled={act.busy} data-testid="provision-group"
                            onClick={() => void act.run(() => orgApi.provisionAgentGroup(active, orgId), 'Agent group provisioned.').then((r) => { if (r) g.setData(r); })}>Provision the agent group</button>}
                </>
            )}
        </Loaded>
    );
}
