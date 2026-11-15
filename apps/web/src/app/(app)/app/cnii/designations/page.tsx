'use client';

import { useCallback, useState } from 'react';
import { Landmark } from 'lucide-react';
import { Notice, PageHeader, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { adminApi } from '../../admin/api';

const SECTORS = ['power', 'water', 'ict', 'finance', 'health', 'publicadmin', 'education', 'defence', 'transport', 'food', 'safety', 'industrial', 'mines'] as const;
type Overview = Awaited<ReturnType<typeof adminApi.overview>>;

export default function CniiPage() {
    const { orgId, can } = useSession();
    const mine = useResource(useCallback(() => adminApi.myDesignations(orgId), [orgId]));
    const all = useResource(useCallback(() => (can('users:manage') ? adminApi.designations(orgId) : Promise.resolve({ items: [] })), [orgId, can]));
    const [sector, setSector] = useState<string>('');
    const [ov, setOv] = useState<Overview | null>(null);
    const [grant, setGrant] = useState({ user: '', sectors: 'power', reason: '', days: 30 });
    const [msg, setMsg] = useState<Msg>(null);
    async function view(s: string) {
        setSector(s); setOv(null); setMsg(null);
        try { setOv(await adminApi.overview(orgId, s)); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    async function doGrant() {
        setMsg(null);
        try {
            await adminApi.grant(orgId, { user_id: grant.user.trim(), sectors: grant.sectors.split(',').map((x) => x.trim()) as never, reason: grant.reason,
                scope_org_ids: null, expires_at: new Date(Date.now() + grant.days * 86_400_000).toISOString() });
            setMsg({ ok: true, text: 'Designation granted (expires automatically).' }); all.reload();
        } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <>
            <PageHeader title="CNII designations and sectors" icon={Landmark} description="Critical National Information Infrastructure. A permission is never enough: every sector view also needs an explicit, expiring designation. Views show aggregate counts only, and every access (granted or denied) is audited." />
            <Notice msg={msg} />
            <Loaded title="My designations" data={mine.data} error={mine.error} testid="cnii-mine">
                {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">You hold no CNII designation. Sector views will be refused.</p> : (
                    <ul className="text-sm space-y-1">{d.items.map((x) => (
                        <li key={x.id}>{x.sectors.map((s) => <Tag key={s}>{s}</Tag>)} expires {fmt(x.expires_at)} {x.revoked_at && <StatusPill tone="critical" label="revoked" />}</li>))}</ul>)}
            </Loaded>
            <Card>
                <SectionTitle title="Sector overview" />
                <div className="mt-3 flex flex-wrap gap-1">{SECTORS.map((s) => <button key={s} className={btn(s === sector ? 'primary' : 'secondary')} onClick={() => void view(s)}>{s}</button>)}</div>
                {ov && (
                    <div className="mt-3" data-testid="cnii-overview">
                        <p className="text-xs text-foreground-muted">Designation valid until {fmt(ov.designation_expires_at)}</p>
                        <DataTable rows={ov.items} rowKey={(r) => r.org_id} empty="No organization in this sector is covered by your designation." columns={[
                            { key: 'o', header: 'Organization', render: (r) => r.org_name },
                            { key: 'c', header: 'Criticality', render: (r) => <Tag>{r.criticality}</Tag> },
                            { key: 'a', header: 'Open alerts', render: (r) => r.open_alerts },
                            { key: 'k', header: 'Critical (7 d)', render: (r) => r.critical_alerts_7d },
                            { key: 'x', header: 'Open cases', render: (r) => r.open_cases },
                        ]} />
                    </div>
                )}
            </Card>
            {can('users:manage') && (
                <Loaded title="Designations (platform administrators)" data={all.data} error={all.error}>
                    {(d) => (
                        <>
                            <DataTable rows={d.items} rowKey={(x) => x.id} empty="No designations." columns={[
                                { key: 'u', header: 'User', render: (x) => <span className="font-mono text-[11px]">{x.user_id}</span> },
                                { key: 's', header: 'Sectors', render: (x) => x.sectors.join(', ') },
                                { key: 'e', header: 'Expires', render: (x) => <span className="text-xs">{fmt(x.expires_at)}{x.revoked_at ? ' (revoked)' : ''}</span> },
                                { key: 'r', header: '', render: (x) => !x.revoked_at ? <button className={btn('ghost')} onClick={() => void adminApi.revokeDesignation(orgId, x.id, 'Revoked from CNII Watch').then(() => all.reload())}>Revoke</button> : null },
                            ]} />
                            <div className="mt-3 flex flex-wrap items-end gap-2">
                                <Field label="User id"><TextInput value={grant.user} onChange={(e) => setGrant({ ...grant, user: e.target.value })} /></Field>
                                <Field label="Sectors (comma)"><TextInput value={grant.sectors} onChange={(e) => setGrant({ ...grant, sectors: e.target.value })} /></Field>
                                <Field label="Reason"><TextInput value={grant.reason} onChange={(e) => setGrant({ ...grant, reason: e.target.value })} /></Field>
                                <Field label="Days"><input type="number" min={1} max={365} className={inputCls} value={grant.days} onChange={(e) => setGrant({ ...grant, days: Number(e.target.value) })} /></Field>
                                <button className={btn('primary')} disabled={grant.reason.trim().length < 3 || !grant.user} onClick={() => void doGrant()}>Grant</button>
                            </div>
                        </>
                    )}
                </Loaded>
            )}
        </>
    );
}
