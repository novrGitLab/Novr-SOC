'use client';

// CNII monitoring: ONLY explicitly designated assets of the active organization, each under an active authorization
// record, limited to the sectors the user's designation covers (enforced by the API). Monitoring schedules record
// checks honestly: no availability probe is configured, so a due check is `not_run`, never "up". Nothing here discovers
// or scans third-party infrastructure.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { Landmark } from 'lucide-react';
import { KpiCard, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { assetsApi, cniiApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { CniiGate } from './CniiGate';

type Sector = Schemas['CniiMonitoredAssetCreate']['sector'];

export default function CniiMonitoringPage() {
    const { orgId, can } = useSession();
    const ov = useResource(useCallback(() => cniiApi.overview(orgId), [orgId]));
    const assets = useResource(useCallback(() => cniiApi.monitored(orgId), [orgId]));
    const auths = useResource(useCallback(() => cniiApi.authorizations(orgId), [orgId]));
    const inv = useResource(useCallback(() => (can('assets:read') ? assetsApi.list(orgId, { limit: 500 }) : Promise.resolve(null)), [orgId, can]));
    const [f, setF] = useState({ asset: '', auth: '', sector: '' as Sector | '', unit: '', monitoring: 'both' as 'availability' | 'vulnerability' | 'both' });
    const act = useAction();
    const reload = () => { ov.reload(); assets.reload(); };

    async function designate(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => cniiApi.designate(orgId, { asset_id: f.asset, authorization_id: f.auth, sector: f.sector as Sector, owning_unit: f.unit.trim(), monitoring: f.monitoring }),
            'Asset designated for CNII monitoring.')) reload();
    }
    const activeAuths = (auths.data?.items ?? []).filter((a) => a.state === 'active');

    return (
        <>
            <PageHeader title="CNII monitoring" icon={Landmark}
                description="Monitoring of explicitly designated Critical National Information Infrastructure assets only, under a recorded authorization, within your designated sectors. Server-side checks refuse anything outside that scope." />
            {act.notice}
            <CniiGate data={ov.data} error={ov.error} reload={ov.reload}>
                {(o) => (
                    <>
                        <div className="grid grid-cols-2 lg:grid-cols-5 gap-3" data-testid="cnii-kpis">
                            <KpiCard label="Designated assets" value={o.monitored_assets} hint={`${o.suspended_assets} suspended`} />
                            <KpiCard label="Active authorizations" value={o.authorizations_active} hint={`${o.authorizations_expiring_30d} expire within 30 days`} href="/app/cnii/authorizations" />
                            <KpiCard label="Open findings" value={o.open_findings} hint={`${o.critical_findings} critical`} />
                            <KpiCard label="Checks run (30 days)" value={o.availability_checks_30d} hint="not_run checks excluded" />
                            <KpiCard label="Sectors in your designation" text={o.designation_sectors.join(', ')} />
                        </div>
                        <p className="text-xs text-foreground-muted">{o.probe}</p>
                        <Card>
                            <SectionTitle title="Designated assets" />
                            <div className="mt-3"><DataTable testid="cnii-assets" rows={assets.data?.items ?? []} rowKey={(m) => m.id} empty="No asset is designated in your sectors." columns={[
                                { key: 'a', header: 'Asset', render: (m) => <Link className="font-semibold text-purple hover:underline" href={`/app/assets/${m.asset_id}`}>{m.asset_name}<span className="block text-[11px] font-normal text-foreground-muted">{m.owning_unit}</span></Link> },
                                { key: 's', header: 'Sector', render: (m) => <Tag>{m.sector}</Tag> },
                                { key: 'z', header: 'Authorization', render: (m) => <span className="text-xs">{m.authorization_reference} <StateTag state={m.authorization_state} /></span> },
                                { key: 'st', header: 'Monitoring', render: (m) => <span className="text-xs"><StateTag state={m.status} /> {m.monitoring}</span> },
                                { key: 'av', header: 'Availability (30 d)', render: (m) => <span className="text-xs">{m.availability_30d === null || m.availability_30d === undefined ? 'unknown (no check recorded)' : `${Math.round(m.availability_30d * 1000) / 10}%`}
                                    {m.last_check && <span className="block text-foreground-muted">last: {m.last_check.outcome.replace('_', ' ')} {fmt(m.last_check.observed_at)}</span>}</span> },
                                { key: 'f', header: 'Findings', render: (m) => <span className="text-xs">{m.open_findings} ({m.critical_findings} critical)</span> },
                                { key: 'x', header: '', render: (m) => (can('cnii:manage') ? (
                                    <span className="flex flex-col gap-1">
                                        {m.schedules.length === 0 || !m.schedules[0].enabled
                                            ? <button className={btn('secondary')} disabled={act.busy || m.authorization_state !== 'active' || m.status !== 'active'}
                                                onClick={() => void act.run(() => cniiApi.setSchedule(orgId, m.id, { check_kind: 'availability', interval_minutes: 60, enabled: true }), 'Hourly availability schedule enabled.').then(reload)}>Schedule hourly checks</button>
                                            : <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => cniiApi.setSchedule(orgId, m.id, { check_kind: 'availability', interval_minutes: m.schedules[0].interval_minutes, enabled: false }), 'Schedule disabled.').then(reload)}>Disable schedule</button>}
                                        <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => cniiApi.setStatus(orgId, m.id, m.status === 'active' ? 'suspended' : 'active', 'Changed from CNII monitoring'), 'Monitoring status changed.').then(reload)}>{m.status === 'active' ? 'Suspend' : 'Resume'}</button>
                                    </span>) : null) },
                            ]} /></div>
                        </Card>
                        {can('cnii:manage') && (
                            <Card>
                                <SectionTitle title="Designate an asset" hint="The asset must be in the inventory; the authorization must be active and cover the sector" />
                                {activeAuths.length === 0 ? <p className="mt-3 text-xs text-foreground-muted">No active authorization: <Link className="underline" href="/app/cnii/authorizations">record one first</Link>.</p> : (
                                    <form onSubmit={designate} className="mt-3 grid sm:grid-cols-5 gap-2 items-end text-xs">
                                        <Field label="Asset"><select required className={selectCls} value={f.asset} onChange={(e) => setF({ ...f, asset: e.target.value })}>
                                            <option value="">Choose…</option>{(inv.data?.items ?? []).filter((a) => !a.monitoring.cnii_designated).map((a) => <option key={a.id} value={a.id}>{a.display_name}</option>)}</select></Field>
                                        <Field label="Authorization"><select required className={selectCls} value={f.auth} onChange={(e) => setF({ ...f, auth: e.target.value, sector: '' })}>
                                            <option value="">Choose…</option>{activeAuths.map((a) => <option key={a.id} value={a.id}>{a.reference}</option>)}</select></Field>
                                        <Field label="Sector"><select required className={selectCls} value={f.sector} onChange={(e) => setF({ ...f, sector: e.target.value as Sector })}>
                                            <option value="">Choose…</option>{(activeAuths.find((a) => a.id === f.auth)?.sectors ?? []).filter((s) => o.designation_sectors.includes(s)).map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
                                        <Field label="Owning unit"><TextInput required minLength={2} value={f.unit} onChange={(e) => setF({ ...f, unit: e.target.value })} /></Field>
                                        <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Designate</button>
                                    </form>
                                )}
                            </Card>
                        )}
                    </>
                )}
            </CniiGate>
        </>
    );
}
