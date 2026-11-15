'use client';

// Billing: plan catalogue and organization subscriptions as administrative records, with usage against plan limits.
// No payment provider is configured: NovrSOC takes no payments and issues no invoices, and says so.
import { useCallback, useState, type FormEvent } from 'react';
import { CreditCard } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { adminxApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Status = 'trial' | 'active' | 'past_due' | 'cancelled';
const money = (minor: number, cur: string) => new Intl.NumberFormat('en-NG', { style: 'currency', currency: cur }).format(minor / 100);

export default function BillingPage() {
    const { orgId } = useSession();
    const b = useResource(useCallback(() => adminxApi.billing(orgId), [orgId]));
    const [p, setP] = useState({ code: '', name: '', price: 0, currency: 'NGN', interval: 'monthly' as 'monthly' | 'annual', assets: '', users: '' });
    const [sub, setSub] = useState<Record<string, { plan: string; status: Status }>>({});
    const act = useAction();

    async function addPlan(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => adminxApi.createPlan(orgId, { code: p.code.trim(), name: p.name.trim(), description: '', price_minor: Math.round(p.price * 100), currency: p.currency,
            billing_interval: p.interval, max_assets: p.assets ? Number(p.assets) : null, max_users: p.users ? Number(p.users) : null, features: [] }), 'Plan created.')) b.reload();
    }

    return (
        <>
            <PageHeader title="Billing" icon={CreditCard} description="Plans and subscriptions per client organization, and usage against plan limits." />
            {act.notice}
            <Loaded title="Subscriptions" hint={b.data?.note} data={b.data} error={b.error} reload={b.reload} testid="billing">
                {(d) => (
                    <>
                        <p className="mb-3 text-xs"><StateTag state="unconfigured" label="payment provider: not configured" /></p>
                        <DataTable rows={d.organizations} rowKey={(o) => o.org_id} empty="No client organizations." columns={[
                            { key: 'o', header: 'Organization', render: (o) => <strong>{o.org_name}</strong> },
                            { key: 'p', header: 'Plan', render: (o) => (o.plan_name ? <span>{o.plan_name} <Tag>{o.plan_code}</Tag></span> : <span className="text-xs text-foreground-muted">none</span>) },
                            { key: 's', header: 'Status', render: (o) => (o.status ? <StateTag state={o.status === 'active' ? 'active' : o.status === 'past_due' ? 'at_risk' : 'draft'} label={o.status.replace('_', ' ')} /> : '—') },
                            { key: 'u', header: 'Usage', render: (o) => <span className="text-xs">{o.assets}{o.max_assets ? `/${o.max_assets}` : ''} assets · {o.users}{o.max_users ? `/${o.max_users}` : ''} users
                                {o.over_limit.length > 0 && <strong className="block text-red">over limit: {o.over_limit.join(', ')}</strong>}</span> },
                            { key: 'r', header: 'Renews', render: (o) => <span className="text-xs">{fmt(o.renews_at)}</span> },
                            { key: 'x', header: 'Set plan', render: (o) => (
                                <span className="flex gap-1 items-center">
                                    <select className={selectCls} aria-label="Plan" value={sub[o.org_id]?.plan ?? ''} onChange={(e) => setSub({ ...sub, [o.org_id]: { plan: e.target.value, status: sub[o.org_id]?.status ?? 'active' } })}>
                                        <option value="">Plan…</option>{d.plans.filter((x) => x.active).map((x) => <option key={x.id} value={x.id}>{x.name}</option>)}</select>
                                    <select className={selectCls} aria-label="Status" value={sub[o.org_id]?.status ?? 'active'} onChange={(e) => setSub({ ...sub, [o.org_id]: { plan: sub[o.org_id]?.plan ?? '', status: e.target.value as Status } })}>
                                        {['trial', 'active', 'past_due', 'cancelled'].map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}</select>
                                    <button className={btn('secondary')} disabled={act.busy || !sub[o.org_id]?.plan} onClick={() => void act.run(() => adminxApi.setSubscription(orgId, {
                                        org_id: o.org_id, plan_id: sub[o.org_id].plan, status: sub[o.org_id].status, renews_at: null, notes: '' }), 'Subscription recorded.').then(() => b.reload())}>Save</button>
                                </span>) },
                        ]} />
                    </>
                )}
            </Loaded>
            <Loaded title="Plans" data={b.data} error={b.error}>
                {(d) => <DataTable rows={d.plans} rowKey={(x) => x.id} empty="No plans defined. NovrSOC ships none." columns={[
                    { key: 'n', header: 'Plan', render: (x) => <span><strong>{x.name}</strong> <Tag>{x.code}</Tag></span> },
                    { key: 'p', header: 'Price', render: (x) => `${money(x.price_minor, x.currency)} / ${x.billing_interval === 'monthly' ? 'month' : 'year'}` },
                    { key: 'l', header: 'Limits', render: (x) => <span className="text-xs">{x.max_assets ?? '∞'} assets · {x.max_users ?? '∞'} users</span> },
                    { key: 'a', header: '', render: (x) => <button className={btn('ghost')} disabled={act.busy} onClick={() => void act.run(() => adminxApi.setPlanActive(orgId, x.id, !x.active), x.active ? 'Plan retired.' : 'Plan reactivated.').then(() => b.reload())}>{x.active ? 'Retire' : 'Reactivate'}</button> },
                ]} />}
            </Loaded>
            <Card>
                <SectionTitle title="Create a plan" />
                <form onSubmit={addPlan} className="mt-3 grid sm:grid-cols-4 gap-2 items-end text-xs">
                    <Field label="Code (a-z, 0-9, -)"><TextInput required pattern="[a-z0-9][a-z0-9-]{1,39}" value={p.code} onChange={(e) => setP({ ...p, code: e.target.value })} /></Field>
                    <Field label="Name"><TextInput required minLength={2} value={p.name} onChange={(e) => setP({ ...p, name: e.target.value })} /></Field>
                    <Field label="Price (major units)"><TextInput type="number" min={0} step="0.01" value={p.price} onChange={(e) => setP({ ...p, price: Number(e.target.value) })} /></Field>
                    <Field label="Currency"><TextInput required pattern="[A-Z]{3}" value={p.currency} onChange={(e) => setP({ ...p, currency: e.target.value.toUpperCase() })} /></Field>
                    <Field label="Interval"><select className={selectCls} value={p.interval} onChange={(e) => setP({ ...p, interval: e.target.value as typeof p.interval })}><option value="monthly">monthly</option><option value="annual">annual</option></select></Field>
                    <Field label="Max assets"><TextInput type="number" min={1} value={p.assets} onChange={(e) => setP({ ...p, assets: e.target.value })} /></Field>
                    <Field label="Max users"><TextInput type="number" min={1} value={p.users} onChange={(e) => setP({ ...p, users: e.target.value })} /></Field>
                    <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Create plan</button>
                </form>
            </Card>
        </>
    );
}
