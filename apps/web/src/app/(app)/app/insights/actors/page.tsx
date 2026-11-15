'use client';

// Threat actor profiling. Every profile carries an explicit attribution: verified (cited sources required), suspected,
// or unknown. Associations with the organization's indicators, CVEs, cases, alerts and assets are verified or
// suspected, each with a rationale. Nothing is pre-loaded and NovrSOC never names an actor on its own.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { Fingerprint } from 'lucide-react';
import { Drawer, EmptyState, PageHeader, SearchBox, Select, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { intelApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { StateTag, selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Actor = Schemas['ThreatActorView'];
type Attribution = 'verified' | 'suspected' | 'unknown';
const ATTR = [['', 'Any attribution'], ['verified', 'Verified'], ['suspected', 'Suspected'], ['unknown', 'Unknown']] as const;
const LINK_HREF: Record<string, (id: string) => string> = { alert: (id) => `/app/alerts/${id}`, case: (id) => `/app/cases/${id}`,
    asset: (id) => `/app/assets/${id}`, cve: () => '/app/insights/cves', indicator: () => '/app/insights' };
const split = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);

function ActorDrawer({ actor, onClose, onChanged }: { actor: Actor; onClose: () => void; onChanged: (a: Actor) => void }) {
    const { orgId, can } = useSession();
    const [l, setL] = useState({ type: 'alert' as Schemas['ActorLinkCreate']['link_type'], ref: '', assoc: 'suspected' as 'verified' | 'suspected', why: '' });
    const act = useAction();
    async function link(e: FormEvent) {
        e.preventDefault();
        const r = await act.run(() => intelApi.link(orgId, actor.id, { link_type: l.type, ref_id: l.ref.trim(), association: l.assoc, rationale: l.why.trim() }), 'Association recorded.');
        if (r) { onChanged(r); setL({ ...l, ref: '', why: '' }); }
    }
    return (
        <Drawer open onClose={onClose} title={actor.name} subtitle={actor.aliases.length ? `Also known as ${actor.aliases.join(', ')}` : undefined}>
            <div className="space-y-4 text-sm">
                <p className="flex flex-wrap gap-2 items-center"><StateTag state={actor.attribution === 'verified' ? 'verified' : actor.attribution === 'suspected' ? 'suspected' : 'unknown'} label={`attribution ${actor.attribution}`} />
                    <Tag>confidence {actor.confidence}</Tag>{actor.observed_in_organization && <Tag strong>Verified link to this organization</Tag>}</p>
                {actor.description && <p className="whitespace-pre-wrap">{actor.description}</p>}
                <dl className="grid grid-cols-[9rem_1fr] gap-y-1 text-xs">
                    <dt className="text-foreground-muted">Motivations</dt><dd>{actor.motivations.join(', ') || '—'}</dd>
                    <dt className="text-foreground-muted">Targeted sectors (reported)</dt><dd>{actor.target_sectors.join(', ') || '—'}</dd>
                    <dt className="text-foreground-muted">Targeted regions (reported)</dt><dd>{actor.target_regions.join(', ') || '—'}</dd>
                    <dt className="text-foreground-muted">ATT&amp;CK techniques</dt><dd className="flex flex-wrap gap-1">{actor.techniques.length ? actor.techniques.map((t) => <Tag key={t}>{t}</Tag>) : '—'}</dd>
                    <dt className="text-foreground-muted">Active (reported)</dt><dd>{actor.first_seen ?? '?'} – {actor.last_seen ?? '?'}</dd>
                </dl>
                <div><p className="text-xs font-semibold">Sources</p>
                    <ul className="text-xs list-disc ml-5">{actor.sources.length === 0 ? <li className="text-foreground-muted">No cited source (attribution cannot be verified).</li>
                        : actor.sources.map((s, i) => <li key={i}>{s.name}{s.published && ` (${s.published})`}{s.url && <> · <span className="font-mono break-all">{s.url}</span></>}</li>)}</ul></div>
                <div><p className="text-xs font-semibold">Associations with this organization</p>
                    <ul className="text-xs space-y-1">{actor.links.length === 0 ? <li className="text-foreground-muted">None.</li> : actor.links.map((x) => (
                        <li key={x.id}><StateTag state={x.association === 'verified' ? 'verified' : 'suspected'} label={x.association} /> {x.link_type}{' '}
                            {x.exists ? <Link className="underline font-mono" href={LINK_HREF[x.link_type](x.ref_id)}>{x.ref_id.slice(0, 18)}</Link> : <span className="font-mono">{x.ref_id.slice(0, 18)} (no longer visible)</span>}
                            <span className="block text-foreground-muted">{x.rationale} · {x.created_label} · {fmt(x.created_at)}</span></li>))}</ul></div>
                {can('intel:manage') && (
                    <form onSubmit={link} className="grid gap-2 text-xs border-t border-border pt-3">
                        <SectionTitle level={3} title="Add an association" />
                        <div className="grid grid-cols-2 gap-2">
                            <Field label="Record type"><select className={selectCls} value={l.type} onChange={(e) => setL({ ...l, type: e.target.value as typeof l.type })}>
                                {['alert', 'case', 'asset', 'indicator', 'cve'].map((t) => <option key={t}>{t}</option>)}</select></Field>
                            <Field label="Association"><select className={selectCls} value={l.assoc} onChange={(e) => setL({ ...l, assoc: e.target.value as typeof l.assoc })}>
                                <option value="suspected">suspected</option><option value="verified" disabled={actor.attribution !== 'verified'}>verified (verified actors only)</option></select></Field>
                        </div>
                        <Field label="Record id (or CVE id)"><TextInput required value={l.ref} onChange={(e) => setL({ ...l, ref: e.target.value })} /></Field>
                        <Field label="Rationale"><TextInput required minLength={3} value={l.why} onChange={(e) => setL({ ...l, why: e.target.value })} /></Field>
                        <button className={`${btn('primary')} w-fit`} disabled={act.busy}>Record association</button>
                        {act.notice}
                    </form>
                )}
            </div>
        </Drawer>
    );
}

export default function ActorsPage() {
    const { orgId, can } = useSession();
    const [attr, setAttr] = useState<(typeof ATTR)[number][0]>('');
    const [q, setQ] = useState('');
    const list = useResource(useCallback(() => intelApi.actors(orgId, { attribution: attr || undefined, q: q || undefined }), [orgId, attr, q]));
    const [open, setOpen] = useState<Actor | null>(null);
    const [f, setF] = useState({ name: '', aliases: '', attribution: 'unknown' as Attribution, confidence: 0, description: '', sectors: '', regions: '',
        techniques: '', motivations: '', srcName: '', srcUrl: '' });
    const act = useAction();

    async function create(e: FormEvent) {
        e.preventDefault();
        const body: Schemas['ThreatActorCreate'] = {
            name: f.name.trim(), aliases: split(f.aliases), attribution: f.attribution, confidence: f.attribution === 'unknown' ? 0 : f.confidence,
            description: f.description.trim(), target_sectors: split(f.sectors), target_regions: split(f.regions), techniques: split(f.techniques).map((t) => t.toUpperCase()),
            motivations: split(f.motivations), first_seen: null, last_seen: null,
            sources: f.srcName.trim() ? [{ name: f.srcName.trim(), url: f.srcUrl.trim(), published: null }] : [],
        };
        if (await act.run(() => intelApi.createActor(orgId, body), 'Profile recorded.')) { list.reload(); setF({ ...f, name: '', aliases: '', description: '', srcName: '', srcUrl: '' }); }
    }

    return (
        <>
            <PageHeader title="Threat actors" icon={Fingerprint}
                description="Analyst-maintained actor profiles with explicit attribution: verified (cited sources), suspected, or unknown. An actor is tied to this organization only through recorded associations; nothing is inferred." />
            {act.notice}
            <div className="flex flex-wrap gap-2"><Select label="Attribution" options={ATTR} value={attr} onChange={setAttr} /><SearchBox label="Search actors" placeholder="Name, alias or sector" value={q} onSubmit={setQ} /></div>
            <Loaded title="Profiles" data={list.data} error={list.error} reload={list.reload} testid="actors">
                {(d) => d.items.length === 0 ? <EmptyState title="No actor profiles" body="Profiles are recorded by analysts from cited intelligence. NovrSOC ships none and never invents attribution." />
                    : <DataTable rows={d.items} rowKey={(a) => a.id} columns={[
                        { key: 'n', header: 'Actor', render: (a) => <button className="text-left" onClick={() => setOpen(a)}><strong className="text-purple">{a.name}</strong><span className="block text-[11px] text-foreground-muted">{a.aliases.join(', ')}</span></button> },
                        { key: 'a', header: 'Attribution', render: (a) => <StateTag state={a.attribution === 'verified' ? 'verified' : a.attribution === 'suspected' ? 'suspected' : 'unknown'} label={`${a.attribution} · ${a.confidence}`} /> },
                        { key: 's', header: 'Sectors (reported)', render: (a) => <span className="text-xs">{a.target_sectors.join(', ') || '—'}</span> },
                        { key: 'l', header: 'Associations', render: (a) => <span className="text-xs">{a.links.length}{a.observed_in_organization && <Tag strong>verified here</Tag>}</span> },
                        { key: 'src', header: 'Sources', render: (a) => <span className="text-xs">{a.sources.length}</span> },
                    ]} />}
            </Loaded>
            {can('intel:manage') && (
                <Card>
                    <SectionTitle title="Record a profile" hint="Verified needs a cited source; unknown carries confidence 0" />
                    <form onSubmit={create} className="mt-3 grid sm:grid-cols-3 gap-2 items-end text-xs">
                        <Field label="Name"><TextInput required minLength={2} value={f.name} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
                        <Field label="Aliases (comma separated)"><TextInput value={f.aliases} onChange={(e) => setF({ ...f, aliases: e.target.value })} /></Field>
                        <Field label="Attribution"><select className={selectCls} value={f.attribution} onChange={(e) => setF({ ...f, attribution: e.target.value as Attribution })}>
                            <option value="unknown">unknown</option><option value="suspected">suspected</option><option value="verified">verified</option></select></Field>
                        <Field label="Confidence (0-100)"><TextInput type="number" min={0} max={100} disabled={f.attribution === 'unknown'} value={f.confidence} onChange={(e) => setF({ ...f, confidence: Number(e.target.value) })} /></Field>
                        <Field label="Targeted sectors"><TextInput value={f.sectors} onChange={(e) => setF({ ...f, sectors: e.target.value })} /></Field>
                        <Field label="Targeted regions"><TextInput value={f.regions} onChange={(e) => setF({ ...f, regions: e.target.value })} /></Field>
                        <Field label="ATT&CK techniques (T1110, ...)"><TextInput value={f.techniques} onChange={(e) => setF({ ...f, techniques: e.target.value })} /></Field>
                        <Field label="Motivations"><TextInput value={f.motivations} onChange={(e) => setF({ ...f, motivations: e.target.value })} /></Field>
                        <Field label="Source name"><TextInput value={f.srcName} required={f.attribution === 'verified'} onChange={(e) => setF({ ...f, srcName: e.target.value })} /></Field>
                        <Field label="Source URL"><TextInput value={f.srcUrl} onChange={(e) => setF({ ...f, srcUrl: e.target.value })} /></Field>
                        <Field label="Description"><TextInput value={f.description} onChange={(e) => setF({ ...f, description: e.target.value })} /></Field>
                        <button className={`${btn('primary', 'md')} w-fit`} disabled={act.busy}>Record profile</button>
                    </form>
                </Card>
            )}
            {open && <ActorDrawer actor={open} onClose={() => setOpen(null)} onChanged={(a) => { setOpen(a); list.reload(); }} />}
        </>
    );
}
