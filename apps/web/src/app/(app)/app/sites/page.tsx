'use client';

// Phase 2 integration example: Web -> FastAPI -> PostgreSQL -> Web, scoped to the active organization.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { MapPin, Plus } from 'lucide-react';
import { EmptyState, Notice, PageHeader, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { api, type Site } from '@/foundation/api/client';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { useResource } from '@/foundation/ui/useResource';

export default function SitesPage() {
    const { orgId, can, session } = useSession();
    const { data, error, reload } = useResource(useCallback(() => api.listSites(orgId), [orgId]));
    const sites: Site[] | null = data ? data.items : null;
    const [name, setName] = useState('');
    const [cidrs, setCidrs] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);

    async function create(e: FormEvent) {
        e.preventDefault();
        setBusy(true); setMsg(null);
        try {
            const site = await api.createSite(orgId, {
                name: name.trim(), description: '',
                network_cidrs: cidrs.split(',').map((c) => c.trim()).filter(Boolean),
            });
            setMsg({ ok: true, text: `Created ${site.name}.` });
            setName(''); setCidrs('');
            reload();
        } catch (err) {
            const s = uiState(err);
            setMsg({ ok: false, text: s === 'validation' ? 'Check the name and network ranges (CIDR, comma separated).' : (err instanceof ApiError && err.message) || STATE_TEXT[s].body });
        } finally { setBusy(false); }
    }

    return (
        <>
            <PageHeader title="Sites" icon={MapPin}
                description="Locations of an organization. Collectors and scan targets are bound to a site, so the same private address at two sites is two different hosts." />
            {can('sites:manage') && (
                <Card>
                    <SectionTitle title="Add a site" />
                    <form onSubmit={create} className="mt-3 grid gap-3 sm:flex sm:flex-wrap sm:items-end" data-testid="site-form">
                        <label className="text-xs text-foreground-muted flex flex-col gap-1">Name
                            <input required maxLength={120} value={name} onChange={(e) => setName(e.target.value)} data-testid="site-name"
                                className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-purple/40" />
                        </label>
                        <label className="text-xs text-foreground-muted flex flex-col gap-1">Networks (optional)
                            <input value={cidrs} onChange={(e) => setCidrs(e.target.value)} placeholder="10.0.0.0/24, 192.168.1.0/24" data-testid="site-cidrs"
                                className="bg-card border border-border rounded-lg px-2.5 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-purple/40" />
                        </label>
                        <button type="submit" disabled={busy || !name.trim()} className={btn('primary', 'md')} data-testid="site-submit"><Plus className="w-4 h-4" aria-hidden /> Add site</button>
                    </form>
                    <div className="mt-3"><Notice msg={msg} /></div>
                </Card>
            )}
            {error ? <ApiErrorState error={error} onRetry={reload} />
                : sites === null ? <LoadingState label="Loading sites" />
                : sites.length === 0 ? <Card><EmptyState title="No sites yet" body={`${session.active_org.name} has no sites recorded.`} /></Card>
                : (
                    <Card className="p-0 overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm" data-testid="sites-table">
                                <caption className="sr-only">Sites of {session.active_org.name}</caption>
                                <thead className="bg-card-muted">
                                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                        <th scope="col" className="px-5 py-3 font-semibold">Name</th>
                                        <th scope="col" className="px-5 py-3 font-semibold">Networks</th>
                                        <th scope="col" className="px-5 py-3 font-semibold whitespace-nowrap">Created</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {sites.map((s) => (
                                        <tr key={s.id} className="hover:bg-card-muted/60 transition-colors" data-site-id={s.id}>
                                            <td className="px-5 py-3 font-semibold"><Link className="text-purple dark:text-[var(--vz-prog-4)] hover:underline" href={`/app/sites/${s.id}`}>{s.name}</Link></td>
                                            <td className="px-5 py-3 text-xs text-foreground-muted font-mono">{s.network_cidrs.join(', ') || '—'}</td>
                                            <td className="px-5 py-3 text-xs text-foreground-muted whitespace-nowrap">{new Date(s.created_at).toLocaleString('en-GB')}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                    </Card>
                )}
        </>
    );
}
