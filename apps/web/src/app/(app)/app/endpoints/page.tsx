'use client';

// Endpoint inventory of the active organization: Wazuh agents in the agent groups mapped to it, read by the
// API (the browser never talks to Wazuh). The source state is always shown; an unconfigured connector
// yields no endpoints and says so.
import Link from 'next/link';
import { useCallback } from 'react';
import { Monitor, Unplug } from 'lucide-react';
import { EmptyState, PageHeader, Tag } from '@/components/features/vms/kit';
import { Card, StatusPill } from '@/components/features/vms/ui';
import { endpointsApi } from './api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { AGENT_STATUS, OS_SUPPORT, SourceBanner, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

export default function EndpointsPage() {
    const { orgId, session } = useSession();
    const { data, error, reload } = useResource(useCallback(() => endpointsApi.inventory(orgId), [orgId]));

    return (
        <>
            <PageHeader title="Endpoints" icon={Monitor}
                description="Wazuh agents in the agent groups mapped to this organization. Read through the NovrSOC API; agent health is as last reported by the Wazuh manager." />
            {error ? <ApiErrorState error={error} onRetry={() => void reload()} />
                : !data ? <LoadingState label="Loading endpoints" />
                : (
                    <>
                        <SourceBanner source={data.source} what="Endpoint inventory" />
                        {data.source.state === 'unconfigured' ? (
                            <Card><EmptyState icon={Unplug} title="No Wazuh connection is configured"
                                body="Endpoint inventory appears here once the Wazuh connector is configured for this installation. No endpoint data is shown until then." /></Card>
                        ) : data.mapped_groups === 0 ? (
                            <Card><EmptyState title="No agent groups are mapped to this organization"
                                body="A SOC manager maps Wazuh agent groups to an organization; only agents in mapped groups are shown." /></Card>
                        ) : (
                            <>
                                <div className="flex flex-wrap items-center gap-3 text-xs text-foreground-muted" data-testid="endpoint-counts">
                                    <span><strong className="text-foreground">{data.items.length}</strong> endpoint(s) in {data.mapped_groups} mapped group(s)</span>
                                    {Object.entries(data.by_status).map(([k, n]) => (
                                        <StatusPill key={k} tone={AGENT_STATUS[k]?.tone ?? 'neutral'} label={`${n} ${AGENT_STATUS[k]?.label.toLowerCase() ?? k}`} />
                                    ))}
                                </div>
                                {data.items.length === 0 ? <Card><EmptyState title="No endpoints in the mapped groups" /></Card> : (
                                    <Card className="p-0 overflow-hidden">
                                        <div className="overflow-x-auto">
                                            <table className="w-full text-sm" data-testid="endpoints-table">
                                                <caption className="sr-only">Endpoints of {session.active_org.name}</caption>
                                                <thead className="bg-card-muted">
                                                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                                        <th scope="col" className="px-4 py-3 font-semibold">Endpoint</th>
                                                        <th scope="col" className="px-4 py-3 font-semibold">Agent health</th>
                                                        <th scope="col" className="px-4 py-3 font-semibold">Operating system</th>
                                                        <th scope="col" className="px-4 py-3 font-semibold hidden md:table-cell">Groups</th>
                                                        <th scope="col" className="px-4 py-3 font-semibold hidden lg:table-cell whitespace-nowrap">Last keep-alive</th>
                                                    </tr>
                                                </thead>
                                                <tbody className="divide-y divide-border">
                                                    {data.items.map((e) => (
                                                        <tr key={e.agent_id} data-agent-id={e.agent_id} className="hover:bg-card-muted/60 transition-colors">
                                                            <td className="px-4 py-3">
                                                                <Link href={`/app/endpoints/${e.agent_id}`} className="font-semibold text-purple dark:text-[var(--vz-prog-4)] hover:underline">{e.name}</Link>
                                                                <span className="block text-[11px] text-foreground-muted font-mono">#{e.agent_id}{e.ip ? ` · ${e.ip}` : ''}</span>
                                                            </td>
                                                            <td className="px-4 py-3"><StatusPill tone={AGENT_STATUS[e.status]?.tone ?? 'neutral'} label={AGENT_STATUS[e.status]?.label ?? e.status} /></td>
                                                            <td className="px-4 py-3 text-xs">{[e.os.name, e.os.version].filter(Boolean).join(' ') || '—'}
                                                                <span className="block text-[11px] text-foreground-muted">{OS_SUPPORT[e.os.support]}</span></td>
                                                            <td className="px-4 py-3 hidden md:table-cell"><span className="flex flex-wrap gap-1">{e.groups.map((g) => <Tag key={g}>{g}</Tag>)}</span></td>
                                                            <td className="px-4 py-3 text-xs text-foreground-muted hidden lg:table-cell whitespace-nowrap">{fmtDateTime(e.last_keepalive_at)}</td>
                                                        </tr>
                                                    ))}
                                                </tbody>
                                            </table>
                                        </div>
                                    </Card>
                                )}
                            </>
                        )}
                    </>
                )}
        </>
    );
}
