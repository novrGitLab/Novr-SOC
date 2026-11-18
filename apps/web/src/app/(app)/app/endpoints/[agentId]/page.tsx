'use client';

import Link from 'next/link';
import { useCallback } from 'react';
import { useParams } from 'next/navigation';
import { ArrowLeft, Monitor } from 'lucide-react';
import { KpiCard, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { endpointsApi } from '../api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { AGENT_STATUS, OS_SUPPORT, SourceBanner, SourcePill, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

export default function EndpointDetailPage() {
    const { agentId } = useParams<{ agentId: string }>();
    const { orgId } = useSession();
    const { data, error } = useResource(useCallback(() => endpointsApi.detail(orgId, agentId), [orgId, agentId]));
    const e = data?.endpoint;
    const v = data?.vulnerabilities;
    const vulnReason = v ? `Vulnerability source: ${v.source.state.replace('_', ' ')}` : '';

    return (
        <>
            <PageHeader title={e?.name ?? 'Endpoint'} icon={Monitor}
                actions={<Link href="/app/endpoints" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> All endpoints</Link>} />
            {error ? <div data-testid="endpoint-error"><ApiErrorState error={error} /></div>
                : !data || !e || !v ? <LoadingState label="Loading endpoint" />
                : (
                    <>
                        <SourceBanner source={data.source} what="Endpoint data" />
                        <div className="grid gap-5 lg:grid-cols-2">
                            <Card>
                                <SectionTitle title="Agent" />
                                <dl className="mt-3 grid grid-cols-[9rem_1fr] gap-y-2 text-sm" data-testid="endpoint-detail">
                                    <dt className="text-foreground-muted">Agent id</dt><dd className="font-mono text-xs">{e.agent_id}</dd>
                                    <dt className="text-foreground-muted">Health</dt><dd><StatusPill tone={AGENT_STATUS[e.status]?.tone ?? 'neutral'} label={AGENT_STATUS[e.status]?.label ?? e.status} /></dd>
                                    <dt className="text-foreground-muted">Last keep-alive</dt><dd>{fmtDateTime(e.last_keepalive_at)}</dd>
                                    <dt className="text-foreground-muted">Agent version</dt><dd>{e.agent_version ?? '—'}</dd>
                                    <dt className="text-foreground-muted">IP address</dt><dd className="font-mono text-xs">{e.ip ?? '—'}</dd>
                                    <dt className="text-foreground-muted">Groups</dt><dd className="flex flex-wrap gap-1">{e.groups.map((g) => <Tag key={g}>{g}</Tag>)}</dd>
                                </dl>
                            </Card>
                            <Card>
                                <SectionTitle title="Operating system" />
                                <dl className="mt-3 grid grid-cols-[9rem_1fr] gap-y-2 text-sm" data-testid="endpoint-os">
                                    <dt className="text-foreground-muted">Name</dt><dd>{e.os.name ?? '—'}</dd>
                                    <dt className="text-foreground-muted">Version</dt><dd>{e.os.version ?? '—'}</dd>
                                    <dt className="text-foreground-muted">Platform</dt><dd className="font-mono text-xs">{e.os.platform ?? '—'}</dd>
                                    <dt className="text-foreground-muted">NovrSOC support</dt><dd>{OS_SUPPORT[e.os.support]}</dd>
                                </dl>
                            </Card>
                        </div>

                        <section aria-label="Vulnerability summary">
                            <div className="flex items-center gap-2 mb-2"><h2 className="text-sm font-bold text-foreground">Vulnerabilities</h2><SourcePill state={v.source.state} /></div>
                            <div className="grid grid-cols-2 md:grid-cols-5 gap-3" data-testid="endpoint-vulns">
                                <KpiCard label="Critical" value={v.critical ?? null} reason={vulnReason} />
                                <KpiCard label="High" value={v.high ?? null} reason={vulnReason} />
                                <KpiCard label="Medium" value={v.medium ?? null} reason={vulnReason} />
                                <KpiCard label="Low" value={v.low ?? null} reason={vulnReason} />
                                <KpiCard label="Total" value={v.total ?? null} reason={vulnReason} />
                            </div>
                        </section>

                        <Card>
                            <SectionTitle title="Configuration assessment (SCA)" hint="NovrAgent security configuration assessment policies for this agent" action={<SourcePill state={data.sca.source.state} />} />
                            {data.sca.policies.length === 0 ? <p className="mt-3 text-xs text-foreground-muted">No SCA results are available for this endpoint.</p> : (
                                <div className="overflow-x-auto mt-3">
                                    <table className="w-full text-sm" data-testid="endpoint-sca">
                                        <thead><tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                            <th scope="col" className="py-2 pr-4 font-semibold">Policy</th>
                                            <th scope="col" className="py-2 pr-4 font-semibold">Score</th>
                                            <th scope="col" className="py-2 pr-4 font-semibold">Passed</th>
                                            <th scope="col" className="py-2 pr-4 font-semibold">Failed</th>
                                            <th scope="col" className="py-2 pr-4 font-semibold hidden sm:table-cell">Not applicable</th>
                                            <th scope="col" className="py-2 font-semibold hidden md:table-cell">Scanned</th>
                                        </tr></thead>
                                        <tbody className="divide-y divide-border">
                                            {data.sca.policies.map((p) => (
                                                <tr key={p.policy_id}>
                                                    <td className="py-2 pr-4">{p.name}<span className="block text-[11px] text-foreground-muted font-mono">{p.policy_id}</span></td>
                                                    <td className="py-2 pr-4 font-bold tabular-nums">{p.score_percent}%</td>
                                                    <td className="py-2 pr-4 tabular-nums">{p.passed}</td>
                                                    <td className="py-2 pr-4 tabular-nums">{p.failed}</td>
                                                    <td className="py-2 pr-4 tabular-nums hidden sm:table-cell">{p.not_applicable}</td>
                                                    <td className="py-2 text-xs text-foreground-muted hidden md:table-cell">{fmtDateTime(p.scanned_at)}</td>
                                                </tr>
                                            ))}
                                        </tbody>
                                    </table>
                                </div>
                            )}
                        </Card>
                    </>
                )}
        </>
    );
}
