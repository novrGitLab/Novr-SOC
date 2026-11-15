'use client';

import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Briefcase, ChevronLeft, ChevronRight } from 'lucide-react';
import { EmptyState, PageHeader, Segmented, SeverityBadge, btn } from '@/components/features/vms/kit';
import { Card, StatusPill } from '@/components/features/vms/ui';
import { socApi } from '../alerts/api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { CASE_STATUS_LABEL, STATUS_TONE, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { StateTag } from '@/foundation/ui/module';

const PAGE = 25;
const STATUS_OPTS = [['', 'All'], ['open', 'Open'], ['in_progress', 'In progress'], ['resolved', 'Resolved'], ['closed', 'Closed']] as const;
type StatusF = (typeof STATUS_OPTS)[number][0];

export default function CasesPage() {
    const { orgId, session } = useSession();
    const [status, setStatus] = useState<StatusF>('');
    const [offset, setOffset] = useState(0);
    const { data, error, reload } = useResource(useCallback(() => socApi.cases(orgId, { status, limit: PAGE, offset }), [orgId, status, offset]));

    return (
        <>
            <PageHeader title="Cases" icon={Briefcase} description="Investigations of this organization. A case is created from one or more alerts; every change is recorded in its timeline and the audit trail." />
            <Segmented label="Status" options={STATUS_OPTS} value={status} onChange={(v) => { setStatus(v); setOffset(0); }} />
            {error ? <ApiErrorState error={error} onRetry={() => void reload()} />
                : !data ? <LoadingState label="Loading cases" />
                : data.items.length === 0 ? <Card><EmptyState title="No cases" body={status ? 'No cases have this status.' : 'Create a case from an alert to start an investigation.'}
                    action={<Link href="/app/alerts" className={btn('secondary')}>View alerts</Link>} /></Card>
                : (
                    <Card className="p-0 overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm" data-testid="cases-table">
                                <caption className="sr-only">Cases of {session.active_org.name}</caption>
                                <thead className="bg-card-muted">
                                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                        <th scope="col" className="px-4 py-3 font-semibold">Case</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Severity</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">SLA</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden md:table-cell">Assignee</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden md:table-cell">Alerts</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden lg:table-cell whitespace-nowrap">Updated</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {data.items.map((c) => (
                                        <tr key={c.id} data-case-id={c.id} className="hover:bg-card-muted/60 transition-colors">
                                            <td className="px-4 py-3 min-w-[14rem]"><Link href={`/app/cases/${c.id}`} className="font-semibold text-purple dark:text-[var(--vz-prog-4)] hover:underline">{c.title}</Link>
                                                <span className="block text-[11px] text-foreground-muted font-mono">{c.reference}</span></td>
                                            <td className="px-4 py-3"><SeverityBadge severity={c.severity} /></td>
                                            <td className="px-4 py-3"><StatusPill tone={STATUS_TONE[c.status] ?? 'neutral'} label={CASE_STATUS_LABEL[c.status] ?? c.status} /></td>
                                            <td className="px-4 py-3"><StateTag state={c.sla_state} label={c.sla_state === 'no_policy' ? 'no policy' : undefined} /></td>
                                            <td className="px-4 py-3 text-xs hidden md:table-cell">{c.assignee_label ?? <span className="text-foreground-muted">Unassigned</span>}</td>
                                            <td className="px-4 py-3 tabular-nums hidden md:table-cell">{c.alert_count}</td>
                                            <td className="px-4 py-3 text-xs text-foreground-muted hidden lg:table-cell whitespace-nowrap">{fmtDateTime(c.updated_at)}</td>
                                        </tr>
                                    ))}
                                </tbody>
                            </table>
                        </div>
                        <div className="flex items-center justify-between gap-2 px-4 py-2.5 border-t border-border text-xs text-foreground-muted">
                            <span>{data.offset + 1}–{data.offset + data.items.length} of {data.total}</span>
                            <span className="flex gap-1.5">
                                <button className={btn('secondary')} disabled={offset === 0} onClick={() => setOffset(Math.max(0, offset - PAGE))}><ChevronLeft className="w-3.5 h-3.5" aria-hidden /> Previous</button>
                                <button className={btn('secondary')} disabled={offset + PAGE >= data.total} onClick={() => setOffset(offset + PAGE)}>Next <ChevronRight className="w-3.5 h-3.5" aria-hidden /></button>
                            </span>
                        </div>
                    </Card>
                )}
        </>
    );
}
