'use client';

// Stored alerts of the active organization (ingested by the Wazuh forwarder, or the labelled local fixture).
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { Bell, ChevronLeft, ChevronRight } from 'lucide-react';
import { EmptyState, PageHeader, SearchBox, Segmented, Select, SeverityBadge, btn } from '@/components/features/vms/kit';
import { initialParam } from '@/foundation/ui/module';
import { Card, StatusPill } from '@/components/features/vms/ui';
import { socApi } from './api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { ALERT_STATUS_LABEL, FixtureTag, STATUS_TONE, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

const PAGE = 25;
const STATUS_OPTS = [['', 'All'], ['new', 'New'], ['acknowledged', 'Acknowledged'], ['in_progress', 'In progress'], ['closed', 'Closed']] as const;
const SEV_OPTS = [['', 'All severities'], ['critical', 'Critical'], ['high', 'High'], ['medium', 'Medium'], ['low', 'Low']] as const;
type StatusF = (typeof STATUS_OPTS)[number][0];
type SevF = (typeof SEV_OPTS)[number][0];
const ASSIGN_OPTS = [['', 'Anyone'], ['me', 'Assigned to me'], ['unassigned', 'Unassigned']] as const;
type AssignF = (typeof ASSIGN_OPTS)[number][0];

export default function AlertsPage() {
    const { orgId, session } = useSession();
    const [status, setStatus] = useState<StatusF>('');
    const [severity, setSeverity] = useState<SevF>(() => (SEV_OPTS.find(([k]) => k === initialParam('severity'))?.[0] ?? ''));
    const [assigned, setAssigned] = useState<AssignF>('');
    const [q, setQ] = useState('');
    const [offset, setOffset] = useState(0);
    const { data, error, reload } = useResource(useCallback(
        () => socApi.alerts(orgId, { status, severity, limit: PAGE, offset, q, assigned }), [orgId, status, severity, offset, q, assigned]));

    return (
        <>
            <PageHeader title="Alerts" icon={Bell}
                description="Alerts stored for this organization. The organization of each alert is decided from its NovrAgent group; alerts whose group is unmapped are quarantined, never shown to a client." />
            <div className="flex flex-wrap items-center gap-2">
                <Segmented label="Status" options={STATUS_OPTS} value={status} onChange={(v) => { setStatus(v); setOffset(0); }} />
                <Select label="Severity" options={SEV_OPTS} value={severity} onChange={(v) => { setSeverity(v); setOffset(0); }} />
                <Select label="Assignment" options={ASSIGN_OPTS} value={assigned} onChange={(v) => { setAssigned(v); setOffset(0); }} />
                <SearchBox label="Search alerts" placeholder="Rule, agent, rule id or source IP" value={q} onSubmit={(v) => { setQ(v); setOffset(0); }} />
            </div>
            {error ? <ApiErrorState error={error} onRetry={() => void reload()} />
                : !data ? <LoadingState label="Loading alerts" />
                : data.items.length === 0 ? <Card><EmptyState title="No alerts" body={status || severity || q || assigned ? 'No stored alerts match these filters.' : 'No alerts are stored for this organization.'} /></Card>
                : (
                    <Card className="p-0 overflow-hidden">
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm" data-testid="alerts-table">
                                <caption className="sr-only">Alerts of {session.active_org.name}</caption>
                                <thead className="bg-card-muted">
                                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                        <th scope="col" className="px-4 py-3 font-semibold">Severity</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Alert</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden md:table-cell">Endpoint</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden lg:table-cell">Assignee</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden lg:table-cell whitespace-nowrap">Observed</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {data.items.map((a) => (
                                        <tr key={a.id} data-alert-id={a.id} className="hover:bg-card-muted/60 transition-colors">
                                            <td className="px-4 py-3"><SeverityBadge severity={a.severity} /><span className="block text-[11px] text-foreground-muted">Level {a.rule_level}</span></td>
                                            <td className="px-4 py-3 min-w-[14rem]">
                                                <Link href={`/app/alerts/${a.id}`} className="font-semibold text-purple dark:text-[var(--vz-prog-4)] hover:underline">{a.rule_description || `Rule ${a.rule_id}`}</Link>
                                                <span className="flex flex-wrap items-center gap-1.5 mt-0.5 text-[11px] text-foreground-muted">Rule {a.rule_id}{a.source === 'local_fixture' && <FixtureTag />}</span>
                                            </td>
                                            <td className="px-4 py-3 text-xs hidden md:table-cell">{a.agent_name || '—'}<span className="block text-[11px] text-foreground-muted font-mono">#{a.agent_id}</span>
                                                {a.asset_id && <Link href={`/app/assets/${a.asset_id}`} className="block text-[11px] underline text-foreground-muted">Asset</Link>}</td>
                                            <td className="px-4 py-3"><StatusPill tone={STATUS_TONE[a.status] ?? 'neutral'} label={ALERT_STATUS_LABEL[a.status] ?? a.status} />
                                                {a.case_id && <Link href={`/app/cases/${a.case_id}`} className="block text-[11px] underline text-foreground-muted">In a case</Link>}</td>
                                            <td className="px-4 py-3 text-xs hidden lg:table-cell">{a.assignee_label ?? <span className="text-foreground-muted">Unassigned</span>}</td>
                                            <td className="px-4 py-3 text-xs text-foreground-muted hidden lg:table-cell whitespace-nowrap">{fmtDateTime(a.observed_at)}</td>
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
