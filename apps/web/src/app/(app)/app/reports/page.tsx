'use client';

// Platform-wide reporting centre: every report type reads the organization's actual records for the period, and each
// section states whether its source was available. History can be filtered by type; previews are printable.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { useRouter } from 'next/navigation';
import { FileBarChart } from 'lucide-react';
import { EmptyState, Notice, PageHeader, Select, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { newIdempotencyKey } from '@/foundation/api/paths';
import { reportsApi } from './api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { REPORT_LABEL, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

const PERIODS = [['7', 'Last 7 days'], ['30', 'Last 30 days'], ['90', 'Last 90 days'], ['365', 'Last 12 months']] as const;
type ReportTypeKey = 'organization_summary' | 'executive' | 'secops' | 'vms_executive' | 'vms_technical' | 'threat_intel' | 'brand_protection'
    | 'email_security' | 'cnii_sector' | 'compliance_sca' | 'sla' | 'audit' | 'soc_monthly';
const TYPES: readonly (readonly [ReportTypeKey, string])[] = [['executive', 'Executive'], ['secops', 'SECOPS'], ['vms_executive', 'VMS (executive)'],
    ['vms_technical', 'VMS (technical)'], ['threat_intel', 'Threat intelligence'], ['brand_protection', 'Brand protection'],
    ['email_security', 'Email security'], ['cnii_sector', 'CNII (designated sectors)'], ['compliance_sca', 'Compliance (NovrAgent SCA)'],
    ['sla', 'SLA performance'], ['audit', 'Audit'], ['organization_summary', 'Organization summary']] as const;
const TYPE_LABEL: Record<string, string> = { ...Object.fromEntries(TYPES), soc_monthly: 'SOC monthly' };
const FORMATS = [['json', 'JSON'], ['csv', 'CSV']] as const;

export default function ReportsPage() {
    const router = useRouter();
    const { orgId, can, session } = useSession();
    const { data, error, reload } = useResource(useCallback(() => reportsApi.list(orgId), [orgId]));
    const [days, setDays] = useState<(typeof PERIODS)[number][0]>('30');
    const [format, setFormat] = useState<'json' | 'csv'>('json');
    const [type, setType] = useState<ReportTypeKey>('executive');
    const [filter, setFilter] = useState<'all' | ReportTypeKey>('all');
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true); setMsg(null);
        try {
            const r = await reportsApi.requestSummary(orgId, Number(days), format, newIdempotencyKey('report'), type);
            router.push(`/app/reports/${r.id}`);
        } catch (err) {
            setMsg({ ok: false, text: (err instanceof ApiError && err.message) || STATE_TEXT[uiState(err)].body });
            setBusy(false);
        }
    }

    return (
        <>
            <PageHeader title="Reports" icon={FileBarChart}
                description="Reports generated from the data NovrSOC holds for this organization. Each section states whether its source was available; nothing is estimated." />
            {can('reports:manage') && (
                <Card>
                    <SectionTitle title="Generate a report" hint="Every type reads actual records; unavailable sources are listed as such" />
                    <form onSubmit={submit} className="mt-3 flex flex-wrap items-end gap-3" data-testid="report-form">
                        <Select label="Report" options={TYPES} value={type} onChange={setType} />
                        <Select label="Period" options={PERIODS} value={days} onChange={setDays} />
                        <Select label="Format" options={FORMATS} value={format} onChange={setFormat} />
                        <button type="submit" className={btn('primary', 'md')} disabled={busy} data-testid="report-submit">Generate report</button>
                    </form>
                    <p className="mt-3 text-[11px] text-foreground-muted">Downloads are JSON or CSV with a verified SHA-256; open a report to preview and print it (Save as PDF from the browser).</p>
                    <div className="mt-2"><Notice msg={msg} /></div>
                </Card>
            )}
            {error ? <ApiErrorState error={error} onRetry={() => void reload()} />
                : !data ? <LoadingState label="Loading reports" />
                : data.items.length === 0 ? <Card><EmptyState title="No reports yet" body={`No reports have been generated for ${session.active_org.name}.`} /></Card>
                : (
                    <Card className="p-0 overflow-hidden">
                        <div className="p-3 border-b border-border"><Select label="Show" options={[['all', 'All types'] as const, ...TYPES]} value={filter} onChange={setFilter} /></div>
                        <div className="overflow-x-auto">
                            <table className="w-full text-sm" data-testid="reports-table">
                                <caption className="sr-only">Reports of {session.active_org.name}</caption>
                                <thead className="bg-card-muted">
                                    <tr className="text-left text-[11px] uppercase tracking-wider text-foreground-muted">
                                        <th scope="col" className="px-4 py-3 font-semibold">Report</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Period</th>
                                        <th scope="col" className="px-4 py-3 font-semibold">Status</th>
                                        <th scope="col" className="px-4 py-3 font-semibold hidden md:table-cell whitespace-nowrap">Requested</th>
                                    </tr>
                                </thead>
                                <tbody className="divide-y divide-border">
                                    {data.items.filter((r) => filter === 'all' || r.type === filter).map((r) => (
                                        <tr key={r.id} data-report-id={r.id} className="hover:bg-card-muted/60 transition-colors">
                                            <td className="px-4 py-3"><Link href={`/app/reports/${r.id}`} className="font-semibold text-purple dark:text-[var(--vz-prog-4)] hover:underline">{REPORT_LABEL[r.type] ?? TYPE_LABEL[r.type] ?? r.type}</Link>
                                                <span className="block text-[11px] text-foreground-muted uppercase">{r.format}</span></td>
                                            <td className="px-4 py-3 text-xs">{new Date(r.period_start).toLocaleDateString('en-GB')} – {new Date(r.period_end).toLocaleDateString('en-GB')}</td>
                                            <td className="px-4 py-3"><StatusPill tone={r.status === 'ready' ? 'good' : r.status === 'failed' ? 'critical' : 'neutral'} label={r.status} /></td>
                                            <td className="px-4 py-3 text-xs text-foreground-muted hidden md:table-cell whitespace-nowrap">{fmtDateTime(r.created_at)}</td>
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
