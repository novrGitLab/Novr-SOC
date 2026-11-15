'use client';

// Executive overview (the landing page). Every figure is an explainable measurement from the API: value, how it was
// computed and the records behind it. A figure without data is shown as unavailable with the reason, never as zero,
// and the posture score is withheld when its measurements cover too little.
import Link from 'next/link';
import { useCallback } from 'react';
import { AlertTriangle, ArrowRight, Gauge, LayoutDashboard } from 'lucide-react';
import { EmptyState, PageHeader, SeverityBadge, btn } from '@/components/features/vms/kit';
import { BarList, ChartCard, Donut, Legend, TimeChart, type Series, type Token } from '@/components/features/vms/charts';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { postureApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { Grid, MeasureTile } from '@/foundation/ui/module';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { SourceBanner } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { PlatformPanel } from './_overview/PlatformPanel';
import { ScoreCard, rows } from './_overview/shared';

const SEV_TOKEN: Record<string, Token> = { critical: '--vz-sev-critical', high: '--vz-sev-high', medium: '--vz-sev-medium', low: '--vz-sev-low', info: '--vz-sev-info' };
const VULN: Series[] = [{ key: 'new', label: 'New findings', token: '--vz-sev-high' }, { key: 'resolved', label: 'Verified fixed', token: '--vz-good' }];
const INC: Series[] = [{ key: 'opened', label: 'Cases opened', token: '--vz-prog-3' }, { key: 'resolved', label: 'Cases resolved', token: '--vz-good' },
    { key: 'critical_high_alerts', label: 'Critical/high alerts', token: '--vz-sev-critical' }];

export default function ExecutiveOverviewPage() {
    const { orgId, session } = useSession();
    const { data, error, reload } = useResource(useCallback(() => postureApi.overview(orgId), [orgId]));
    const wazuh = data?.sources.find((s) => s.connector === 'wazuh_manager');
    return (
        <>
            <PageHeader title="Executive overview" icon={LayoutDashboard}
                description={`Security posture, exposure, coverage, incidents, vulnerabilities and SLA performance of ${session.active_org.name}. Every figure links to its evidence; missing data is shown as unavailable.`}
                actions={<Link href="/app/posture" className={btn('secondary')}><Gauge className="w-3.5 h-3.5" aria-hidden /> Security posture</Link>} />
            {wazuh && wazuh.state === 'local_fixture' && <SourceBanner source={wazuh} what="Endpoint and alert data" />}
            {error ? <ApiErrorState error={error} onRetry={reload} /> : !data ? <LoadingState label="Loading the executive overview" /> : (
                <>
                    <div data-testid="kpis"><Grid cols={4}>{data.kpis.map((m) => <MeasureTile key={m.key} m={m} testid={`kpi-${m.key}`} />)}</Grid></div>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <ScoreCard score={data.score} />
                        <Card className="lg:col-span-2">
                            <SectionTitle title="Actionable priorities" hint="Derived from records: SLA breaches, overdue P1 remediation, KEV findings, approvals" />
                            <div className="mt-3" data-testid="priorities">
                                {data.priorities.length === 0 ? <EmptyState compact title="No priority items" body="Nothing breaches a target or waits for a decision right now." />
                                    : (
                                        <ul className="divide-y divide-border">
                                            {data.priorities.map((p, i) => (
                                                <li key={`${p.kind}-${i}`} className="py-2.5 flex items-start gap-3">
                                                    <AlertTriangle className="w-4 h-4 mt-0.5 text-foreground-muted shrink-0" aria-hidden />
                                                    <div className="flex-1 min-w-0">
                                                        <p className="text-sm font-semibold flex flex-wrap items-center gap-2">{p.title} <SeverityBadge severity={p.severity} /></p>
                                                        {p.detail && <p className="text-xs text-foreground-muted">{p.detail}</p>}
                                                    </div>
                                                    <Link href={p.href} className="text-xs text-purple inline-flex items-center gap-1 shrink-0">Open <ArrowRight className="w-3 h-3" aria-hidden /></Link>
                                                </li>
                                            ))}
                                        </ul>
                                    )}
                            </div>
                        </Card>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                        <ChartCard title="Vulnerability trend" hint="New findings and verified fixes per week (12 weeks)"
                            empty={data.vulnerability_trend.length === 0 ? { title: 'Not available for your role' } : null}>
                            <TimeChart data={rows(data.vulnerability_trend)} series={VULN} kind="bar" stacked={false} label="Vulnerability trend" unit="findings" />
                            <Legend series={VULN} data={rows(data.vulnerability_trend)} />
                        </ChartCard>
                        <ChartCard title="Incident trend" hint="Cases opened and resolved, critical and high alerts per week"
                            empty={data.incident_trend.length === 0 ? { title: 'Not available for your role' } : null}>
                            <TimeChart data={rows(data.incident_trend)} series={INC} kind="line" stacked={false} label="Incident trend" markers />
                            <Legend series={INC} data={rows(data.incident_trend)} />
                        </ChartCard>
                    </div>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <ChartCard title="Open findings by severity" empty={Object.keys(data.findings_by_severity).length === 0 ? { title: 'No open findings recorded' } : null}>
                            <Donut label="Open findings by severity" centerLabel="open" slices={['critical', 'high', 'medium', 'low', 'info'].map((k) => ({
                                key: k, label: k, value: data.findings_by_severity[k] ?? 0, token: SEV_TOKEN[k], href: `/app/vms/findings?severity=${k}` }))} />
                        </ChartCard>
                        <ChartCard title="Assets by criticality" empty={Object.keys(data.assets_by_criticality).length === 0 ? { title: 'No assets in the inventory' } : null}>
                            <BarList label="Assets by criticality" items={['critical', 'high', 'medium', 'low'].map((k) => ({
                                key: k, label: k, value: data.assets_by_criticality[k] ?? 0, token: SEV_TOKEN[k], href: `/app/assets?criticality=${k}` }))} />
                        </ChartCard>
                        <ChartCard title="Remediation tasks by state" empty={Object.keys(data.remediation_by_state).length === 0 ? { title: 'No remediation tasks' } : null}>
                            <BarList label="Remediation tasks by state" items={Object.entries(data.remediation_by_state).map(([k, v]) => ({
                                key: k, label: k.replace(/_/g, ' '), value: v, href: '/app/vms/remediation' }))} />
                        </ChartCard>
                    </div>
                    <Card>
                        <SectionTitle title="Posture measurements" hint="Each one: value, numerator and denominator, formula and weight" />
                        <div className="mt-3"><Grid cols={4}>{data.measures.map((m) => <MeasureTile key={m.key} m={m} />)}</Grid></div>
                    </Card>
                </>
            )}
            <section aria-label="Platform readiness and recent activity" className="space-y-5">
                <h2 className="text-sm font-bold text-foreground-muted uppercase tracking-wider pt-2">Platform readiness and recent activity</h2>
                <PlatformPanel />
            </section>
        </>
    );
}
