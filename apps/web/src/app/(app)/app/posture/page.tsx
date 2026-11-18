'use client';

// Security posture: control areas with explainable measurements, configuration compliance (Wazuh SCA, labelled with its
// source), security gaps derived from the organization's real configuration, and the remediation trend.
import Link from 'next/link';
import { useCallback } from 'react';
import { ArrowRight, Gauge } from 'lucide-react';
import { EmptyState, PageHeader, SeverityBadge } from '@/components/features/vms/kit';
import { ChartCard, Legend, TimeChart, type Series } from '@/components/features/vms/charts';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import { postureApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable } from '@/foundation/ui/pilot';
import { Grid, MeasureTile } from '@/foundation/ui/module';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { SourceBanner } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { ScoreCard, rows } from '../_overview/shared';

const REM: Series[] = [{ key: 'opened', label: 'Remediation tasks opened', token: '--vz-sev-high' }, { key: 'closed', label: 'Verified fixed', token: '--vz-good' }];

export default function PosturePage() {
    const { orgId, session } = useSession();
    const { data, error, reload } = useResource(useCallback(() => postureApi.assessment(orgId), [orgId]));
    return (
        <>
            <PageHeader title="Security posture" icon={Gauge}
                description={`Control effectiveness, compliance, exposure, asset coverage, remediation progress and security gaps of ${session.active_org.name}. No score is computed from missing data.`} />
            {error ? <ApiErrorState error={error} onRetry={reload} /> : !data ? <LoadingState label="Loading the posture assessment" /> : (
                <>
                    <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
                        <ScoreCard score={data.score} />
                        <Card className="lg:col-span-2">
                            <SectionTitle title="Security gaps" hint="From the organization's configuration and records" />
                            <div className="mt-3" data-testid="posture-gaps">
                                {data.gaps.length === 0 ? <EmptyState compact title="No gaps detected" body="Every check below has the data it needs." /> : (
                                    <ul className="divide-y divide-border">
                                        {data.gaps.map((g) => (
                                            <li key={g.key} className="py-2.5 flex items-start gap-3">
                                                <SeverityBadge severity={g.severity} />
                                                <div className="flex-1 min-w-0"><p className="text-sm font-semibold">{g.title}</p><p className="text-xs text-foreground-muted">{g.detail}</p></div>
                                                <Link href={g.href} className="text-xs text-purple inline-flex items-center gap-1 shrink-0">Fix <ArrowRight className="w-3 h-3" aria-hidden /></Link>
                                            </li>
                                        ))}
                                    </ul>
                                )}
                            </div>
                        </Card>
                    </div>
                    {data.areas.map((a) => (
                        <Card key={a.key}>
                            <SectionTitle title={a.title} hint={a.description} />
                            <div className="mt-3" data-testid={`area-${a.key}`}><Grid cols={3}>{a.measures.map((m) => <MeasureTile key={m.key} m={m} />)}</Grid></div>
                        </Card>
                    ))}
                    <Card>
                        <SectionTitle title="Configuration compliance (NovrAgent SCA)" hint={`${data.compliance.endpoints_assessed} endpoint(s) assessed`} />
                        <div className="mt-3 space-y-3" data-testid="compliance">
                            {data.compliance.source.state !== 'connected' && <SourceBanner source={data.compliance.source} what="Configuration assessment" />}
                            {data.compliance.note && <p className="text-xs text-foreground-muted">{data.compliance.note}</p>}
                            <DataTable rows={data.compliance.policies} rowKey={(r) => r.policy_id} empty="No configuration assessment results."
                                columns={[{ key: 'n', header: 'Policy', render: (r) => <span className="font-semibold">{r.name}</span> },
                                    { key: 'e', header: 'Endpoints', render: (r) => r.endpoints },
                                    { key: 's', header: 'Average score', render: (r) => (r.average_score === null || r.average_score === undefined ? '—' : `${r.average_score}%`) },
                                    { key: 'p', header: 'Passed checks', render: (r) => r.passed_checks },
                                    { key: 'f', header: 'Failed checks', render: (r) => r.failed_checks }]} />
                        </div>
                    </Card>
                    <ChartCard title="Remediation progress" hint="Tasks opened and verified fixed per week"
                        empty={data.remediation_trend.length === 0 ? { title: 'Not available for your role' } : null}>
                        <TimeChart data={rows(data.remediation_trend)} series={REM} kind="bar" stacked={false} label="Remediation progress" unit="tasks" />
                        <Legend series={REM} data={rows(data.remediation_trend)} />
                    </ChartCard>
                </>
            )}
        </>
    );
}
