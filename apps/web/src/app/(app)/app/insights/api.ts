// Threat Insights and NHAI APIs (workstream F).
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, queryString, type ApiPath } from '@/foundation/api/paths';

export type NhaiJob = Schemas['NhaiJob'];
const P = {
    indicators: '/api/v1/insights/indicators', context: '/api/v1/insights/indicators/{indicator_id}/context', match: '/api/v1/insights/match',
    matches: '/api/v1/insights/matches', verdict: '/api/v1/insights/matches/{match_id}/verdict', correlations: '/api/v1/insights/correlations',
    bundles: '/api/v1/insights/stix/bundles', feedRuns: '/api/v1/insights/feed-runs',
    explain: '/api/v1/nhai/alert-explanations', jobs: '/api/v1/nhai/jobs', job: '/api/v1/nhai/jobs/{job_id}', review: '/api/v1/nhai/jobs/{job_id}/review',
    readiness: '/api/v1/nhai/readiness', overview: '/api/v1/nhai/overview', posture: '/api/v1/nhai/posture-analyses',
    retry: '/api/v1/nhai/jobs/{job_id}/retry',
} as const satisfies Record<string, ApiPath>;

export const insightsApi = {
    indicators: (orgId: string | null) => request<Schemas['IndicatorList']>(P.indicators, { orgId }),
    context: (orgId: string | null, id: string) => request<Schemas['IndicatorContext']>(fillPath(P.context, { indicator_id: id }), { orgId }),
    runMatch: (orgId: string | null, hours: number) => request<Schemas['MatchRunResult']>(`${P.match}${queryString({ hours })}`, { method: 'POST', orgId }),
    matches: (orgId: string | null, alertId?: string) => request<Schemas['InsightMatchList']>(`${P.matches}${queryString({ alert_id: alertId })}`, { orgId }),
    verdict: (orgId: string | null, id: string, verdict: Schemas['InsightFeedback']['verdict'], note: string) =>
        request<Schemas['InsightMatchList']>(fillPath(P.verdict, { match_id: id }), { method: 'POST', orgId, body: { match_id: id, verdict, note } }),
    correlations: (orgId: string | null, hours: number) => request<Schemas['CorrelationList']>(`${P.correlations}${queryString({ hours })}`, { orgId }),
    uploadBundle: (orgId: string | null, source: string, bundle: Record<string, unknown>) =>
        request<Schemas['StixIngestResult']>(P.bundles, { method: 'POST', orgId, body: { source, collection: '', bundle } }),
    feedRuns: (orgId: string | null) => request<Schemas['FeedRunList']>(P.feedRuns, { orgId }),
};

export const nhaiApi = {
    explain: (orgId: string | null, alertId: string) => request<NhaiJob>(P.explain, { method: 'POST', orgId, body: { alert_id: alertId } }),
    jobs: (orgId: string | null, subjectId?: string) => request<Schemas['NhaiJobList']>(`${P.jobs}${queryString({ subject_id: subjectId })}`, { orgId }),
    job: (orgId: string | null, id: string) => request<NhaiJob>(fillPath(P.job, { job_id: id }), { orgId }),
    review: (orgId: string | null, id: string, decision: Schemas['NhaiReviewRequest']['decision'], note: string) =>
        request<NhaiJob>(fillPath(P.review, { job_id: id }), { method: 'POST', orgId, body: { decision, note } }),
    readiness: (orgId: string | null) => request<Schemas['NhaiReadiness']>(P.readiness, { orgId }),
    overview: (orgId: string | null) => request<Schemas['NhaiOverview']>(P.overview, { orgId }),
    analyse: (orgId: string | null, scope: 'organization' | 'platform', windowDays: number) =>
        request<NhaiJob>(P.posture, { method: 'POST', orgId, body: { scope, window_days: windowDays } satisfies Schemas['PostureAnalysisRequest'] }),
    retry: (orgId: string | null, id: string) => request<NhaiJob>(fillPath(P.retry, { job_id: id }), { method: 'POST', orgId }),
};
