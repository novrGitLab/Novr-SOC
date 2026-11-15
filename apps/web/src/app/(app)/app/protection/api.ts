// Email Security and Brand Protection API (workstream D).
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, type ApiPath } from '@/foundation/api/paths';

const P = {
    domains: '/api/v1/protection/email/domains', dmarc: '/api/v1/protection/email/dmarc-reports',
    subjects: '/api/v1/protection/brand/subjects', run: '/api/v1/protection/brand/subjects/{subject_id}/runs',
    runs: '/api/v1/protection/brand/runs', findings: '/api/v1/protection/brand/findings', triage: '/api/v1/protection/brand/findings/{finding_id}/triage',
} as const satisfies Record<string, ApiPath>;

export const protectionApi = {
    domains: (orgId: string | null) => request<Schemas['EmailDomainList']>(P.domains, { orgId }),
    addDomain: (orgId: string | null, domain: string) => request<Schemas['EmailDomain']>(P.domains, { method: 'POST', orgId, body: { domain } }),
    dmarc: (orgId: string | null) => request<Schemas['DmarcReportList']>(P.dmarc, { orgId }),
    uploadDmarc: (orgId: string | null, xml: string) => request<Schemas['DmarcReportView']>(P.dmarc, { method: 'POST', orgId, body: { xml, source: 'upload' } }),
    subjects: (orgId: string | null) => request<Schemas['WatchSubjectList']>(P.subjects, { orgId }),
    addSubject: (orgId: string | null, body: Schemas['WatchSubjectCreate']) => request<Schemas['WatchSubject']>(P.subjects, { method: 'POST', orgId, body }),
    runMonitoring: (orgId: string | null, id: string) => request<Schemas['MonitoringRun']>(fillPath(P.run, { subject_id: id }), { method: 'POST', orgId }),
    runs: (orgId: string | null) => request<Schemas['MonitoringRunList']>(P.runs, { orgId }),
    findings: (orgId: string | null) => request<Schemas['BrandFindingList']>(P.findings, { orgId }),
    triage: (orgId: string | null, id: string, status: Schemas['BrandFindingTriage']['status']) =>
        request<Schemas['BrandFindingView']>(fillPath(P.triage, { finding_id: id }), { method: 'POST', orgId, body: { status, note: '' } }),
};
