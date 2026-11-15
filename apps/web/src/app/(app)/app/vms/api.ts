// Vulnerability management API (workstream B).
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, queryString, type ApiPath } from '@/foundation/api/paths';

export type Finding = Schemas['VmsFindingView'];
const P = {
    status: '/api/v1/vms/status', scopes: '/api/v1/vms/scopes', scans: '/api/v1/vms/scans', findings: '/api/v1/vms/findings',
    transition: '/api/v1/vms/findings/{finding_id}/transition', report: '/api/v1/vms/report',
} as const satisfies Record<string, ApiPath>;

export const vmsApi = {
    status: (orgId: string | null) => request<Schemas['VmsStatus']>(P.status, { orgId }),
    scopes: (orgId: string | null) => request<Schemas['VmsScopeList']>(P.scopes, { orgId }),
    addScope: (orgId: string | null, body: Schemas['VmsScopeCreate']) => request<Schemas['VmsScopeView']>(P.scopes, { method: 'POST', orgId, body }),
    scans: (orgId: string | null) => request<Schemas['VmsScanList']>(P.scans, { orgId }),
    requestScan: (orgId: string | null, body: Schemas['VmsScanCreate']) => request<Schemas['VmsScanView']>(P.scans, { method: 'POST', orgId, body }),
    findings: (orgId: string | null, status?: string) => request<Schemas['VmsFindingList']>(`${P.findings}${queryString({ status })}`, { orgId }),
    transition: (orgId: string | null, id: string, to: Schemas['FindingTransition']['to_status'], reason: string) =>
        request<Finding>(fillPath(P.transition, { finding_id: id }), { method: 'POST', orgId, body: { finding_id: id, to_status: to, reason } }),
    report: (orgId: string | null) => request<Schemas['VmsReport']>(P.report, { orgId }),
};
