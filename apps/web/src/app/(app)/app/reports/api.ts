// Reports API (workstream E module): organization-scoped requests, history, detail and verified download.
import { request, type Schemas } from '@/foundation/api/client';
import { ApiError, apiErrorFromResponse } from '@/foundation/api/errors';
import { fillPath, type ApiPath } from '@/foundation/api/paths';

export type ReportDetail = Schemas['ReportDetail'];

const P = {
    reports: '/api/v1/reports',
    report: '/api/v1/reports/{report_id}',
    reportDownload: '/api/v1/reports/{report_id}/download',
} as const satisfies Record<string, ApiPath>;

export const reportsApi = {
    list: (orgId: string | null) => request<Schemas['ReportList']>(P.reports, { orgId }),
    detail: (orgId: string | null, id: string) => request<ReportDetail>(fillPath(P.report, { report_id: id }), { orgId }),
    requestSummary: (orgId: string | null, days: number, format: 'json' | 'csv', idempotencyKey: string,
                     type: Schemas['ReportRequest']['type'] = 'organization_summary') => {
        const end = new Date();
        const start = new Date(end.getTime() - days * 86_400_000);
        return request<ReportDetail>(P.reports, {
            method: 'POST', orgId, body: {
                idempotency_key: idempotencyKey, type, format,
                period_start: start.toISOString(), period_end: end.toISOString(),
            } satisfies Schemas['ReportRequest'],
        });
    },
    /** Fetches the stored artifact (the API re-verifies its SHA-256) and returns it with its file name.
     *  A fetch, not a link: the active organization travels in the X-Org-Id header. */
    download: async (orgId: string | null, id: string): Promise<{ filename: string; type: string; text: string }> => {
        const headers: Record<string, string> = {};
        if (orgId) headers['X-Org-Id'] = orgId;
        let res: Response;
        try {
            res = await fetch(fillPath(P.reportDownload, { report_id: id }), { headers, credentials: 'same-origin', cache: 'no-store' });
        } catch {
            throw new ApiError(0, 'backend_unreachable', 'The NovrSOC service could not be reached.');
        }
        if (!res.ok) throw await apiErrorFromResponse(res);
        const disp = res.headers.get('content-disposition') ?? '';
        const filename = /filename="([^"]+)"/.exec(disp)?.[1] ?? `report-${id}`;
        return { filename, type: res.headers.get('content-type') ?? 'application/octet-stream', text: await res.text() };
    },
};
