// SOC API (workstream A module): stored alerts, triage and cases. Used by the alerts and cases pages.
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, queryString, type ApiPath } from '@/foundation/api/paths';

export type AlertDetail = Schemas['AlertDetail'];
export type CaseDetail = Schemas['CaseDetail'];
export type AlertStatus = AlertDetail['status'];
export type CaseStatus = CaseDetail['status'];

const P = {
    alerts: '/api/v1/soc/alerts',
    alert: '/api/v1/soc/alerts/{alert_id}',
    alertStatus: '/api/v1/soc/alerts/{alert_id}/status',
    evidence: '/api/v1/soc/alerts/{alert_id}/evidence',
    cases: '/api/v1/soc/cases',
    caseOne: '/api/v1/soc/cases/{case_id}',
    caseNotes: '/api/v1/soc/cases/{case_id}/notes',
    caseStatus: '/api/v1/soc/cases/{case_id}/status',
} as const satisfies Record<string, ApiPath>;

export const socApi = {
    alerts: (orgId: string | null, f: { status?: string; severity?: string; limit?: number; offset?: number; q?: string; assigned?: string; asset_id?: string } = {}) =>
        request<Schemas['AlertList']>(`${P.alerts}${queryString(f)}`, { orgId }),
    alert: (orgId: string | null, id: string) => request<AlertDetail>(fillPath(P.alert, { alert_id: id }), { orgId }),
    evidence: (orgId: string | null, id: string) => request<Schemas['AlertEvidence']>(fillPath(P.evidence, { alert_id: id }), { orgId }),
    setAlertStatus: (orgId: string | null, id: string, status: AlertStatus, reason = '') =>
        request<AlertDetail>(fillPath(P.alertStatus, { alert_id: id }), { method: 'POST', orgId, body: { status, reason } satisfies Schemas['AlertStatusUpdate'] }),
    /** Promotes one alert to a case. Dedupe key (source "alert", the alert id): a repeat returns the same case. */
    caseFromAlert: (orgId: string | null, alert: AlertDetail) =>
        request<Schemas['CasePromotionResult']>(P.cases, {
            method: 'POST', orgId, body: {
                alert_ids: [alert.id], title: (alert.rule_description || `Alert ${alert.rule_id}`).slice(0, 200).padEnd(3, '.'),
                severity: alert.severity, source: 'alert', source_id: alert.id, summary: '',
            } satisfies Schemas['AlertToCasePromotion'],
        }),
    cases: (orgId: string | null, f: { status?: string; limit?: number; offset?: number } = {}) =>
        request<Schemas['CaseList']>(`${P.cases}${queryString(f)}`, { orgId }),
    caseDetail: (orgId: string | null, id: string) => request<CaseDetail>(fillPath(P.caseOne, { case_id: id }), { orgId }),
    addNote: (orgId: string | null, id: string, body: string, kind: Schemas['CaseNoteCreate']['kind'] = 'note') =>
        request<CaseDetail>(fillPath(P.caseNotes, { case_id: id }), { method: 'POST', orgId, body: { body, kind } satisfies Schemas['CaseNoteCreate'] }),
    assignCase: (orgId: string | null, id: string, assigneeId: string | null, note = '') =>
        request<CaseDetail>(`/api/v1/soc/cases/${encodeURIComponent(id)}/assign`, { method: 'POST', orgId, body: { assignee_id: assigneeId, note } satisfies Schemas['AssignmentRequest'] }),
    assignAlert: (orgId: string | null, id: string, assigneeId: string | null) =>
        request<AlertDetail>(`/api/v1/soc/alerts/${encodeURIComponent(id)}/assign`, { method: 'POST', orgId, body: { assignee_id: assigneeId, note: '' } satisfies Schemas['AssignmentRequest'] }),
    setCaseStatus: (orgId: string | null, id: string, status: CaseStatus, note = '') =>
        request<CaseDetail>(fillPath(P.caseStatus, { case_id: id }), { method: 'POST', orgId, body: { status, note } satisfies Schemas['CaseStatusUpdate'] }),
};
