// Platform-owned API calls used by the shell and the dashboard: service status and the audit trail.
import { request, type Schemas } from './client';
import { queryString, type ApiPath } from './paths';

export type PlatformStatus = Schemas['PlatformStatus'];
export type ConnectorState = Schemas['ConnectorState'];
export type AuditEvent = Schemas['AuditEvent'];

const P = {
    status: '/api/v1/platform/status',
    audit: '/api/v1/audit/events',
} as const satisfies Record<string, ApiPath>;

export const platformApi = {
    status: (orgId: string | null) => request<PlatformStatus>(P.status, { orgId }),
    recentAudit: (orgId: string | null, limit = 8) => request<Schemas['AuditEventList']>(`${P.audit}${queryString({ limit })}`, { orgId }),
};
