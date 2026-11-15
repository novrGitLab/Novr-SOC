// Administration, CNII Watch and audit APIs (workstream E / platform).
import { request, type Schemas } from '@/foundation/api/client';
import { fillPath, queryString, type ApiPath } from '@/foundation/api/paths';

const P = {
    orgs: '/api/v1/admin/organizations', users: '/api/v1/admin/users', userStatus: '/api/v1/admin/users/{user_id}/status', userReset: '/api/v1/admin/users/{user_id}/reset-password',
    identities: '/api/v1/admin/service-identities', revoke: '/api/v1/admin/service-identities/{identity_id}/revoke', backups: '/api/v1/admin/backups',
    mine: '/api/v1/cnii/designations/mine', designations: '/api/v1/cnii/designations', revokeDesignation: '/api/v1/cnii/designations/{designation_id}/revoke',
    profiles: '/api/v1/cnii/profiles', overview: '/api/v1/cnii/sector-overview', audit: '/api/v1/audit/events',
} as const satisfies Record<string, ApiPath>;

export const adminApi = {
    orgs: (orgId: string | null) => request<Schemas['AdminOrgList']>(P.orgs, { orgId }),
    createOrg: (orgId: string | null, body: Schemas['AdminOrgCreate']) => request<Schemas['AdminOrg']>(P.orgs, { method: 'POST', orgId, body }),
    users: (orgId: string | null) => request<Schemas['AdminUserList']>(P.users, { orgId }),
    createUser: (orgId: string | null, body: Schemas['AdminUserCreate']) => request<Schemas['AdminUserCreated']>(P.users, { method: 'POST', orgId, body }),
    resetPassword: (orgId: string | null, id: string) =>
        request<Schemas['AdminUserCreated']>(fillPath(P.userReset, { user_id: id }), { method: 'POST', orgId }),
    setStatus: (orgId: string | null, id: string, status: 'active' | 'disabled') =>
        request<Schemas['AdminUser']>(fillPath(P.userStatus, { user_id: id }), { method: 'POST', orgId, body: { status } }),
    identities: (orgId: string | null) => request<Schemas['ServiceIdentityList']>(P.identities, { orgId }),
    issue: (orgId: string | null, body: Schemas['ServiceIdentityCreate']) => request<Schemas['ServiceIdentityIssued']>(P.identities, { method: 'POST', orgId, body }),
    revoke: (orgId: string | null, id: string) => request<Schemas['ServiceIdentityView']>(fillPath(P.revoke, { identity_id: id }), { method: 'POST', orgId }),
    backups: (orgId: string | null) => request<Schemas['BackupRunList']>(P.backups, { orgId }),
    myDesignations: (orgId: string | null) => request<Schemas['CniiDesignationList']>(P.mine, { orgId }),
    designations: (orgId: string | null) => request<Schemas['CniiDesignationList']>(P.designations, { orgId }),
    grant: (orgId: string | null, body: Schemas['CniiDesignationGrant']) => request<Schemas['CniiDesignation']>(P.designations, { method: 'POST', orgId, body }),
    revokeDesignation: (orgId: string | null, id: string, reason: string) =>
        request<Schemas['CniiDesignation']>(fillPath(P.revokeDesignation, { designation_id: id }), { method: 'POST', orgId, body: { designation_id: id, reason } }),
    profiles: (orgId: string | null) => request<Schemas['CniiOrgProfileList']>(P.profiles, { orgId }),
    setProfile: (orgId: string | null, body: Schemas['CniiOrgProfileSet']) => request<Schemas['CniiOrgProfile']>(P.profiles, { method: 'PUT', orgId, body }),
    overview: (orgId: string | null, sector: string) => request<Schemas['CniiSectorOverview']>(`${P.overview}${queryString({ sector })}`, { orgId }),
    audit: (orgId: string | null, limit = 200) => request<Schemas['AuditEventList']>(`${P.audit}${queryString({ limit })}`, { orgId }),
};
