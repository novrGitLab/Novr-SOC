// Typed clients for the consolidated modules. Every path is checked against the generated OpenAPI (`satisfies`),
// so API drift breaks `npm run typecheck`. The API enforces every permission; the UI only reflects the answer.
import { request, type Schemas } from './client';
import { fillPath, queryString, type ApiPath } from './paths';

type O = string | null;
const get = <T,>(path: string, orgId: O) => request<T>(path, { orgId });
const post = <T,>(path: string, orgId: O, body: unknown = {}) => request<T>(path, { method: 'POST', orgId, body });
const put = <T,>(path: string, orgId: O, body: unknown) => request<T>(path, { method: 'PUT', orgId, body });
const patch = <T,>(path: string, orgId: O, body: unknown) => request<T>(path, { method: 'PATCH', orgId, body });
const del = <T,>(path: string, orgId: O) => request<T>(path, { method: 'DELETE', orgId });

const P = {
    posture: '/api/v1/posture/overview', assessment: '/api/v1/posture/assessment',
    assets: '/api/v1/assets', asset: '/api/v1/assets/{asset_id}', merge: '/api/v1/assets/{asset_id}/merge', retire: '/api/v1/assets/{asset_id}/retire',
    syncWazuh: '/api/v1/assets/sync/wazuh', syncRuns: '/api/v1/assets/sync-runs', conflicts: '/api/v1/assets/conflicts',
    collectors: '/api/v1/assets/collectors', collector: '/api/v1/assets/collectors/{collector_id}', collectorRun: '/api/v1/assets/collectors/{collector_id}/run',
    slaPolicies: '/api/v1/secops/sla/policies', slaStatus: '/api/v1/secops/sla/status', slaPerf: '/api/v1/secops/sla/performance',
    slaEscalate: '/api/v1/secops/sla/escalate', handoverDraft: '/api/v1/secops/handovers/draft', handovers: '/api/v1/secops/handovers',
    handoverAck: '/api/v1/secops/handovers/{handover_id}/acknowledge', notifications: '/api/v1/secops/notifications',
    notificationsRead: '/api/v1/secops/notifications/read',
    playbooks: '/api/v1/soar/playbooks', versions: '/api/v1/soar/playbooks/{name}/versions', validate: '/api/v1/soar/playbooks/{playbook_id}/validate',
    submit: '/api/v1/soar/playbooks/{playbook_id}/submit', review: '/api/v1/soar/playbooks/{playbook_id}/review',
    retirePb: '/api/v1/soar/playbooks/{playbook_id}/retire', operations: '/api/v1/soar/operations', aiActivity: '/api/v1/soar/ai-activity',
    estop: '/api/v1/soar/emergency-stop',
    findings: '/api/v1/vms/findings', finding: '/api/v1/vms/findings/{finding_id}', transition: '/api/v1/vms/findings/{finding_id}/transition',
    retest: '/api/v1/vms/findings/{finding_id}/retest', remediation: '/api/v1/vms/remediation', task: '/api/v1/vms/remediation/{task_id}',
    risk: '/api/v1/vms/risk', services: '/api/v1/vms/services', vmsAudit: '/api/v1/vms/audit', schedules: '/api/v1/vms/schedules',
    schedule: '/api/v1/vms/schedules/{schedule_id}', vmsReport: '/api/v1/vms/report', vmsStatus: '/api/v1/vms/status', scopes: '/api/v1/vms/scopes',
    scans: '/api/v1/vms/scans',
    actors: '/api/v1/insights/actors', actor: '/api/v1/insights/actors/{actor_id}', actorLinks: '/api/v1/insights/actors/{actor_id}/links',
    cves: '/api/v1/insights/cves', cveImport: '/api/v1/insights/cves/import', cveStix: '/api/v1/insights/cves/import-stix',
    snapshots: '/api/v1/insights/snapshots',
    findingExplain: '/api/v1/nhai/finding-explanations', assetSummary: '/api/v1/nhai/asset-summaries',
    cniiOverview: '/api/v1/cnii/overview', cniiAuth: '/api/v1/cnii/authorizations', cniiRevoke: '/api/v1/cnii/authorizations/{authorization_id}/revoke',
    cniiAssets: '/api/v1/cnii/monitored-assets', cniiStatus: '/api/v1/cnii/monitored-assets/{monitored_id}/status',
    cniiSchedule: '/api/v1/cnii/monitored-assets/{monitored_id}/schedule', cniiChecks: '/api/v1/cnii/monitored-assets/{monitored_id}/checks',
    plans: '/api/v1/continuity/plans', planTested: '/api/v1/continuity/plans/{plan_id}/tested', requests: '/api/v1/continuity/requests',
    requestOne: '/api/v1/continuity/requests/{request_id}', decision: '/api/v1/continuity/requests/{request_id}/decision',
    progress: '/api/v1/continuity/requests/{request_id}/progress', verify: '/api/v1/continuity/requests/{request_id}/verify',
    contOverview: '/api/v1/continuity/overview',
    convs: '/api/v1/chat/conversations', conv: '/api/v1/chat/conversations/{conversation_id}', ask: '/api/v1/chat/conversations/{conversation_id}/messages',
    billing: '/api/v1/admin/billing', plansAdmin: '/api/v1/admin/billing/plans', planAdmin: '/api/v1/admin/billing/plans/{plan_id}',
    subs: '/api/v1/admin/billing/subscriptions', exports: '/api/v1/admin/exports', exportRevoke: '/api/v1/admin/exports/{export_id}/revoke',
    teams: '/api/v1/admin/teams', teamMembers: '/api/v1/admin/teams/{team_id}/members', teamMember: '/api/v1/admin/teams/{team_id}/members/{user_id}',
    memberships: '/api/v1/admin/users/{user_id}/memberships', membership: '/api/v1/admin/users/{user_id}/memberships/{org_id}',
    analytics: '/api/v1/admin/analytics', health: '/api/v1/admin/health', quarantine: '/api/v1/admin/wazuh/quarantine', onboarding: '/api/v1/admin/onboarding',
    audit: '/api/v1/audit/events', mappings: '/api/v1/endpoints/group-mappings', mapping: '/api/v1/endpoints/group-mappings/{mapping_id}',
} as const satisfies Record<string, ApiPath>;

export const exportDownloadPath = (id: string) => `/api/v1/admin/exports/${encodeURIComponent(id)}/download`;

export const postureApi = {
    overview: (o: O) => get<Schemas['ExecutiveOverview']>(P.posture, o),
    assessment: (o: O) => get<Schemas['PostureAssessment']>(P.assessment, o),
};

export const assetsApi = {
    list: (o: O, q: Record<string, string | number | undefined>) => get<Schemas['AssetList']>(P.assets + queryString(q), o),
    get: (o: O, id: string) => get<Schemas['AssetDetail']>(fillPath(P.asset, { asset_id: id }), o),
    create: (o: O, body: Schemas['AssetCreate']) => post<Schemas['AssetSummary']>(P.assets, o, body),
    update: (o: O, id: string, body: Schemas['AssetUpdate']) => patch<Schemas['AssetSummary']>(fillPath(P.asset, { asset_id: id }), o, body),
    merge: (o: O, id: string, body: Schemas['AssetMerge']) => post<Schemas['AssetSummary']>(fillPath(P.merge, { asset_id: id }), o, body),
    retire: (o: O, id: string, reason: string) => post<Schemas['AssetSummary']>(fillPath(P.retire, { asset_id: id }), o, { reason }),
    syncWazuh: (o: O) => post<Schemas['SyncRunView']>(P.syncWazuh, o),
    syncRuns: (o: O) => get<Schemas['SyncRunList']>(P.syncRuns, o),
    conflicts: (o: O) => get<Schemas['ConflictList']>(P.conflicts, o),
    collectors: (o: O) => get<Schemas['CollectorList']>(P.collectors, o),
    createCollector: (o: O, body: Schemas['CollectorCreate']) => post<Schemas['CollectorView']>(P.collectors, o, body),
    updateCollector: (o: O, id: string, body: Schemas['CollectorUpdate']) => patch<Schemas['CollectorView']>(fillPath(P.collector, { collector_id: id }), o, body),
    deleteCollector: (o: O, id: string) => del<void>(fillPath(P.collector, { collector_id: id }), o),
    runCollector: (o: O, id: string) => post<Schemas['SyncRunView']>(fillPath(P.collectorRun, { collector_id: id }), o),
    summarize: (o: O, id: string) => post<Schemas['NhaiJob']>(P.assetSummary, o, { asset_id: id }),
};

export const secopsApi = {
    policies: (o: O) => get<Schemas['SlaPolicyList']>(P.slaPolicies, o),
    setPolicies: (o: O, body: Schemas['SlaPolicySet']) => put<Schemas['SlaPolicyList']>(P.slaPolicies, o, body),
    status: (o: O) => get<Schemas['SlaStatus']>(P.slaStatus, o),
    performance: (o: O, days: number) => get<Schemas['SlaPerformance']>(P.slaPerf + queryString({ days }), o),
    escalate: (o: O) => post<Schemas['EscalationResult']>(P.slaEscalate, o),
    draft: (o: O) => get<Schemas['HandoverDraft']>(P.handoverDraft, o),
    handovers: (o: O) => get<Schemas['HandoverList']>(P.handovers, o),
    submit: (o: O, body: Schemas['HandoverCreate']) => post<Schemas['HandoverView']>(P.handovers, o, body),
    acknowledge: (o: O, id: string, note: string) => post<Schemas['HandoverView']>(fillPath(P.handoverAck, { handover_id: id }), o, { note }),
    notifications: (o: O) => get<Schemas['NotificationList']>(P.notifications, o),
    markRead: (o: O) => post<Schemas['NotificationList']>(P.notificationsRead, o),
};

export const playbookApi = {
    list: (o: O) => get<Schemas['PlaybookList']>(P.playbooks, o),
    versions: (o: O, name: string) => get<Schemas['PlaybookVersionList']>(fillPath(P.versions, { name }), o),
    create: (o: O, body: Schemas['PlaybookCreate']) => post<Schemas['PlaybookView']>(P.playbooks, o, body),
    validate: (o: O, id: string) => post<Schemas['PlaybookView']>(fillPath(P.validate, { playbook_id: id }), o),
    submit: (o: O, id: string) => post<Schemas['PlaybookView']>(fillPath(P.submit, { playbook_id: id }), o),
    review: (o: O, id: string, body: Schemas['PlaybookReview']) => post<Schemas['PlaybookView']>(fillPath(P.review, { playbook_id: id }), o, body),
    retire: (o: O, id: string) => post<Schemas['PlaybookView']>(fillPath(P.retirePb, { playbook_id: id }), o),
    operations: (o: O) => get<Schemas['SoarOperations']>(P.operations, o),
    aiActivity: (o: O, kind?: string) => get<Schemas['AiActivityList']>(P.aiActivity + queryString({ kind, limit: 200 }), o),
    emergencyStop: (o: O, active: boolean, reason: string) => post<Schemas['SoarPolicyView']>(P.estop, o, { active, reason }),
};

export const vmsxApi = {
    findings: (o: O, q: Record<string, string | number | undefined>) => get<Schemas['VmsFindingList']>(P.findings + queryString(q), o),
    finding: (o: O, id: string) => get<Schemas['VmsFindingDetail']>(fillPath(P.finding, { finding_id: id }), o),
    transition: (o: O, id: string, to: string, reason: string) =>
        post<Schemas['VmsFindingView']>(fillPath(P.transition, { finding_id: id }), o, { finding_id: id, to_status: to, reason }),
    retest: (o: O, id: string, note: string) => post<Schemas['VerificationRequestView']>(fillPath(P.retest, { finding_id: id }), o, { note }),
    explain: (o: O, id: string) => post<Schemas['NhaiJob']>(P.findingExplain, o, { finding_id: id }),
    remediation: (o: O, q: Record<string, string | undefined> = {}) => get<Schemas['RemediationTaskList']>(P.remediation + queryString(q), o),
    updateTask: (o: O, id: string, body: Schemas['RemediationTaskUpdate']) => patch<Schemas['RemediationTaskView']>(fillPath(P.task, { task_id: id }), o, body),
    risk: (o: O) => get<Schemas['VmsRiskOverview']>(P.risk, o),
    services: (o: O) => get<Schemas['ServiceList']>(P.services, o),
    audit: (o: O) => get<Schemas['AuditEventList']>(P.vmsAudit, o),
    schedules: (o: O) => get<Schemas['VmsScheduleList']>(P.schedules, o),
    createSchedule: (o: O, body: Schemas['VmsScheduleCreate']) => post<Schemas['VmsScheduleView']>(P.schedules, o, body),
    toggleSchedule: (o: O, id: string, enabled: boolean) => patch<Schemas['VmsScheduleView']>(fillPath(P.schedule, { schedule_id: id }), o, { enabled }),
    report: (o: O) => get<Schemas['VmsReport']>(P.vmsReport, o),
    status: (o: O) => get<Schemas['VmsStatus']>(P.vmsStatus, o),
    scopes: (o: O) => get<Schemas['VmsScopeList']>(P.scopes, o),
    createScope: (o: O, body: Schemas['VmsScopeCreate']) => post<Schemas['VmsScopeView']>(P.scopes, o, body),
    scans: (o: O) => get<Schemas['VmsScanList']>(P.scans, o),
    createScan: (o: O, body: Schemas['VmsScanCreate']) => post<Schemas['VmsScanView']>(P.scans, o, body),
};

export const intelApi = {
    actors: (o: O, q: Record<string, string | undefined> = {}) => get<Schemas['ThreatActorList']>(P.actors + queryString(q), o),
    createActor: (o: O, body: Schemas['ThreatActorCreate']) => post<Schemas['ThreatActorView']>(P.actors, o, body),
    updateActor: (o: O, id: string, body: Schemas['ThreatActorCreate']) => put<Schemas['ThreatActorView']>(fillPath(P.actor, { actor_id: id }), o, body),
    link: (o: O, id: string, body: Schemas['ActorLinkCreate']) => post<Schemas['ThreatActorView']>(fillPath(P.actorLinks, { actor_id: id }), o, body),
    cves: (o: O, q: Record<string, string | undefined> = {}) => get<Schemas['CveIntelList']>(P.cves + queryString(q), o),
    importCves: (o: O, body: Schemas['CveImport']) => post<Schemas['CveImportResult']>(P.cveImport, o, body),
    importStix: (o: O) => post<Schemas['CveImportResult']>(P.cveStix, o),
    snapshots: (o: O, subject?: string) => get<Schemas['SnapshotList']>(P.snapshots + queryString({ subject }), o),
    snapshot: (o: O, body: Schemas['SnapshotCreate']) => post<Schemas['SnapshotView']>(P.snapshots, o, body),
};

export const cniiApi = {
    overview: (o: O) => get<Schemas['CniiOverview']>(P.cniiOverview, o),
    authorizations: (o: O) => get<Schemas['CniiAuthorizationList']>(P.cniiAuth, o),
    createAuthorization: (o: O, body: Schemas['CniiAuthorizationCreate']) => post<Schemas['CniiAuthorizationView']>(P.cniiAuth, o, body),
    revoke: (o: O, id: string, reason: string) => post<Schemas['CniiAuthorizationView']>(fillPath(P.cniiRevoke, { authorization_id: id }), o, { reason }),
    monitored: (o: O) => get<Schemas['CniiMonitoredAssetList']>(P.cniiAssets, o),
    designate: (o: O, body: Schemas['CniiMonitoredAssetCreate']) => post<Schemas['CniiMonitoredAssetView']>(P.cniiAssets, o, body),
    setStatus: (o: O, id: string, status: 'active' | 'suspended', reason: string) =>
        post<Schemas['CniiMonitoredAssetView']>(fillPath(P.cniiStatus, { monitored_id: id }), o, { status, reason }),
    setSchedule: (o: O, id: string, body: Schemas['CniiScheduleSet']) => put<Schemas['CniiMonitoredAssetView']>(fillPath(P.cniiSchedule, { monitored_id: id }), o, body),
    checks: (o: O, id: string) => get<Schemas['CniiCheckView'][]>(fillPath(P.cniiChecks, { monitored_id: id }), o),
};

export const continuityApi = {
    overview: (o: O) => get<Schemas['ContinuityOverview']>(P.contOverview, o),
    plans: (o: O) => get<Schemas['RecoveryPlanList']>(P.plans, o),
    createPlan: (o: O, body: Schemas['RecoveryPlanCreate']) => post<Schemas['RecoveryPlanView']>(P.plans, o, body),
    tested: (o: O, id: string, body: Schemas['RecoveryPlanTested']) => post<Schemas['RecoveryPlanView']>(fillPath(P.planTested, { plan_id: id }), o, body),
    requests: (o: O) => get<Schemas['RecoveryRequestList']>(P.requests, o),
    request: (o: O, id: string) => get<Schemas['RecoveryRequestView']>(fillPath(P.requestOne, { request_id: id }), o),
    submit: (o: O, body: Schemas['RecoveryRequestCreate']) => post<Schemas['RecoveryRequestView']>(P.requests, o, body),
    decide: (o: O, id: string, body: Schemas['RecoveryDecision']) => post<Schemas['RecoveryRequestView']>(fillPath(P.decision, { request_id: id }), o, body),
    progress: (o: O, id: string, body: Schemas['RecoveryProgress']) => post<Schemas['RecoveryRequestView']>(fillPath(P.progress, { request_id: id }), o, body),
    verify: (o: O, id: string, body: Schemas['RecoveryVerification']) => post<Schemas['RecoveryRequestView']>(fillPath(P.verify, { request_id: id }), o, body),
};

export const chatApi = {
    list: (o: O) => get<Schemas['ChatConversationList']>(P.convs, o),
    start: (o: O) => post<Schemas['ChatConversationView']>(P.convs, o, {}),
    get: (o: O, id: string) => get<Schemas['ChatConversationView']>(fillPath(P.conv, { conversation_id: id }), o),
    remove: (o: O, id: string) => del<void>(fillPath(P.conv, { conversation_id: id }), o),
    ask: (o: O, id: string, content: string) => post<Schemas['ChatExchange']>(fillPath(P.ask, { conversation_id: id }), o, { content }),
};

export const adminxApi = {
    billing: (o: O) => get<Schemas['BillingOverview']>(P.billing, o),
    createPlan: (o: O, body: Schemas['BillingPlanCreate']) => post<Schemas['BillingPlanView']>(P.plansAdmin, o, body),
    setPlanActive: (o: O, id: string, active: boolean) => patch<Schemas['BillingPlanView']>(fillPath(P.planAdmin, { plan_id: id }), o, { active }),
    setSubscription: (o: O, body: Schemas['SubscriptionSet']) => put<Schemas['BillingOverview']>(P.subs, o, body),
    exports: (o: O) => get<Schemas['DataExportList']>(P.exports, o),
    createExport: (o: O, body: Schemas['DataExportCreate']) => post<Schemas['DataExportView']>(P.exports, o, body),
    revokeExport: (o: O, id: string) => post<Schemas['DataExportView']>(fillPath(P.exportRevoke, { export_id: id }), o),
    teams: (o: O) => get<Schemas['TeamList']>(P.teams, o),
    createTeam: (o: O, body: Schemas['TeamCreate']) => post<Schemas['TeamView']>(P.teams, o, body),
    addMember: (o: O, id: string, body: Schemas['TeamMemberAdd']) => post<Schemas['TeamView']>(fillPath(P.teamMembers, { team_id: id }), o, body),
    removeMember: (o: O, id: string, userId: string) => del<Schemas['TeamView']>(fillPath(P.teamMember, { team_id: id, user_id: userId }), o),
    memberships: (o: O, userId: string) => get<Schemas['MembershipList']>(fillPath(P.memberships, { user_id: userId }), o),
    grant: (o: O, userId: string, body: Schemas['MembershipGrant']) => post<Schemas['MembershipList']>(fillPath(P.memberships, { user_id: userId }), o, body),
    revokeMembership: (o: O, userId: string, orgId: string) => del<Schemas['MembershipList']>(fillPath(P.membership, { user_id: userId, org_id: orgId }), o),
    analytics: (o: O) => get<Schemas['PlatformAnalytics']>(P.analytics, o),
    health: (o: O) => get<Schemas['PlatformHealth']>(P.health, o),
    quarantine: (o: O) => get<Schemas['QuarantineSummary']>(P.quarantine, o),
    onboarding: (o: O) => get<Schemas['OnboardingStatus']>(P.onboarding, o),
    audit: (o: O, q: Record<string, string | number | undefined>) => get<Schemas['AuditEventList']>(P.audit + queryString(q), o),
    mappings: (o: O) => get<Schemas['GroupMappingList']>(P.mappings, o),
    addMapping: (o: O, group: string) => post<Schemas['GroupMapping']>(P.mappings, o, { group_name: group }),
    removeMapping: (o: O, id: string) => del<void>(fillPath(P.mapping, { mapping_id: id }), o),
};
