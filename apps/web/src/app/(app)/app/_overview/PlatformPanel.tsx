'use client';

// Organization dashboard. Every figure comes from the FastAPI service for the active organization; a
// figure that cannot be established is shown as Unavailable with the reason, never as zero or healthy.
import Link from 'next/link';
import { useCallback } from 'react';
import { Bell, Briefcase, Building2, CircleDashed, Database, Lock, MapPin, Monitor, ScrollText } from 'lucide-react';
import { KpiCard, SeverityBadge, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { api } from '@/foundation/api/client';
import { STATE_TEXT, uiState } from '@/foundation/api/errors';
import { platformApi } from '@/foundation/api/platform';
import { socApi } from '../alerts/api';
import { endpointsApi } from '../endpoints/api';
import { ROLE_LABEL } from '@/foundation/shell/AppShell';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { CONNECTOR_LABEL, FixtureTag, SourceBanner, SourcePill, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

const reasonOf = (e: unknown) => STATE_TEXT[uiState(e)].title;
const NOT_IN_ROLE = 'Not available for your role';

/** One optional figure: skipped (null loader) when the role lacks the permission. */
function useOptional<T>(allowed: boolean, loader: () => Promise<T>) {
    const r = useResource(useCallback(() => (allowed ? loader() : Promise.resolve(null as T | null)), [allowed, loader]));
    return { ...r, loading: allowed && r.data === undefined && !r.error };
}

/** Platform readiness, module states and recent activity (moved from the former overview; part of the executive overview). */
export function PlatformPanel() {
    const { session, can, orgs, orgId } = useSession();
    const status = useResource(useCallback(() => platformApi.status(orgId), [orgId]));
    const sites = useOptional(can('sites:read'), useCallback(() => api.listSites(orgId), [orgId]));
    const endpoints = useOptional(can('endpoints:read'), useCallback(() => endpointsApi.inventory(orgId), [orgId]));
    const newAlerts = useOptional(can('alerts:read'), useCallback(() => socApi.alerts(orgId, { status: 'new', limit: 5 }), [orgId]));
    const openCases = useOptional(can('cases:read'), useCallback(() => socApi.cases(orgId, { status: 'open', limit: 1 }), [orgId]));
    const audit = useOptional(can('audit:read'), useCallback(() => platformApi.recentAudit(orgId, 8), [orgId]));

    const wazuh = status.data?.connectors.find((c) => c.connector === 'wazuh_manager');
    const inv = endpoints.data;
    const fixtureAlerts = newAlerts.data?.items.some((a) => a.source === 'local_fixture');

    return (
        <>
            {wazuh && wazuh.state === 'local_fixture' && <SourceBanner source={wazuh} what="Endpoint and alert data" />}

            <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4" data-testid="platform-kpis">
                <KpiCard label="Active organization" text={session.active_org.name} icon={Building2}
                    hint={session.cross_org ? 'Acting for another organization (audited)' : `${ROLE_LABEL[session.role] ?? session.role} · ${orgs.length} organization(s) available`} />
                <KpiCard label="Sites in this organization" icon={MapPin} loading={sites.loading}
                    value={sites.data ? sites.data.items.length : null}
                    reason={!can('sites:read') ? NOT_IN_ROLE : reasonOf(sites.error)} href={can('sites:read') ? '/app/sites' : undefined} />
                <KpiCard label="Endpoints" icon={Monitor} loading={endpoints.loading}
                    value={inv && inv.source.state !== 'unconfigured' ? inv.items.length : null}
                    reason={!can('endpoints:read') ? NOT_IN_ROLE : inv?.source.state === 'unconfigured' ? 'No Wazuh connection is configured' : reasonOf(endpoints.error)}
                    hint={inv?.source.state === 'local_fixture' ? 'Local fixture data, not live telemetry' : inv ? `${inv.mapped_groups} agent group(s) mapped` : undefined}
                    href={can('endpoints:read') ? '/app/endpoints' : undefined} />
                <KpiCard label="New alerts" icon={Bell} loading={newAlerts.loading}
                    value={newAlerts.data ? newAlerts.data.total : null}
                    reason={!can('alerts:read') ? NOT_IN_ROLE : reasonOf(newAlerts.error)}
                    hint={newAlerts.data ? (fixtureAlerts ? 'Stored alerts, including local fixture alerts' : 'Stored alerts awaiting triage') : undefined}
                    href={can('alerts:read') ? '/app/alerts' : undefined} />
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
                <Card>
                    <SectionTitle title="Service and connector readiness" hint="As established by the API. Nothing is shown as connected unless the API has connected." />
                    {status.error ? <div className="mt-3"><ApiErrorState error={status.error} onRetry={() => void status.reload()} /></div>
                        : !status.data ? <div className="mt-3"><LoadingState label="Reading service status" /></div>
                        : (
                            <ul className="mt-3 divide-y divide-border text-sm" data-testid="readiness">
                                <li className="flex items-center gap-2 py-2">
                                    <Database className="w-4 h-4 text-foreground-muted shrink-0" aria-hidden />
                                    <span className="flex-1">Database</span>
                                    <StatusPill tone={status.data.database === 'ok' ? 'good' : 'critical'} label={status.data.database === 'ok' ? `Ready · schema ${status.data.migration}` : 'Unavailable'} />
                                </li>
                                {status.data.connectors.map((c) => (
                                    <li key={c.connector} className="flex items-start gap-2 py-2" data-connector={c.connector} data-state={c.state}>
                                        <CircleDashed className="w-4 h-4 mt-0.5 text-foreground-muted shrink-0" aria-hidden />
                                        <span className="flex-1 min-w-0">{CONNECTOR_LABEL[c.connector]}
                                            {c.detail && <span className="block text-[11px] text-foreground-muted">{c.detail}</span>}</span>
                                        <SourcePill state={c.state} />
                                    </li>
                                ))}
                            </ul>
                        )}
                </Card>
                <Card>
                    <SectionTitle title="Modules" hint="Live modules are backed by the API. Others are approved and in development." />
                    {status.data && (
                        <ul className="mt-3 divide-y divide-border text-sm" data-testid="modules">
                            {status.data.modules.map((m) => (
                                <li key={m.key} className="flex items-center gap-2 py-2" data-module={m.key} data-state={m.state}>
                                    <span className="flex-1 min-w-0">{m.label}{m.note && <span className="block text-[11px] text-foreground-muted">{m.note}</span>}</span>
                                    {m.state === 'live' ? <StatusPill tone="good" label="Available" />
                                        : m.state === 'restricted' ? <StatusPill tone="neutral" label="Restricted" />
                                        : <span className="text-[10px] font-bold uppercase tracking-wider border border-border rounded px-1.5 py-0.5 text-foreground-muted">Not yet available</span>}
                                </li>
                            ))}
                        </ul>
                    )}
                </Card>
            </div>

            <div className="grid gap-5 lg:grid-cols-2">
                <Card>
                    <SectionTitle title="Latest new alerts" action={can('alerts:read') ? <Link href="/app/alerts" className={btn('ghost')}>All alerts</Link> : undefined} />
                    {!can('alerts:read') ? <p className="mt-3 text-xs text-foreground-muted">{NOT_IN_ROLE}.</p>
                        : newAlerts.error ? <div className="mt-3"><ApiErrorState error={newAlerts.error} /></div>
                        : !newAlerts.data ? <div className="mt-3"><LoadingState label="Loading alerts" /></div>
                        : newAlerts.data.items.length === 0 ? <p className="mt-3 text-xs text-foreground-muted">No new alerts are stored for this organization.</p>
                        : (
                            <ul className="mt-3 divide-y divide-border" data-testid="latest-alerts">
                                {newAlerts.data.items.map((a) => (
                                    <li key={a.id} className="py-2 flex items-center gap-2 text-sm">
                                        <SeverityBadge severity={a.severity} />
                                        <Link href={`/app/alerts/${a.id}`} className="flex-1 min-w-0 truncate text-foreground hover:underline">{a.rule_description || `Rule ${a.rule_id}`}</Link>
                                        {a.source === 'local_fixture' && <FixtureTag />}
                                    </li>
                                ))}
                            </ul>
                        )}
                    {openCases.data && <p className="mt-3 text-xs text-foreground-muted flex items-center gap-1.5"><Briefcase className="w-3.5 h-3.5" aria-hidden />
                        {openCases.data.total} open case(s). <Link href="/app/cases" className="underline">View cases</Link></p>}
                </Card>
                <Card>
                    <SectionTitle title="Recent audit events" hint="Actions recorded for this organization" />
                    {!can('audit:read') ? <p className="mt-3 text-xs text-foreground-muted flex items-center gap-1.5"><Lock className="w-3.5 h-3.5" aria-hidden />The audit trail is visible to roles with audit access.</p>
                        : audit.error ? <div className="mt-3"><ApiErrorState error={audit.error} /></div>
                        : !audit.data ? <div className="mt-3"><LoadingState label="Loading audit events" /></div>
                        : audit.data.items.length === 0 ? <p className="mt-3 text-xs text-foreground-muted">No audit events yet.</p>
                        : (
                            <ul className="mt-3 divide-y divide-border" data-testid="audit-events">
                                {audit.data.items.map((e) => (
                                    <li key={e.id} className="py-2 flex items-start gap-2 text-xs">
                                        <ScrollText className="w-3.5 h-3.5 mt-0.5 text-foreground-muted shrink-0" aria-hidden />
                                        <span className="flex-1 min-w-0"><span className="font-mono font-semibold text-foreground">{e.action}</span>
                                            <span className="block text-foreground-muted truncate">{e.actor_label} · {e.outcome} · {fmtDateTime(e.occurred_at)}</span></span>
                                    </li>
                                ))}
                            </ul>
                        )}
                </Card>
            </div>
        </>
    );
}
