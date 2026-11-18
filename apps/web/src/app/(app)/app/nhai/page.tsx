'use client';

// NHAI analysis: readiness from records (backend, the worker's heartbeat, the queue, outcomes), combined analyses of the
// organization (SIEM, VMS, assets, cases, Threat Insights, SOAR, remediation, posture) or, for platform staff, of every
// organization in scope, and every NHAI job with its progress, failure and retry. Results are drafts with citations
// for a person to review; NHAI never acts.
import Link from 'next/link';
import { useCallback, useEffect, useState } from 'react';
import { RotateCcw, Sparkles } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import type { Schemas } from '@/foundation/api/client';
import { nhaiApi, type NhaiJob } from '../insights/api';
import { NhaiResult } from '../insights/AlertIntelPanel';

const TONE: Record<string, 'good' | 'warning' | 'critical' | 'neutral'> = { succeeded: 'good', queued: 'neutral', running: 'warning', failed: 'critical', timed_out: 'critical' };
const READY: Record<string, 'good' | 'warning' | 'critical'> = { ready: 'good', degraded: 'warning', unavailable: 'critical' };
const ERRORS: Record<string, string> = {
    backend_unavailable: 'The model could not be reached', timeout: 'The model did not answer in time', subject_missing: 'The record no longer exists',
    invalid_bundle: 'The stored evidence was invalid', scope_violation: 'Evidence from another organization was refused', output_invalid: 'The draft failed validation',
};

function subjectLink(j: NhaiJob): string | null {
    const id = j.subject.id;
    switch (j.subject.type) {
        case 'alert': return `/app/alerts/${id}`;
        case 'vms_finding': return `/app/vms/findings?finding=${id}`;
        case 'asset': return `/app/assets/${id}`;
        case 'case': return `/app/cases/${id}`;
        case 'chat_message': return '/app/chat';
        default: return null;
    }
}

function progress(j: NhaiJob): string {
    const since = (t: string | null | undefined) => (t ? Math.max(0, Math.round((Date.now() - new Date(t).getTime()) / 1000)) : 0);
    if (j.status === 'queued') return `waiting ${since(j.queued_at)} s${j.attempts ? ` · attempt ${j.attempts + 1}` : ''}`;
    if (j.status === 'running') return `running ${since(j.started_at)} s · deadline ${fmt(j.deadline_at)}`;
    if (j.status === 'succeeded') return `finished ${fmt(j.finished_at)}`;
    return `${ERRORS[j.error_code ?? ''] ?? j.error_code ?? 'failed'} · ${fmt(j.finished_at)}`;
}

function Readiness({ r }: { r: Schemas['NhaiReadiness'] }) {
    return (
        <div className="space-y-2 text-sm" data-testid="nhai-readiness" data-state={r.state}>
            <p className="flex flex-wrap items-center gap-2"><StatusPill tone={READY[r.state]} label={r.state} />
                {r.model && <Tag>{r.model}</Tag>}{r.pilot && <span data-testid="nhai-pilot"><StatusPill tone="warning" label="limited pilot" /></span>}
                <span className="text-xs text-foreground-muted">worker {r.worker_state}{r.worker_last_seen_at ? `, last seen ${fmt(r.worker_last_seen_at)}` : ''}</span></p>
            {r.pilot_note && <p className="text-xs rounded-lg border border-border bg-card-muted p-2">{r.pilot_note}</p>}
            {r.reasons.length > 0 && <ul className="text-xs list-disc pl-5 text-foreground-muted">{r.reasons.map((x) => <li key={x} className="wrap-any">{x}</li>)}</ul>}
            <p className="text-xs text-foreground-muted">Queue: {r.queued} waiting{r.oldest_queued_seconds != null ? ` (oldest ${Math.round(r.oldest_queued_seconds / 60)} min)` : ''} · {r.running} running ·
                last 24 h: {r.succeeded_24h} drafts, {r.failed_24h} failed · {r.awaiting_review} awaiting review{r.last_success_at ? ` · last draft ${fmt(r.last_success_at)}` : ''}</p>
        </div>
    );
}

export default function NhaiPage() {
    const { orgId, can } = useSession();
    const jobs = useResource(useCallback(() => nhaiApi.jobs(orgId), [orgId]));
    const ready = useResource(useCallback(() => nhaiApi.readiness(orgId), [orgId]));
    // Platform staff only: anybody else gets 403 and the platform section simply does not appear.
    const platform = useResource(useCallback(() => nhaiApi.overview(orgId), [orgId]));
    const [open, setOpen] = useState<NhaiJob | null>(null);
    const [days, setDays] = useState(7);
    const act = useAction();
    const active = jobs.data?.items.some((j) => j.status === 'queued' || j.status === 'running') ?? false;
    const { reload: reloadJobs } = jobs;
    const { reload: reloadReady } = ready;
    useEffect(() => {                                   // live progress while a job is waiting or running
        if (!active) return;
        const t = setInterval(() => { reloadJobs(); reloadReady(); }, 5000);
        return () => clearInterval(t);
    }, [active, reloadJobs, reloadReady]);
    async function analyse(scope: 'organization' | 'platform') {
        const r = await act.run(() => nhaiApi.analyse(orgId, scope, days), scope === 'platform' ? 'Platform analysis queued.' : 'Analysis queued.');
        if (r) { jobs.reload(); ready.reload(); }
    }
    async function retry(j: NhaiJob) {
        const r = await act.run(() => nhaiApi.retry(orgId, j.id), 'Queued again with fresh evidence.');
        if (r) { jobs.reload(); ready.reload(); }
    }
    const latest = jobs.data?.items.find((j) => j.task === 'posture_analysis');
    return (
        <>
            <PageHeader title="NHAI analysis" icon={Sparkles}
                description="Evidence-grounded drafts for human review, across SIEM, VMS, assets, cases, Threat Insights, NovrSOAR, remediation and posture. Every statement cites the evidence; the SIEM and scanner severities stay authoritative; NHAI never acts." />
            {act.notice}
            <div className="grid gap-5 lg:grid-cols-[repeat(2,minmax(0,1fr))]">
                <Loaded title="Readiness" hint="From records: configuration, the worker's heartbeat, the queue and recent outcomes" data={ready.data} error={ready.error} reload={ready.reload}>
                    {(r) => <Readiness r={r} />}
                </Loaded>
                <Card>
                    <SectionTitle title="Combined analysis" hint="Aggregates of every domain, cited; individual records stay where they are" />
                    <div className="mt-3 flex flex-wrap items-end gap-2" data-testid="nhai-analyse">
                        <Field label="Window"><select className={selectCls} value={days} onChange={(e) => setDays(Number(e.target.value))}>
                            {[1, 7, 14, 30].map((d) => <option key={d} value={d}>{d === 1 ? 'Last 24 hours' : `Last ${d} days`}</option>)}</select></Field>
                        <button className={btn('primary')} disabled={act.busy || !can('nhai:analyze')} onClick={() => void analyse('organization')} data-testid="nhai-analyse-org">Analyse this organization</button>
                        {platform.data && <button className={btn('secondary')} disabled={act.busy} onClick={() => void analyse('platform')} data-testid="nhai-analyse-platform">Analyse every organization</button>}
                    </div>
                    {latest && (
                        <p className="mt-3 text-xs flex flex-wrap items-center gap-2" data-testid="nhai-latest">Latest: <StatusPill tone={TONE[latest.status] ?? 'neutral'} label={latest.status.replace('_', ' ')} />
                            <span className="text-foreground-muted">{latest.subject.type === 'platform' ? 'every organization' : 'this organization'} · {progress(latest)}</span>
                            {latest.result && <button className="underline" onClick={() => setOpen(latest)}>Open the draft</button>}</p>
                    )}
                </Card>
            </div>
            {platform.data && (
                <Loaded title="Organizations" hint="NHAI activity per organization of your command scope, read under each organization's own access rules" data={platform.data} error={null} reload={platform.reload}>
                    {(d) => <DataTable testid="nhai-orgs" rows={d.organizations} rowKey={(o) => o.org_id} empty="No organization in scope." columns={[
                        { key: 'o', header: 'Organization', render: (o) => <span className="wrap-any">{o.org_name}</span> },
                        { key: 'q', header: 'Queue', render: (o) => <span className="text-xs">{o.queued} waiting · {o.running} running</span> },
                        { key: 'd', header: 'Last 24 h', render: (o) => <span className="text-xs">{o.succeeded_24h} drafts · {o.failed_24h} failed</span> },
                        { key: 'r', header: 'Awaiting review', render: (o) => <span className="text-xs">{o.awaiting_review}</span> },
                        { key: 'l', header: 'Last draft', className: 'hidden md:table-cell', render: (o) => <span className="text-xs">{fmt(o.last_success_at)}</span> },
                    ]} />}
                </Loaded>
            )}
            <Loaded title="Jobs" hint={active ? 'Refreshing every 5 seconds while a job is waiting or running' : undefined} data={jobs.data} error={jobs.error} reload={jobs.reload}>
                {(d) => <DataTable testid="nhai-jobs" rows={d.items} rowKey={(j) => j.id} empty="No NHAI job yet. Ask for an analysis above, or an explanation from an alert, finding, asset or case." columns={[
                    { key: 's', header: 'Request', render: (j) => {
                        const href = subjectLink(j);
                        const label = j.task === 'posture_analysis' ? (j.subject.type === 'platform' ? 'combined analysis · every organization' : 'combined analysis') : j.task.replace(/_/g, ' ');
                        return href ? <Link className="underline text-xs" href={href}>{label}</Link> : <span className="text-xs">{label}</span>;
                    } },
                    { key: 'st', header: 'Status', render: (j) => <span className="min-w-0"><StatusPill tone={TONE[j.status] ?? 'neutral'} label={j.status.replace('_', ' ')} />
                        <span className="block text-[11px] text-foreground-muted wrap-any">{progress(j)}</span></span> },
                    { key: 'r', header: 'Review', render: (j) => j.result?.review ? <Tag>{j.result.review.decision}</Tag> : j.result ? <Tag>draft</Tag> : '—' },
                    { key: 'q', header: 'Requested', className: 'hidden md:table-cell', render: (j) => <span className="text-xs">{j.requested_by.label} · {fmt(j.queued_at)}</span> },
                    { key: 'o', header: '', render: (j) => j.result ? <button className="text-xs underline" onClick={() => setOpen(j)}>Open</button>
                        : (j.status === 'failed' || j.status === 'timed_out') && j.task !== 'chat_answer'
                            ? <button className={btn('ghost')} disabled={act.busy} onClick={() => void retry(j)} data-testid="nhai-retry"><RotateCcw className="w-3.5 h-3.5" aria-hidden />Retry</button> : null },
                ]} />}
            </Loaded>
            {open && (
                <Card>
                    <SectionTitle title="Draft result" hint="Each statement cites its evidence; review before using it" />
                    <div className="mt-3"><NhaiResult job={open} onChange={(j) => { setOpen(j); jobs.reload(); }} /></div>
                </Card>
            )}
        </>
    );
}
