'use client';

// One stored alert: details, triage (acknowledge / close) and promotion to a case. There is no response
// action here: containment is not available in this release.
import Link from 'next/link';
import { useCallback, useState } from 'react';
import { useParams, useRouter } from 'next/navigation';
import { ArrowLeft, Bell, Briefcase, Info } from 'lucide-react';
import { EvidenceViewer, Notice, PageHeader, SeverityBadge, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { socApi, type AlertStatus } from '../api';
import { AlertIntelPanel } from '../../insights/AlertIntelPanel';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { ALERT_STATUS_LABEL, FixtureTag, STATUS_TONE, fmtDateTime, inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { errorText } from '@/foundation/ui/pilot';

export default function AlertDetailPage() {
    const { id } = useParams<{ id: string }>();
    const router = useRouter();
    const { orgId, can, session } = useSession();
    const { data: a, error, setData } = useResource(useCallback(() => socApi.alert(orgId, id), [orgId, id]));
    const [reason, setReason] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);

    const fail = (e: unknown) => setMsg({ ok: false, text: (e instanceof ApiError && e.message) || STATE_TEXT[uiState(e)].body });

    async function setStatus(status: AlertStatus) {
        setBusy(true); setMsg(null);
        try { setData(await socApi.setAlertStatus(orgId, id, status, reason.trim())); setReason(''); setMsg({ ok: true, text: `Alert marked ${ALERT_STATUS_LABEL[status].toLowerCase()}.` }); }
        catch (e) { fail(e); } finally { setBusy(false); }
    }
    async function assign(user: string | null) {
        setBusy(true); setMsg(null);
        try { setData(await socApi.assignAlert(orgId, id, user)); setMsg({ ok: true, text: user ? 'Assigned to you.' : 'Unassigned.' }); }
        catch (e) { setMsg({ ok: false, text: errorText(e) }); } finally { setBusy(false); }
    }
    async function createCase() {
        if (!a) return;
        setBusy(true); setMsg(null);
        try { const r = await socApi.caseFromAlert(orgId, a); router.push(`/app/cases/${r.case_id}`); }
        catch (e) { fail(e); setBusy(false); }
    }

    return (
        <>
            <PageHeader title={a ? (a.rule_description || `Rule ${a.rule_id}`) : 'Alert'} icon={Bell}
                actions={<Link href="/app/alerts" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> All alerts</Link>} />
            {error ? <div data-testid="alert-error"><ApiErrorState error={error} /></div>
                : !a ? <LoadingState label="Loading alert" />
                : (
                    <>
                        <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
                            <Card>
                                <SectionTitle title="Alert" />
                                <dl className="mt-3 grid grid-cols-[9rem_1fr] gap-y-2 text-sm" data-testid="alert-detail">
                                    <dt className="text-foreground-muted">Severity</dt><dd><SeverityBadge severity={a.severity} /> <span className="text-xs text-foreground-muted">(rule level {a.rule_level})</span></dd>
                                    <dt className="text-foreground-muted">Status</dt><dd data-testid="alert-status"><StatusPill tone={STATUS_TONE[a.status] ?? 'neutral'} label={ALERT_STATUS_LABEL[a.status] ?? a.status} />{a.status_reason && <span className="block text-xs text-foreground-muted">{a.status_reason}</span>}</dd>
                                    <dt className="text-foreground-muted">Source</dt><dd className="flex items-center gap-2">{a.source === 'local_fixture' ? <><span>Local fixture</span><FixtureTag /></> : 'NovrSIEM'}</dd>
                                    <dt className="text-foreground-muted">Rule</dt><dd className="font-mono text-xs">{a.rule_id}</dd>
                                    <dt className="text-foreground-muted">Endpoint</dt><dd>{a.agent_name || '—'} <span className="font-mono text-xs text-foreground-muted">#{a.agent_id}</span>
                                        {a.asset_id && <Link href={`/app/assets/${a.asset_id}`} className="ml-2 text-xs underline">Canonical asset</Link>}</dd>
                                    <dt className="text-foreground-muted">Assignee</dt><dd data-testid="alert-assignee">{a.assignee_label ?? 'Unassigned'}
                                        {can('alerts:triage') && (a.assignee_id !== session.user.id
                                            ? <button className={`${btn('secondary')} ml-2`} disabled={busy} onClick={() => void assign(session.user.id)} data-testid="alert-assign-me">Assign to me</button>
                                            : <button className={`${btn('secondary')} ml-2`} disabled={busy} onClick={() => void assign(null)}>Unassign</button>)}</dd>
                                    <dt className="text-foreground-muted">Agent groups</dt><dd className="flex flex-wrap gap-1">{a.agent_groups.map((g) => <Tag key={g}>{g}</Tag>)}</dd>
                                    <dt className="text-foreground-muted">Source IP</dt><dd className="font-mono text-xs">{a.src_ip ?? '—'}</dd>
                                    <dt className="text-foreground-muted">MITRE ATT&amp;CK</dt><dd className="flex flex-wrap gap-1">{a.mitre_techniques.length ? a.mitre_techniques.map((t) => <Tag key={t}>{t}</Tag>) : '—'}</dd>
                                    <dt className="text-foreground-muted">Observed</dt><dd>{fmtDateTime(a.observed_at)}</dd>
                                    <dt className="text-foreground-muted">Received</dt><dd>{fmtDateTime(a.received_at)}</dd>
                                    <dt className="text-foreground-muted">External id</dt><dd className="font-mono text-xs break-all">{a.external_id}</dd>
                                </dl>
                            </Card>
                            <Card>
                                <SectionTitle title="Triage" />
                                <div className="mt-3 space-y-3 text-sm">
                                    {a.case_id ? (
                                        <Link href={`/app/cases/${a.case_id}`} className={btn('primary', 'md')} data-testid="open-case"><Briefcase className="w-4 h-4" aria-hidden /> Open linked case</Link>
                                    ) : can('cases:write') && a.severity !== 'info' ? (
                                        <button className={btn('primary', 'md')} disabled={busy} onClick={() => void createCase()} data-testid="create-case"><Briefcase className="w-4 h-4" aria-hidden /> Create case from alert</button>
                                    ) : null}
                                    {can('alerts:triage') && a.status !== 'closed' && (
                                        <>
                                            <label className="text-xs text-foreground-muted flex flex-col gap-1">Reason (optional)
                                                <input value={reason} maxLength={500} onChange={(e) => setReason(e.target.value)} className={inputCls} data-testid="alert-reason" />
                                            </label>
                                            <div className="flex flex-wrap gap-2">
                                                {a.status === 'new' && <button className={btn('secondary')} disabled={busy} onClick={() => void setStatus('acknowledged')} data-testid="alert-ack">Acknowledge</button>}
                                                <button className={btn('secondary')} disabled={busy} onClick={() => void setStatus('closed')} data-testid="alert-close">Close alert</button>
                                            </div>
                                        </>
                                    )}
                                    {!can('alerts:triage') && !can('cases:write') && <p className="text-xs text-foreground-muted">Your role can view this alert but not triage it.</p>}
                                    <Notice msg={msg} />
                                    <p className="flex items-start gap-1.5 text-[11px] text-foreground-muted"><Info className="w-3.5 h-3.5 mt-0.5 shrink-0" aria-hidden />Response actions run only through SOAR on a case: every consequential step needs a second person&apos;s approval, and nothing runs automatically.</p>
                                </div>
                            </Card>
                        </div>
                        <AlertIntelPanel alertId={a.id} />
                        <Card>
                            <SectionTitle title="Original alert" hint="As received (capped at 32 KB)" />
                            <div className="mt-3"><EvidenceViewer items={[{ id: 'raw', title: 'Alert JSON', content: a.raw }]} /></div>
                        </Card>
                    </>
                )}
        </>
    );
}
