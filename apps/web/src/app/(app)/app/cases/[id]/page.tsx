'use client';

import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { useParams } from 'next/navigation';
import { ArrowLeft, Briefcase } from 'lucide-react';
import { Notice, PageHeader, SeverityBadge, Timeline, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { socApi, type CaseStatus } from '../../alerts/api';
import { CaseSoarPanel } from '../../soar/CaseSoarPanel';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { ALERT_STATUS_LABEL, CASE_STATUS_LABEL, FixtureTag, STATUS_TONE, fmtDateTime, inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { StateTag } from '@/foundation/ui/module';

const KIND: Record<string, string> = { created: 'Case created', note: 'Note', status_changed: 'Status changed', alert_linked: 'Alert linked',
    assigned: 'Assignment', remediation: 'Remediation', evidence: 'Evidence', sla_escalated: 'SLA escalation', closure: 'Closed', severity_changed: 'Severity changed' };
const NEXT: Record<CaseStatus, CaseStatus[]> = {
    open: ['in_progress', 'resolved', 'closed'], in_progress: ['resolved', 'closed'], resolved: ['in_progress', 'closed'], closed: ['open'],
};

export default function CaseDetailPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId, can, session } = useSession();
    const { data: c, error, setData } = useResource(useCallback(() => socApi.caseDetail(orgId, id), [orgId, id]));
    const [note, setNote] = useState('');
    const [noteKind, setNoteKind] = useState<'note' | 'remediation' | 'evidence'>('note');
    const [statusNote, setStatusNote] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    const fail = (e: unknown) => setMsg({ ok: false, text: (e instanceof ApiError && e.message) || STATE_TEXT[uiState(e)].body });

    async function addNote(e: FormEvent) {
        e.preventDefault();
        setBusy(true); setMsg(null);
        try { setData(await socApi.addNote(orgId, id, note.trim(), noteKind)); setNote(''); setMsg({ ok: true, text: 'Note added.' }); }
        catch (err) { fail(err); } finally { setBusy(false); }
    }
    async function assign(user: string | null) {
        setBusy(true); setMsg(null);
        try { setData(await socApi.assignCase(orgId, id, user)); setMsg({ ok: true, text: user ? 'Assigned to you.' : 'Unassigned.' }); }
        catch (err) { setMsg({ ok: false, text: (err instanceof ApiError && err.message) || STATE_TEXT[uiState(err)].body }); } finally { setBusy(false); }
    }
    async function move(status: CaseStatus) {
        setBusy(true); setMsg(null);
        try { setData(await socApi.setCaseStatus(orgId, id, status, statusNote.trim())); setStatusNote(''); setMsg({ ok: true, text: `Case is now ${CASE_STATUS_LABEL[status].toLowerCase()}.` }); }
        catch (err) { fail(err); } finally { setBusy(false); }
    }

    return (
        <>
            <PageHeader title={c?.title ?? 'Case'} icon={Briefcase} meta={c && <><span className="font-mono">{c.reference}</span><span>Opened {fmtDateTime(c.created_at)}</span></>}
                actions={<Link href="/app/cases" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> All cases</Link>} />
            {error ? <div data-testid="case-error"><ApiErrorState error={error} /></div>
                : !c ? <LoadingState label="Loading case" />
                : (
                    <>
                        <div className="grid gap-5 lg:grid-cols-[1fr_20rem]">
                            <Card>
                                <SectionTitle title="Linked alerts" />
                                <ul className="mt-3 divide-y divide-border" data-testid="case-alerts">
                                    {c.alerts.map((a) => (
                                        <li key={a.id} className="py-2 flex flex-wrap items-center gap-2 text-sm">
                                            <SeverityBadge severity={a.severity} />
                                            <Link href={`/app/alerts/${a.id}`} className="flex-1 min-w-[10rem] text-foreground hover:underline">{a.rule_description || `Rule ${a.rule_id}`}</Link>
                                            {a.source === 'local_fixture' && <FixtureTag />}
                                            <span className="text-[11px] text-foreground-muted">{a.agent_name} · {ALERT_STATUS_LABEL[a.status]}</span>
                                        </li>
                                    ))}
                                </ul>
                            </Card>
                            <Card>
                                <SectionTitle title="Status" />
                                <div className="mt-3 space-y-3 text-sm">
                                    <p className="flex items-center gap-2" data-testid="case-status"><SeverityBadge severity={c.severity} /><StatusPill tone={STATUS_TONE[c.status] ?? 'neutral'} label={CASE_STATUS_LABEL[c.status] ?? c.status} /></p>
                                    <dl className="grid grid-cols-[8rem_1fr] gap-y-1.5 text-xs" data-testid="case-sla">
                                        <dt className="text-foreground-muted">SLA</dt><dd><StateTag state={c.sla_state} label={c.sla_state === 'no_policy' ? 'no SLA policy' : c.sla_state.replace(/_/g, ' ')} /></dd>
                                        <dt className="text-foreground-muted">Respond by</dt><dd>{fmtDateTime(c.sla_response_due_at)}{c.first_response_at && <span className="text-foreground-muted"> · responded {fmtDateTime(c.first_response_at)}</span>}</dd>
                                        <dt className="text-foreground-muted">Resolve by</dt><dd>{fmtDateTime(c.sla_resolution_due_at)}{c.resolved_at && <span className="text-foreground-muted"> · resolved {fmtDateTime(c.resolved_at)}</span>}</dd>
                                        <dt className="text-foreground-muted">Assignee</dt><dd data-testid="case-assignee">{c.assignee_label ?? 'Unassigned'}
                                            {can('cases:write') && (c.assignee_id !== session.user.id
                                                ? <button className={`${btn('secondary')} ml-2`} disabled={busy} onClick={() => void assign(session.user.id)} data-testid="case-assign-me">Assign to me</button>
                                                : <button className={`${btn('secondary')} ml-2`} disabled={busy} onClick={() => void assign(null)}>Unassign</button>)}</dd>
                                    </dl>
                                    {can('cases:write') && (
                                        <>
                                            <label className="text-xs text-foreground-muted flex flex-col gap-1">Note for the change (closing needs a closure note: outcome and remediation)
                                                <input value={statusNote} maxLength={2000} onChange={(e) => setStatusNote(e.target.value)} className={inputCls} />
                                            </label>
                                            <div className="flex flex-wrap gap-2">
                                                {NEXT[c.status].filter((s) => s !== 'closed' || can('cases:close')).map((s) => (
                                                    <button key={s} className={btn('secondary')} disabled={busy} onClick={() => void move(s)} data-testid={`case-to-${s}`}>
                                                        {s === 'open' ? 'Reopen' : `Mark ${CASE_STATUS_LABEL[s].toLowerCase()}`}
                                                    </button>
                                                ))}
                                            </div>
                                        </>
                                    )}
                                    <Notice msg={msg} />
                                </div>
                            </Card>
                        </div>
                        <CaseSoarPanel caseId={c.id} />
                        <div className="grid gap-5 lg:grid-cols-2">
                            <Card>
                                <SectionTitle title="Timeline" hint="Append-only" />
                                <div className="mt-3" data-testid="case-timeline">
                                    <Timeline items={c.timeline.map((e) => ({
                                        id: String(e.id), at: e.occurred_at, title: KIND[e.kind] ?? e.kind,
                                        meta: `${e.actor_label} · ${fmtDateTime(e.occurred_at)}`, body: e.body || undefined,
                                        tone: e.kind === 'status_changed' || e.kind === 'sla_escalated' ? 'warning' : e.kind === 'closure' ? 'good' : 'neutral',
                                    }))} />
                                </div>
                            </Card>
                            {can('cases:write') && (
                                <Card>
                                    <SectionTitle title="Add to the timeline" />
                                    <form onSubmit={addNote} className="mt-3 space-y-2" data-testid="note-form">
                                        <label className="text-xs text-foreground-muted flex items-center gap-2">Type
                                            <select value={noteKind} onChange={(e) => setNoteKind(e.target.value as typeof noteKind)} className={inputCls} data-testid="note-kind">
                                                <option value="note">Analyst note</option><option value="remediation">Remediation</option><option value="evidence">Evidence</option>
                                            </select></label>
                                        <label className="sr-only" htmlFor="case-note">Note</label>
                                        <textarea id="case-note" required maxLength={8000} rows={4} value={note} onChange={(e) => setNote(e.target.value)} className={`${inputCls} w-full`} data-testid="note-body" />
                                        <button type="submit" className={btn('primary', 'md')} disabled={busy || !note.trim()} data-testid="note-submit">Add note</button>
                                    </form>
                                </Card>
                            )}
                        </div>
                    </>
                )}
        </>
    );
}
