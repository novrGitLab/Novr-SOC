'use client';

// Intelligence for one alert: Threat Insights matches (deterministic), the NHAI explanation (asynchronous draft for
// human review; never authoritative) and the original source evidence (redacted, with its source state).
import { useCallback, useState } from 'react';
import { Info } from 'lucide-react';
import { EvidenceViewer, Notice, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { SourcePill } from '@/foundation/ui/sources';
import { Field, Loaded, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { socApi } from '../alerts/api';
import { insightsApi, nhaiApi, type NhaiJob } from './api';

export function NhaiResult({ job, onChange }: { job: NhaiJob; onChange: (j: NhaiJob) => void }) {
    const { orgId, can } = useSession();
    const [note, setNote] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const r = job.result;
    async function review(decision: 'accept' | 'reject') {
        try { onChange(await nhaiApi.review(orgId, job.id, decision, note.trim())); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    if (!r) {
        return <p className="text-xs text-foreground-muted" data-testid="nhai-status">Job {job.status.replace('_', ' ')}{job.error_code ? ` (${job.error_code})` : ''}. Queued {fmt(job.queued_at)}; CPU inference can take minutes.</p>;
    }
    return (
        <div className="space-y-2 text-sm" data-testid="nhai-result">
            <p className="flex flex-wrap items-center gap-2"><Tag>{r.status}</Tag><Tag>confidence {r.confidence}</Tag><Tag>model {r.model.name}</Tag></p>
            <p>{r.summary}</p>
            {r.severity_assessment && (
                <p className="text-xs">Proposed severity <strong>{r.severity_assessment.proposed}</strong> (uncertainty {r.severity_assessment.uncertainty})
                    {r.severity_assessment.agrees_with_stored === false && <span className="text-red"> — disagrees with the stored (authoritative) severity, which stands</span>}</p>
            )}
            <ul className="list-disc pl-5 text-xs">{r.statements.map((s, i) => <li key={i}>{s.text} <span className="text-foreground-muted">[{s.citation_ids.join(', ')}]</span></li>)}</ul>
            {r.missing_evidence.length > 0 && <details className="text-xs"><summary>Missing evidence ({r.missing_evidence.length})</summary><ul className="list-disc pl-5">{r.missing_evidence.map((g) => <li key={g}>{g}</li>)}</ul></details>}
            {r.validation_notes.length > 0 && <details className="text-xs"><summary>Deterministic checks applied ({r.validation_notes.length})</summary><ul className="list-disc pl-5">{r.validation_notes.map((g) => <li key={g}>{g}</li>)}</ul></details>}
            {r.limitations.length > 0 && <p className="text-[11px] text-foreground-muted">Limitations: {r.limitations.join(' ')}</p>}
            {r.review ? <p className="text-xs"><StatusPill tone={r.review.decision === 'reject' ? 'critical' : 'good'} label={`${r.review.decision} by ${r.review.reviewer.label}`} /> {r.review.note}</p>
                : can('nhai:review') && (
                    <div className="flex flex-wrap items-end gap-2">
                        <Field label="Review note"><TextInput value={note} onChange={(e) => setNote(e.target.value)} /></Field>
                        <button className={btn('primary')} onClick={() => void review('accept')} data-testid="nhai-accept">Accept draft</button>
                        <button className={btn('secondary')} disabled={note.trim().length < 3} onClick={() => void review('reject')}>Reject</button>
                    </div>
                )}
            <Notice msg={msg} />
        </div>
    );
}

export function AlertIntelPanel({ alertId }: { alertId: string }) {
    const { orgId, can } = useSession();
    const matches = useResource(useCallback(() => (can('intel:read') ? insightsApi.matches(orgId, alertId) : Promise.resolve({ items: [] })), [orgId, alertId, can]));
    const jobs = useResource(useCallback(() => (can('nhai:analyze') ? nhaiApi.jobs(orgId, alertId) : Promise.resolve({ items: [] as NhaiJob[] })), [orgId, alertId, can]));
    const evidence = useResource(useCallback(() => socApi.evidence(orgId, alertId), [orgId, alertId]));
    const [msg, setMsg] = useState<Msg>(null);
    async function explain() {
        setMsg(null);
        try { await nhaiApi.explain(orgId, alertId); jobs.reload(); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    const job = jobs.data?.items[0];
    return (
        <div className="grid gap-5 lg:grid-cols-[repeat(2,minmax(0,1fr))]">
            <Loaded title="Threat Insights" hint="Deterministic indicator matches for this alert" data={matches.data} error={matches.error} testid="alert-ti">
                {(d) => d.items.length === 0 ? <p className="text-xs text-foreground-muted">No indicator of this organization matches this alert.</p> : (
                    <ul className="text-sm space-y-1">{d.items.map((m) => (
                        <li key={m.id}><Tag strong>{m.indicator.type}</Tag> <span className="font-mono wrap-any">{m.indicator.value}</span> <span className="text-xs text-foreground-muted">
                            from {m.observable.source_field} · {m.indicator.provenance.source} · confidence {m.confidence.score} ({m.confidence.band}) · {m.verdict}</span></li>))}</ul>
                )}
            </Loaded>
            <Loaded title="Novr Human-Assisted Intelligence (NHAI)" hint="A draft explanation for a human. It never changes the alert or acts."
                data={jobs.data} error={jobs.error} reload={jobs.reload} testid="alert-nhai"
                action={can('nhai:analyze') ? <button className={btn('secondary')} onClick={() => void explain()} data-testid="nhai-explain">{job ? 'Refresh / ask again' : 'Explain this alert'}</button> : undefined}>
                {() => (
                    <>
                        {!can('nhai:analyze') ? <p className="text-xs text-foreground-muted">Your role cannot request NHAI analysis.</p>
                            : job ? <NhaiResult job={job} onChange={() => jobs.reload()} /> : <p className="text-xs text-foreground-muted">No explanation requested yet.</p>}
                        <Notice msg={msg} />
                    </>
                )}
            </Loaded>
            <div className="lg:col-span-2">
                <Loaded title="Source evidence" hint="The original alert as read from its source by the API (redacted)" data={evidence.data} error={evidence.error} testid="alert-evidence">
                    {(ev) => (
                        <div className="space-y-2">
                            <p className="flex items-center gap-2 text-xs"><SourcePill state={ev.source.state} /> {ev.source.detail}</p>
                            {ev.document ? <EvidenceViewer items={[{ id: 'doc', title: 'Original document', content: ev.document }]} />
                                : <p className="flex items-start gap-1.5 text-xs text-foreground-muted"><Info className="w-3.5 h-3.5 mt-0.5" aria-hidden />No source document is available; the stored copy is shown above.</p>}
                        </div>
                    )}
                </Loaded>
            </div>
        </div>
    );
}
