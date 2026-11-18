'use client';

// The SOAR part of a case: deterministic playbook recommendations for the case's alerts and its runs.
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useState } from 'react';
import { Notice, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { newIdempotencyKey } from '@/foundation/api/paths';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, Loaded, TextInput, errorText } from '@/foundation/ui/pilot';
import { useResource } from '@/foundation/ui/useResource';
import { soarApi } from './api';

export function CaseSoarPanel({ caseId }: { caseId: string }) {
    const { orgId, can } = useSession();
    const router = useRouter();
    const recs = useResource(useCallback(() => soarApi.recommendations(orgId, caseId), [orgId, caseId]));
    const runs = useResource(useCallback(() => soarApi.runs(orgId, caseId), [orgId, caseId]));
    const [why, setWhy] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    async function start(playbookId: string, version: number, mode: 'dry_run' | 'live') {
        setMsg(null);
        try {
            const run = await soarApi.startRun(orgId, { idempotency_key: newIdempotencyKey('run'), playbook_id: playbookId, playbook_version: version,
                case_id: caseId, mode, justification: why.trim() });
            router.push(`/app/soar/runs/${run.id}`);
        } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <Loaded title="Response playbooks" hint="Recommended from the case's alerts. Consequential steps wait for another person's approval." data={recs.data} error={recs.error} reload={recs.reload} testid="case-soar">
            {(d) => (
                <div className="space-y-3 text-sm">
                    {d.items.length === 0 ? <p className="text-xs text-foreground-muted">No playbook matches this case&apos;s alerts.</p> : d.items.map((r) => (
                        <div key={r.playbook.id} className="border border-border rounded-xl p-3" data-recommended={r.playbook.name}>
                            <p className="font-semibold">{r.playbook.title} <span className="text-[11px] text-foreground-muted">({r.matched_on.join('; ')})</span></p>
                            <p className="flex flex-wrap gap-1 mt-1 min-w-0">{r.playbook.steps.map((s) => <span key={s.step_key} className="wrap-any max-w-full"><Tag>{s.action}{r.proposed_targets[s.step_key] ? ` → ${r.proposed_targets[s.step_key]}` : ''}</Tag></span>)}</p>
                            {can('response:contain') && (
                                <div className="flex flex-wrap items-end gap-2 mt-2">
                                    <Field label="Justification (10+ characters, shown to the approver)"><TextInput value={why} onChange={(e) => setWhy(e.target.value)} data-testid="run-justification" /></Field>
                                    <button className={btn('primary')} disabled={why.trim().length < 10} onClick={() => void start(r.playbook.id, r.playbook.version, 'dry_run')} data-testid="run-dry">Run (dry run)</button>
                                    <button className={btn('secondary')} disabled={why.trim().length < 10} onClick={() => void start(r.playbook.id, r.playbook.version, 'live')} data-testid="run-live">Run (live)</button>
                                </div>
                            )}
                        </div>
                    ))}
                    {runs.data && runs.data.items.length > 0 && (
                        <ul className="text-xs space-y-1">{runs.data.items.map((r) => (
                            <li key={r.id}><Link className="underline" href={`/app/soar/runs/${r.id}`}>{r.playbook_name} ({r.mode})</Link> <StatusPill tone={r.state === 'succeeded' ? 'good' : r.state === 'failed' ? 'critical' : 'warning'} label={r.state.replace('_', ' ')} /></li>))}</ul>
                    )}
                    <Notice msg={msg} />
                </div>
            )}
        </Loaded>
    );
}
