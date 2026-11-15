'use client';

// One SOAR approval: shows the action, target and justification; another person with response:approve decides.
import { useState } from 'react';
import { Notice, Tag, btn, type Msg } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, TextInput, errorText, fmt } from '@/foundation/ui/pilot';
import { soarApi, type Approval } from './api';

export function ApprovalRow({ a, onDone }: { a: Approval; onDone: () => void }) {
    const { orgId, can, session } = useSession();
    const [reason, setReason] = useState('');
    const [msg, setMsg] = useState<Msg>(null);
    const mine = a.requested_by.id === session.user.id;
    async function decide(d: 'approve' | 'reject') {
        setMsg(null);
        try { await soarApi.decide(orgId, a.id, d, reason.trim()); onDone(); } catch (e) { setMsg({ ok: false, text: errorText(e) }); }
    }
    return (
        <li className="py-3 flex flex-col gap-2" data-approval-id={a.id}>
            <p className="text-sm"><Tag strong>{a.action}</Tag> <span className="font-mono">{a.target}</span> <span className="text-foreground-muted text-xs">requested by {a.requested_by.label} · expires {fmt(a.expires_at)}</span></p>
            <p className="text-xs text-foreground-muted">{a.justification}</p>
            {a.decision ? <p className="text-xs"><StatusPill tone={a.decision === 'approve' ? 'good' : 'critical'} label={`${a.decision}d by ${a.decided_by?.label ?? ''}`} /> {a.reason}</p>
                : can('response:approve') && !mine ? (
                    <div className="flex flex-wrap items-end gap-2">
                        <Field label="Reason (recorded)"><TextInput value={reason} onChange={(e) => setReason(e.target.value)} maxLength={2000} data-testid="approval-reason" /></Field>
                        <button className={btn('primary')} disabled={reason.trim().length < 3} onClick={() => void decide('approve')} data-testid="approval-approve">Approve</button>
                        <button className={btn('secondary')} disabled={reason.trim().length < 3} onClick={() => void decide('reject')}>Reject</button>
                    </div>
                ) : <p className="text-[11px] text-foreground-muted">{mine ? 'You requested this; another person must decide.' : 'Your role cannot approve response actions.'}</p>}
            <Notice msg={msg} />
        </li>
    );
}
