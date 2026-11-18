'use client';

// The organization's automation policy: whether new alerts open cases and start approved automatic playbooks, which
// consequential actions are pre-authorized (no per-event approval) and under which guards. The API validates every
// rule (pre-authorized actions must be allowed actions; protected targets must be addresses, networks, agent ids or
// accounts); this panel only shows the policy and collects changes.
import { useState, type FormEvent } from 'react';
import { Tag, btn } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { policyBody, soarApi, type Policy } from '../api';

type Auto = Required<Schemas['SoarAutomationPolicy']>;
const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;

/** The policy's automation with the API's defaults filled in (an organization without a policy row has none). */
export function automationOf(p: Policy): Auto {
    const a: Partial<Auto> = p.automation ?? {};
    return { enabled: a.enabled ?? false, case_creation: a.case_creation ?? false, case_min_severity: a.case_min_severity ?? 'high',
        pre_authorized_actions: a.pre_authorized_actions ?? [], min_confidence: a.min_confidence ?? 80,
        max_dispatches_per_hour: a.max_dispatches_per_hour ?? 20, protected_targets: a.protected_targets ?? [] };
}

export function AutomationPanel({ p, onSaved }: { p: Policy; onSaved: () => void }) {
    const { orgId, can } = useSession();
    const a = automationOf(p);
    const [d, setD] = useState<(Auto & { protectedText: string }) | null>(null);
    const act = useAction();
    async function save(e: FormEvent) {
        e.preventDefault(); if (!d) return;
        const { protectedText, ...auto } = d;
        const body = policyBody(p, { ...auto, protected_targets: protectedText.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean) });
        const r = await act.run(() => soarApi.setPolicy(orgId, body), 'Automation policy saved.');
        if (r) { setD(null); onSaved(); }
    }
    if (!d) return (
        <div className="text-sm space-y-2" data-testid="soar-automation">
            {act.notice}
            <p className="flex flex-wrap items-center gap-2">Automatic playbooks:
                <StatusPill tone={a.enabled ? 'warning' : 'neutral'} label={a.enabled ? 'on' : 'off'} />
                Automatic cases: <StatusPill tone={a.case_creation ? 'good' : 'neutral'} label={a.case_creation ? `on (${a.case_min_severity} and above)` : 'off'} />
                {p.automation_since && <span className="text-xs text-foreground-muted">only alerts received since {fmt(p.automation_since)}</span>}</p>
            <p>Pre-authorized (no per-event approval): {a.pre_authorized_actions.length
                ? a.pre_authorized_actions.map((x) => <Tag key={x}>{x}</Tag>) : <em className="text-foreground-muted">none: every consequential step waits for a person</em>}</p>
            <p className="text-xs text-foreground-muted">A pre-authorized step proceeds only when the detection confidence is at least {a.min_confidence}, the
                target comes from the alert itself, its NovrAgent groups are authorized, it is not a protected target, and fewer than {a.max_dispatches_per_hour} automatic
                dispatches happened in the last hour. Live execution still needs live mode above.</p>
            <p>Protected targets: {a.protected_targets.length ? a.protected_targets.map((x) => <Tag key={x}>{x}</Tag>) : <em className="text-foreground-muted">none</em>}</p>
            {can('soar:manage') && <button className={btn('secondary')} data-testid="automation-edit"
                onClick={() => setD({ ...a, protectedText: a.protected_targets.join('\n') })}>Edit automation</button>}
        </div>
    );
    const allowed = new Set<string>(p.allowed_actions);
    return (
        <form onSubmit={save} className="grid gap-3 text-xs max-w-xl" data-testid="automation-form">
            {act.notice}
            <label className="flex items-center gap-1"><input type="checkbox" checked={d.case_creation} onChange={() => setD({ ...d, case_creation: !d.case_creation })} />
                Open or join a case automatically for new alerts of</label>
            <Field label="Minimum alert severity for an automatic case"><select className={selectCls} value={d.case_min_severity}
                onChange={(e) => setD({ ...d, case_min_severity: e.target.value as Auto['case_min_severity'] })}>
                {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
            <label className="flex items-center gap-1"><input type="checkbox" checked={d.enabled} onChange={() => setD({ ...d, enabled: !d.enabled })} data-testid="automation-enabled" />
                Start approved automatic playbooks on matching new alerts</label>
            <div className="flex flex-wrap gap-3">Pre-authorized actions:{(['block_ip', 'isolate_agent', 'disable_account'] as const).map((x) => (
                <label key={x} className={`flex items-center gap-1 ${allowed.has(x) ? '' : 'opacity-50'}`} title={allowed.has(x) ? '' : 'Not an allowed action of this policy'}>
                    <input type="checkbox" disabled={!allowed.has(x)} checked={d.pre_authorized_actions.includes(x)} onChange={() => setD({
                        ...d, pre_authorized_actions: d.pre_authorized_actions.includes(x) ? d.pre_authorized_actions.filter((y) => y !== x) : [...d.pre_authorized_actions, x] })} />{x}</label>))}</div>
            <div className="grid grid-cols-2 gap-2">
                <Field label="Minimum detection confidence (0-100)"><TextInput type="number" min={0} max={100} value={d.min_confidence}
                    onChange={(e) => setD({ ...d, min_confidence: Math.max(0, Math.min(100, Number(e.target.value) || 0)) })} /></Field>
                <Field label="Automatic dispatches per hour"><TextInput type="number" min={1} max={500} value={d.max_dispatches_per_hour}
                    onChange={(e) => setD({ ...d, max_dispatches_per_hour: Math.max(1, Math.min(500, Number(e.target.value) || 1)) })} /></Field>
            </div>
            <Field label="Protected targets: IP addresses, networks (CIDR), NovrAgent ids or account names; one per line">
                <textarea className="min-h-24 rounded-lg border border-border bg-card p-2 font-mono text-xs" value={d.protectedText}
                    onChange={(e) => setD({ ...d, protectedText: e.target.value })} /></Field>
            <div className="flex gap-2"><button className={btn('primary')} type="submit" disabled={act.busy}>Save automation</button>
                <button className={btn('ghost')} type="button" onClick={() => setD(null)}>Cancel</button></div>
        </form>
    );
}
