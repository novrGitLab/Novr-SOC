'use client';

// The organization's response authorization policy: allowed actions, authorized Wazuh groups, live mode, approval
// expiry, execution limits. Empty allow-lists mean nothing consequential may run.
import { useCallback, useState, type FormEvent } from 'react';
import { Scale } from 'lucide-react';
import { PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { StatusPill } from '@/components/features/vms/ui';
import { useSession } from '@/foundation/session/SessionProvider';
import { Field, Loaded, TextInput } from '@/foundation/ui/pilot';
import { useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { soarApi, type Policy } from '../api';

const CONSEQUENTIAL = ['block_ip', 'isolate_agent', 'disable_account'] as const;
type Draft = { actions: Set<string>; groups: string; live: boolean; ttl: number; perHour: number; attempts: number };

export default function SoarPolicyPage() {
    const { orgId, can } = useSession();
    const policy = useResource(useCallback(() => soarApi.policy(orgId), [orgId]));
    const [d, setD] = useState<Draft | null>(null);
    const act = useAction();
    const edit = (p: Policy) => setD({ actions: new Set(p.allowed_actions), groups: p.allowed_agent_groups.join(', '), live: p.live_enabled,
        ttl: p.approval_ttl_minutes, perHour: p.max_runs_per_hour ?? 20, attempts: p.max_dispatch_attempts ?? 3 });

    async function save(e: FormEvent) {
        e.preventDefault(); if (!d) return;
        const r = await act.run(() => soarApi.setPolicy(orgId, {
            allowed_actions: [...d.actions] as Policy['allowed_actions'], allowed_agent_groups: d.groups.split(',').map((g) => g.trim()).filter(Boolean),
            live_enabled: d.live, approval_ttl_minutes: d.ttl, max_runs_per_hour: d.perHour, max_dispatch_attempts: d.attempts,
        }), 'Response policy saved.');
        if (r) { policy.reload(); setD(null); }
    }

    return (
        <>
            <PageHeader title="Response policy" icon={Scale}
                description="What this organization authorizes SOAR to request from the Server 1 bridge. The bridge applies its own authorization as well; both must agree, and a person approves every step." />
            {act.notice}
            <Loaded title="Policy" data={policy.data} error={policy.error} reload={policy.reload} testid="soar-policy">
                {(p) => d === null ? (
                    <div className="text-sm space-y-2">
                        <p>Allowed actions: {p.allowed_actions.length ? p.allowed_actions.map((a) => <Tag key={a}>{a}</Tag>) : <em className="text-foreground-muted">none</em>}</p>
                        <p>Authorized Wazuh groups: {p.allowed_agent_groups.length ? p.allowed_agent_groups.map((g) => <Tag key={g}>{g}</Tag>) : <em className="text-foreground-muted">none</em>}</p>
                        <p>Live execution: <StatusPill tone={p.live_enabled ? 'warning' : 'neutral'} label={p.live_enabled ? 'enabled (still needs approval)' : 'disabled (dry runs only)'} /></p>
                        <p>Approvals expire after {p.approval_ttl_minutes} min · at most {p.max_runs_per_hour} runs per hour · {p.max_dispatch_attempts} dispatch attempts per step</p>
                        <p>Emergency stop: <StatusPill tone={p.emergency_stop ? 'critical' : 'good'} label={p.emergency_stop ? `ON: ${p.emergency_reason}` : 'not active'} /></p>
                        {can('soar:manage') && <button className={btn('secondary')} onClick={() => edit(p)}>Edit policy</button>}
                    </div>
                ) : (
                    <form onSubmit={save} className="grid gap-3 text-xs max-w-xl">
                        <div className="flex flex-wrap gap-3">{CONSEQUENTIAL.map((a) => (
                            <label key={a} className="flex items-center gap-1"><input type="checkbox" checked={d.actions.has(a)} onChange={() => {
                                const s = new Set(d.actions); if (s.has(a)) s.delete(a); else s.add(a); setD({ ...d, actions: s });
                            }} />{a}</label>))}</div>
                        <Field label="Authorized Wazuh agent groups (comma separated)"><TextInput value={d.groups} onChange={(e) => setD({ ...d, groups: e.target.value })} /></Field>
                        <label className="flex items-center gap-1"><input type="checkbox" checked={d.live} onChange={() => setD({ ...d, live: !d.live })} />Allow live execution (each step still needs approval)</label>
                        <div className="grid grid-cols-3 gap-2">
                            <Field label="Approval expiry (min)"><TextInput type="number" min={5} max={1440} value={d.ttl} onChange={(e) => setD({ ...d, ttl: Number(e.target.value) })} /></Field>
                            <Field label="Runs per hour"><TextInput type="number" min={1} max={500} value={d.perHour} onChange={(e) => setD({ ...d, perHour: Number(e.target.value) })} /></Field>
                            <Field label="Dispatch attempts"><TextInput type="number" min={1} max={10} value={d.attempts} onChange={(e) => setD({ ...d, attempts: Number(e.target.value) })} /></Field>
                        </div>
                        <div className="flex gap-2"><button className={btn('primary')} type="submit" disabled={act.busy}>Save</button><button className={btn('ghost')} type="button" onClick={() => setD(null)}>Cancel</button></div>
                    </form>
                )}
            </Loaded>
        </>
    );
}
