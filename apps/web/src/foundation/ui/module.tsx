'use client';

// Shared building blocks for the consolidated module pages: internal tabs, explainable measurements, an action runner
// with an honest result message, and small labelled state tags.
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { useState, type ReactNode } from 'react';
import { Notice, type Msg } from '@/components/features/vms/kit';
import { StatusPill, Unavailable, type Tone } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { useSession } from '@/foundation/session/SessionProvider';
import { errorText } from '@/foundation/ui/pilot';

export interface ModuleTab { href: string; label: string; permission?: string; exact?: boolean }

/** Internal module navigation (sub-pages are tabs, never extra sidebar entries). */
export function ModuleTabs({ tabs, label }: { tabs: ModuleTab[]; label: string }) {
    const pathname = usePathname() ?? '';
    const { can } = useSession();
    const visible = tabs.filter((t) => !t.permission || can(t.permission));
    const active = visible.filter((t) => (t.exact ? pathname === t.href : pathname === t.href || pathname.startsWith(`${t.href}/`)))
        .sort((a, b) => b.href.length - a.href.length)[0];
    return (
        <nav aria-label={label} className="flex gap-1 overflow-x-auto border-b border-border -mt-2 mb-2" data-testid="module-tabs">
            {visible.map((t) => {
                const on = active?.href === t.href;
                return (
                    <Link key={t.href} href={t.href} aria-current={on ? 'page' : undefined}
                        className={`px-3 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors ${on ? 'border-purple text-purple font-semibold'
                            : 'border-transparent text-foreground-muted hover:text-foreground'}`}>{t.label}</Link>
                );
            })}
        </nav>
    );
}

type Measure = Schemas['Measure'];

const fmtValue = (m: Measure) => (m.value === null || m.value === undefined ? null
    : m.unit === 'percent' ? `${m.value}%` : Number.isInteger(m.value) ? String(m.value) : m.value.toFixed(1));

/** One explainable measurement: value, how it was computed, and the records behind it; never a made-up figure. */
export function MeasureTile({ m, testid }: { m: Measure; testid?: string }) {
    const v = fmtValue(m);
    const body = (
        <>
            <p className="text-[11px] font-semibold text-foreground-muted leading-tight">{m.label}</p>
            <div className="mt-2 text-[24px] leading-none font-black tracking-tight text-foreground tabular-nums">
                {m.state === 'ok' && v !== null ? v : <Unavailable reason={m.reason || (m.state === 'not_permitted' ? 'Not permitted for your role' : 'Unavailable')} />}
            </div>
            <p className="mt-2 text-[11px] text-foreground-muted leading-snug">
                {m.state === 'ok' && m.denominator ? `${m.numerator} of ${m.denominator}` : m.state === 'not_permitted' ? 'Not permitted for your role' : m.reason}
            </p>
            {m.formula && <p className="mt-1 text-[10px] text-foreground-muted/80 leading-snug" title={m.formula}>{m.formula}</p>}
        </>
    );
    const cls = 'block bg-card border border-border rounded-2xl p-4 min-h-28';
    return m.evidence_href && m.state === 'ok'
        ? <Link href={m.evidence_href} className={`${cls} hover:border-purple/40`} data-testid={testid} data-state={m.state}>{body}</Link>
        : <div className={cls} data-testid={testid} data-state={m.state}>{body}</div>;
}

/** Runs one user action and shows its outcome (the API's own message on failure). */
export function useAction() {
    const [msg, setMsg] = useState<Msg>(null);
    const [busy, setBusy] = useState(false);
    async function run<T>(fn: () => Promise<T>, ok?: string | ((r: T) => string)): Promise<T | undefined> {
        setMsg(null); setBusy(true);
        try {
            const r = await fn();
            if (ok) setMsg({ ok: true, text: typeof ok === 'function' ? ok(r) : ok });
            return r;
        } catch (e) { setMsg({ ok: false, text: errorText(e) }); return undefined; } finally { setBusy(false); }
    }
    return { msg, setMsg, busy, run, notice: <Notice msg={msg} /> };
}

export const TONE: Record<string, Tone> = {
    ok: 'good', active: 'good', approved: 'good', met: 'good', verified: 'good', completed: 'good', succeeded: 'good', acknowledged: 'good', on_track: 'good',
    available: 'good', up: 'good', monitored: 'good',
    draft: 'neutral', validated: 'neutral', retired: 'neutral', unknown: 'neutral', unconfigured: 'neutral', not_run: 'neutral', no_policy: 'neutral',
    submitted: 'warning', pending_approval: 'warning', at_risk: 'warning', degraded: 'warning', assessing: 'warning', in_progress: 'warning',
    pending: 'warning', partial: 'warning', suspected: 'warning', expired: 'warning', local_fixture: 'warning', not_yet_valid: 'warning',
    breached: 'critical', failing: 'critical', failed: 'critical', rejected: 'critical', revoked: 'serious', not_recoverable: 'serious', down: 'critical',
    unmonitored: 'serious', refused: 'serious',
};

export function StateTag({ state, label }: { state: string; label?: string }) {
    return <StatusPill tone={TONE[state] ?? 'neutral'} label={label ?? state.replace(/_/g, ' ')} />;
}

export function Grid({ children, cols = 4 }: { children: ReactNode; cols?: 2 | 3 | 4 | 5 }) {
    const c = { 2: 'sm:grid-cols-2', 3: 'sm:grid-cols-2 lg:grid-cols-3', 4: 'sm:grid-cols-2 lg:grid-cols-4', 5: 'sm:grid-cols-2 lg:grid-cols-5' }[cols];
    return <div className={`grid grid-cols-1 ${c} gap-3`}>{children}</div>;
}

export const selectCls = 'bg-card border border-border rounded-lg px-2.5 py-1.5 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-purple/40';

/** A query-string value read once on the client (pages render only after the session loads in the browser). */
export function initialParam(name: string): string {
    if (typeof window === 'undefined') return '';
    return new URLSearchParams(window.location.search).get(name) ?? '';
}
