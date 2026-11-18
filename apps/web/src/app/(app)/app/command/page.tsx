'use client';

// NovrSOC Command Center: every organization's security operations in one place, for platform staff. Records are read
// by the API inside each organization's own access rules and labelled with their owner; nothing is copied. Platform
// administrators see every organization; platform SOC staff see the organizations they are assigned to. Opening a record
// switches into its organization (audited by the API) and shows the record in that organization's own workspace.
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { useCallback, useState } from 'react';
import { Download, Globe2 } from 'lucide-react';
import { PageHeader, SearchBox, Tag, btn, nf } from '@/components/features/vms/kit';
import { Card, StatusPill, Unavailable, type Tone } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { commandApi, type CommandQuery, type CommandView } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, errorText, fmt } from '@/foundation/ui/pilot';
import { StateTag, initialParam, selectCls } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';

type Rec = Schemas['CommandRecord'];
type Posture = Schemas['OrgPosture'];
type Tab = 'overview' | CommandView;

const LABEL: Record<CommandView, string> = {
    alerts: 'Alerts', assets: 'Assets', vulnerabilities: 'Vulnerabilities', scans: 'Scans', cases: 'Cases', intel: 'Intelligence matches',
    nhai: 'NHAI analyses', soar_runs: 'SOAR runs', soar_approvals: 'Approvals', reports: 'Reports',
};
const ORDER: CommandView[] = ['alerts', 'cases', 'vulnerabilities', 'scans', 'assets', 'intel', 'nhai', 'soar_runs', 'soar_approvals', 'reports'];
const HAS_SEVERITY: CommandView[] = ['alerts', 'assets', 'vulnerabilities', 'cases', 'intel'];
const POSTURE: Record<Posture['posture'], { label: string; tone: Tone }> = {
    critical: { label: 'Critical', tone: 'critical' }, elevated: { label: 'Elevated', tone: 'warning' },
    normal: { label: 'Normal', tone: 'good' }, no_data: { label: 'No data yet', tone: 'neutral' },
};
const SEV_TONE: Record<string, Tone> = { critical: 'critical', high: 'serious', medium: 'warning', low: 'neutral' };

/** Where a record opens, inside its organization's own workspace. */
function detailHref(view: CommandView, r: Rec): string {
    switch (view) {
        case 'alerts': return `/app/alerts/${r.id}`;
        case 'cases': return `/app/cases/${r.id}`;
        case 'assets': return `/app/assets/${r.id}`;
        case 'vulnerabilities': return `/app/vms/findings?finding=${r.id}`;
        case 'scans': return '/app/vms/scans';
        case 'intel': return '/app/insights';
        case 'nhai': return '/app/nhai';
        case 'soar_runs': return `/app/soar/runs/${r.id}`;
        case 'soar_approvals': return '/app/soar/approvals';
        case 'reports': return `/app/reports/${r.id}`;
    }
}

/** The view's most useful columns, from the documented `fields`. */
function detail(view: CommandView, f: Record<string, unknown>): string {
    const s = (k: string) => (f[k] === null || f[k] === undefined || f[k] === '' ? null : String(f[k]));
    const parts: (string | null)[] = {
        alerts: [s('agent_name') ?? s('log_source'), s('rule_id') && `rule ${s('rule_id')}`, s('src_ip')],
        assets: [s('kind'), s('primary_ip'), s('os_name'), s('exposure')],
        vulnerabilities: [s('host') && `${s('host')}${s('port') ? `:${s('port')}` : ''}`, s('priority'), s('risk_score') && `risk ${s('risk_score')}`,
            Array.isArray(f.cves) && f.cves.length ? (f.cves as string[]).slice(0, 3).join(', ') : null],
        scans: [s('origin'), s('activity'), s('targets') && `${s('targets')} target(s)`, s('error')],
        cases: [s('number') && `CASE-${String(s('number')).padStart(6, '0')}`, s('source'), s('sla_resolution_due_at') && `due ${fmt(s('sla_resolution_due_at'))}`],
        intel: [s('observable_type') && `${s('observable_type')}=${s('observable_value')}`, s('confidence') && `confidence ${s('confidence')}`, s('source')],
        nhai: [s('requested_label'), s('error_code'), s('review_decision') && `review: ${s('review_decision')}`],
        soar_runs: [s('mode'), s('playbook') && `${s('playbook')} v${s('playbook_version')}`, s('requested_label')],
        soar_approvals: [s('requested_label') && `requested by ${s('requested_label')}`, s('decided_label') && `decided by ${s('decided_label')}`,
            s('expires_at') && `expires ${fmt(s('expires_at'))}`],
        reports: [s('format'), s('period_start') && `${fmt(s('period_start'))} – ${fmt(s('period_end'))}`, s('failure_reason')],
    }[view];
    return parts.filter(Boolean).join(' · ');
}

export default function CommandCenterPage() {
    const { switchOrg } = useSession();
    const router = useRouter();
    const scope = useResource(useCallback(() => commandApi.scope(), []));
    const [tab, setTabState] = useState<Tab>(() => (initialParam('view') as Tab) || 'overview');
    const [q, setQ] = useState<CommandQuery>({ sort: 'recent', limit: 200 });
    const setTab = (t: Tab) => {
        setTabState(t);
        try { window.history.replaceState(null, '', `${window.location.pathname}${t === 'overview' ? '' : `?view=${t}`}`); } catch { /* ignore */ }
    };
    const open = (view: CommandView, r: Rec) => { switchOrg(r.org.id); router.push(detailHref(view, r)); };

    if (scope.error) {
        return <><PageHeader title="Command Center" icon={Globe2} /><Card><Unavailable reason={errorText(scope.error)} /></Card></>;
    }
    const views = ORDER.filter((v) => scope.data?.views.includes(v));
    return (
        <>
            <PageHeader title="Command Center" icon={Globe2}
                description={scope.data ? <>{scope.data.scope === 'platform' ? 'Every organization' : 'Your assigned organizations'} ({scope.data.organizations.length}).
                    Each organization&apos;s records are read under its own access rules and labelled with their owner; every view is audited.</> : undefined}
                meta={<Link href="/app/admin/health" className="text-xs underline text-foreground-muted">Platform health</Link>} />
            <nav aria-label="Command Center views" role="tablist" className="flex gap-1 overflow-x-auto border-b border-border -mt-2 mb-2" data-testid="command-tabs">
                {(['overview', ...views] as Tab[]).map((k) => (
                    <button key={k} role="tab" aria-selected={tab === k} onClick={() => setTab(k)} data-tab={k}
                        className={`px-3 py-2 text-sm whitespace-nowrap border-b-2 -mb-px transition-colors ${tab === k ? 'border-purple text-purple font-semibold' : 'border-transparent text-foreground-muted hover:text-foreground'}`}>
                        {k === 'overview' ? 'Overview' : LABEL[k]}</button>
                ))}
            </nav>
            {scope.data && (tab === 'overview'
                ? <Overview onPick={(org) => { setQ({ ...q, org }); setTab('alerts'); }} />
                : <ViewPanel key={tab} view={tab} scope={scope.data} q={q} setQ={setQ} open={open} />)}
        </>
    );
}

function Overview({ onPick }: { onPick: (org: string) => void }) {
    const ov = useResource(useCallback(() => commandApi.overview(), []));
    const tiles: [string, string][] = [['organizations', 'Organizations'], ['posture_critical', 'Critical posture'], ['critical_alerts_24h', 'Critical alerts (24 h)'],
        ['open_cases', 'Open cases'], ['critical_findings', 'Critical findings'], ['soar_pending_approvals', 'Approvals waiting'],
        ['nhai_awaiting_review', 'NHAI drafts to review'], ['scans_running', 'Scans running']];
    return (
        <Loaded title="" data={ov.data} error={ov.error} reload={ov.reload} testid="command-overview">
            {(d) => (
                <>
                    <div className="grid gap-3 grid-cols-2 lg:grid-cols-4">
                        {tiles.map(([k, label]) => (
                            <Card key={k} className="!p-4"><p className="text-[11px] uppercase tracking-wide text-foreground-muted">{label}</p>
                                <p className="text-2xl font-bold" data-testid={`command-total-${k}`}>{nf.format(d.totals[k] ?? 0)}</p></Card>
                        ))}
                    </div>
                    <Card className="mt-4">
                        <DataTable testid="command-organizations" rows={d.organizations} rowKey={(r) => r.org.id} empty="No organization in your scope." columns={[
                            { key: 'o', header: 'Organization', render: (r) => <button className="text-left underline-offset-2 hover:underline" onClick={() => onPick(r.org.id)}>
                                <strong>{r.org.name}</strong><span className="block text-[11px] text-foreground-muted">{r.org.slug} · {r.org.kind}{r.org.status !== 'active' ? ` · ${r.org.status}` : ''}</span></button> },
                            { key: 'p', header: 'Posture', render: (r) => <span><StatusPill tone={POSTURE[r.posture].tone} label={POSTURE[r.posture].label} />
                                {r.posture_reasons.length > 0 && <span className="block text-[11px] text-foreground-muted">{r.posture_reasons.slice(0, 2).join('; ')}</span>}</span> },
                            { key: 'a', header: 'Alerts (24 h)', render: (r) => <span className="text-xs">{nf.format(r.alerts_24h)}<span className="block text-foreground-muted">{r.critical_alerts_24h} critical · {r.high_alerts_24h} high</span></span> },
                            { key: 'c', header: 'Cases', render: (r) => <span className="text-xs">{r.open_cases} open{r.critical_cases ? ` · ${r.critical_cases} critical` : ''}</span> },
                            { key: 'v', header: 'Vulnerabilities', render: (r) => <span className="text-xs">{r.open_findings} open · {r.critical_findings} critical{r.overdue_remediation ? ` · ${r.overdue_remediation} overdue` : ''}
                                <span className="block text-foreground-muted">scan policy {r.scan_policy_enabled ? 'enabled' : 'off'}</span></span> },
                            { key: 'i', header: 'Intel / NHAI / SOAR', render: (r) => <span className="text-xs">{r.intel_matches_7d} matches (7 d) · {r.nhai_queued} NHAI queued
                                <span className="block text-foreground-muted">{r.soar_pending_approvals} approvals · {r.soar_runs_7d} runs (7 d)</span></span> },
                            { key: 'l', header: 'Last alert', render: (r) => <span className="text-xs">{fmt(r.last_alert_at)}</span> },
                        ]} />
                    </Card>
                </>
            )}
        </Loaded>
    );
}

function ViewPanel({ view, scope, q, setQ, open }: { view: CommandView; scope: Schemas['CommandScope']; q: CommandQuery; setQ: (q: CommandQuery) => void;
    open: (view: CommandView, r: Rec) => void }) {
    const list = useResource(useCallback(() => commandApi.view(view, q), [view, q]));
    const [busy, setBusy] = useState(false);
    const [err, setErr] = useState<string | null>(null);
    const switchable = new Set(scope.organizations.filter((o) => o.status === 'active').map((o) => o.id));
    async function exportCsv() {
        setBusy(true); setErr(null);
        try {
            const r = await fetch(commandApi.exportPath(view, q), { credentials: 'same-origin', cache: 'no-store' });
            if (!r.ok) throw new Error(`Export refused (${r.status})`);
            const url = URL.createObjectURL(await r.blob());
            const a = document.createElement('a');
            a.href = url; a.download = `novrsoc-${view}.csv`; a.click();
            URL.revokeObjectURL(url);
        } catch (e) { setErr(errorText(e)); } finally { setBusy(false); }
    }
    return (
        <>
            <div className="flex flex-wrap items-end gap-2" data-testid="command-filters">
                <Field label="Organization"><select className={selectCls} value={q.org ?? ''} onChange={(e) => setQ({ ...q, org: e.target.value || undefined })}>
                    <option value="">All in scope</option>{scope.organizations.map((o) => <option key={o.id} value={o.id}>{o.name}</option>)}</select></Field>
                {HAS_SEVERITY.includes(view) && (
                    <Field label="Severity"><select className={selectCls} value={q.severity ?? ''} onChange={(e) => setQ({ ...q, severity: e.target.value || undefined })}>
                        <option value="">Any</option>{['critical', 'high', 'medium', 'low'].map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
                )}
                <Field label="Window"><select className={selectCls} value={q.since_hours ?? ''} onChange={(e) => setQ({ ...q, since_hours: e.target.value ? Number(e.target.value) : undefined })}>
                    <option value="">All time</option><option value="24">24 hours</option><option value="168">7 days</option><option value="720">30 days</option></select></Field>
                <Field label="Sort"><select className={selectCls} value={q.sort ?? 'recent'} onChange={(e) => setQ({ ...q, sort: e.target.value as 'recent' | 'severity' })}>
                    <option value="recent">Most recent</option>{HAS_SEVERITY.includes(view) && <option value="severity">Highest severity</option>}</select></Field>
                <SearchBox value={q.q ?? ''} onSubmit={(v) => setQ({ ...q, q: v || undefined })} placeholder={`Search ${LABEL[view].toLowerCase()}`} label={`Search ${LABEL[view]}`} />
                {scope.can_export && <button className={btn('secondary')} disabled={busy} onClick={() => void exportCsv()} data-testid="command-export">
                    <Download className="w-3.5 h-3.5" aria-hidden />Export CSV</button>}
            </div>
            {err && <p className="text-xs text-red-600" role="alert">{err}</p>}
            <Loaded title={LABEL[view]} hint={list.data ? `${list.data.items.length} shown${list.data.truncated ? ' (more match: narrow the filters)' : ''}` : undefined}
                data={list.data} error={list.error} reload={list.reload} testid={`command-${view}`}>
                {(d) => (
                    <DataTable rows={d.items} rowKey={(r) => `${r.org.id}:${r.id}`} empty="No matching records in your scope." columns={[
                        { key: 'o', header: 'Organization', render: (r) => <span className="text-xs"><strong>{r.org.name}</strong><span className="block text-foreground-muted">{r.org.slug}</span></span> },
                        { key: 'w', header: 'When', render: (r) => <span className="text-xs whitespace-nowrap">{fmt(r.at)}</span> },
                        { key: 't', header: 'Record', render: (r) => <span><span className="text-sm">{r.title}</span><span className="block text-[11px] text-foreground-muted">{detail(view, r.fields)}</span></span> },
                        { key: 's', header: 'Severity', render: (r) => (r.severity ? <StatusPill tone={SEV_TONE[r.severity] ?? 'neutral'} label={r.severity} /> : <span className="text-foreground-muted">—</span>) },
                        { key: 'st', header: 'Status', render: (r) => (r.status ? <StateTag state={r.status} /> : <Tag>—</Tag>) },
                        { key: 'x', header: '', render: (r) => (switchable.has(r.org.id)
                            ? <button className={btn('secondary')} onClick={() => open(view, r)} data-testid="command-open">Open</button>
                            : <span className="text-[11px] text-foreground-muted">{r.org.status}</span>) },
                    ]} />
                )}
            </Loaded>
        </>
    );
}
