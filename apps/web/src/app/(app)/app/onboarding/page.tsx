'use client';

// Guided onboarding of the active organization: NovrAgent on endpoints (one-hour installer commands for Windows, Linux
// and macOS), network devices over syslog (device guides, sender registration verified by NovrSOC), and progress:
// agent installation status, telemetry received, assets in the inventory shared with vulnerability management.
import Link from 'next/link';
import { useCallback, useState, type FormEvent } from 'react';
import { CheckCircle2, Circle, Copy, Rocket, TerminalSquare } from 'lucide-react';
import { PageHeader, Tag, btn, nf } from '@/components/features/vms/kit';
import { Card, StatusPill } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { onboardingApi, sourcesApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { DataTable, Field, Loaded, TextInput, fmt } from '@/foundation/ui/pilot';
import { selectCls, useAction } from '@/foundation/ui/module';
import { useResource } from '@/foundation/ui/useResource';
import { SOURCE_STATUS } from '../admin/_org/meta';
import { GUIDES } from './guides';

type Os = Schemas['InstallerRequest']['os'];
const OS: readonly (readonly [Os, string])[] = [['windows', 'Windows'], ['linux', 'Linux'], ['macos', 'macOS']];
const AGENT_STATE: Record<string, string> = { connected: 'Live', local_fixture: 'Local test data', unconfigured: 'Not connected yet',
                                              unavailable: 'Temporarily unavailable', error: 'Error' };

export default function OnboardingPage() {
    const { orgId, can, session } = useSession();
    const status = useResource(useCallback(() => onboardingApi.status(orgId), [orgId]));
    const sources = useResource(useCallback(() => sourcesApi.list(orgId), [orgId]));
    const tickets = useResource(useCallback(() => onboardingApi.tickets(orgId), [orgId]));
    return (
        <>
            <PageHeader title="Onboarding" icon={Rocket}
                description={`Connect ${session.active_org.name}'s endpoints and network devices to NovrSOC, and follow what has arrived.`} />
            <Loaded title="" data={status.data} error={status.error} reload={status.reload} testid="onboarding">
                {(d) => (
                    <>
                        <Progress d={d} />
                        <div className="grid gap-4 xl:grid-cols-2">
                            <Agents d={d} canManage={can('endpoints:manage')} onIssued={tickets.reload} />
                            <Telemetry d={d} />
                        </div>
                        <div className="grid gap-4 xl:grid-cols-2">
                            <Tickets list={tickets} canManage={can('endpoints:manage')} />
                            <AssetSync s={d.asset_sync} />
                        </div>
                        <Devices d={d} canManage={can('endpoints:manage')} sources={sources.data?.items ?? []}
                                 reload={() => { sources.reload(); status.reload(); }} />
                    </>
                )}
            </Loaded>
        </>
    );
}

function Progress({ d }: { d: Schemas['TenantOnboarding'] }) {
    return (
        <Card>
            <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
                <h2 className="font-bold">Progress</h2>
                <span className="text-xs text-foreground-muted" data-testid="onboarding-progress">{d.completed} of {d.total} done</span>
            </div>
            <ol className="grid gap-2 md:grid-cols-2 xl:grid-cols-3">
                {d.steps.map((s) => (
                    <li key={s.key} className="flex items-start gap-2 text-sm">
                        {s.done ? <CheckCircle2 className="w-4 h-4 mt-0.5 text-green shrink-0" aria-label="done" />
                            : <Circle className="w-4 h-4 mt-0.5 text-foreground-muted shrink-0" aria-label="to do" />}
                        <span>{s.label}{s.detail && <span className="block text-[11px] text-foreground-muted">{s.detail}</span>}</span>
                    </li>
                ))}
            </ol>
        </Card>
    );
}

function Agents({ d, canManage, onIssued }: { d: Schemas['TenantOnboarding']; canManage: boolean; onIssued: () => void }) {
    const { orgId } = useSession();
    const [os, setOs] = useState<Os>('windows');
    const [count, setCount] = useState(10);
    const [cmd, setCmd] = useState<Schemas['InstallerCommand'] | null>(null);
    const [copied, setCopied] = useState(false);
    const act = useAction();
    const a = d.agents;
    return (
        <Card>
            <h2 className="font-bold flex items-center gap-2 mb-1"><TerminalSquare className="w-4 h-4" aria-hidden />Endpoints: install NovrAgent</h2>
            <p className="text-xs text-foreground-muted mb-3">
                Agent data: {AGENT_STATE[a.state] ?? a.state} · {nf.format(a.total)} installed · {a.active} active · {a.disconnected} disconnected
                {a.never_connected ? ` · ${a.never_connected} never connected` : ''}</p>
            {d.enrollment && (
                <p className="text-xs text-foreground-muted mb-3" data-testid="enrollment-info">
                    NovrSOC registers each endpoint itself, in this organization&apos;s agent group; no password is used.
                    {d.enrollment.manager_version && ` NovrSIEM ${d.enrollment.manager_version}`}{d.enrollment.agent_version && ` · NovrAgent ${d.enrollment.agent_version}`}
                    {` · ${d.enrollment.enrolled_agents} enrolled · ${d.enrollment.open_tickets} open command(s)`}</p>
            )}
            {!d.installer_available ? <p className="text-sm" data-testid="installer-unavailable">{d.installer_reason}</p> : (
                <>
                    <div role="tablist" aria-label="Operating system" className="flex gap-1 mb-3">
                        {OS.map(([k, label]) => <button key={k} role="tab" aria-selected={os === k} className={btn(os === k ? 'primary' : 'secondary')}
                            onClick={() => { setOs(k); setCmd(null); }}>{label}</button>)}
                    </div>
                    {canManage ? (
                        <>
                            <div className="flex flex-wrap items-end gap-2">
                                <Field label="Endpoints this command may enroll"><TextInput type="number" min={1} max={500} value={count}
                                    onChange={(e) => setCount(Math.max(1, Math.min(500, Number(e.target.value) || 1)))} /></Field>
                                <button className={btn('primary')} disabled={act.busy} data-testid="installer-generate"
                                    onClick={() => void act.run(() => onboardingApi.installer(orgId, os, count), 'Installer command ready.').then((r) => { if (r) { setCmd(r); setCopied(false); onIssued(); } })}>
                                    Generate the {OS.find(([k]) => k === os)?.[1]} command</button>
                            </div>
                            {act.notice}
                            {cmd && (
                                <div className="mt-3 space-y-2" data-testid="installer-command">
                                    <p className="text-xs">Run in {cmd.run_as}. Valid until {fmt(cmd.expires_at)}.</p>
                                    <div className="flex items-start gap-2">
                                        <pre className="flex-1 text-[11px] font-mono whitespace-pre-wrap break-all bg-card-muted border border-border rounded-lg p-2">{cmd.command}</pre>
                                        <button className={btn('secondary')} aria-label="Copy the command"
                                            onClick={() => void navigator.clipboard?.writeText(cmd.command).then(() => setCopied(true))}><Copy className="w-3.5 h-3.5" aria-hidden />{copied ? 'Copied' : 'Copy'}</button>
                                    </div>
                                    <ul className="text-[11px] text-foreground-muted list-disc ml-4">{cmd.notes.map((n) => <li key={n}>{n}</li>)}</ul>
                                </div>
                            )}
                        </>
                    ) : <p className="text-xs text-foreground-muted">An organization administrator generates installer commands.</p>}
                </>
            )}
            <Link href="/app/endpoints" className="text-xs underline mt-3 inline-block">See every endpoint</Link>
        </Card>
    );
}

type TicketList = Schemas['AgentEnrollmentTicketList'];
function Tickets({ list, canManage }: { list: { data: TicketList | undefined; error: unknown; reload: () => void }; canManage: boolean }) {
    const { orgId } = useSession();
    const act = useAction();
    return (
        <Loaded title="Installer commands" hint="Each command enrolls a limited number of endpoints until it expires; revoke one at any time"
            data={list.data} error={list.error} reload={list.reload} testid="enrollment-tickets">
            {(d) => (
                <>
                    {act.notice}
                    <DataTable rows={d.items} rowKey={(t) => t.id} empty="No installer command generated yet." columns={[
                        { key: 'o', header: 'System', render: (t) => <Tag>{OS.find(([k]) => k === t.os)?.[1] ?? t.os}</Tag> },
                        { key: 'u', header: 'Endpoints', render: (t) => <span className="text-xs">{t.uses} of {t.max_uses}</span> },
                        { key: 's', header: 'State', render: (t) => <StatusPill tone={t.state === 'open' ? 'good' : 'neutral'} label={t.state.replace('_', ' ')} /> },
                        { key: 'e', header: 'Expires', render: (t) => <span className="text-xs">{fmt(t.expires_at)}<span className="block text-foreground-muted">{t.created_label}</span></span> },
                        { key: 'x', header: '', render: (t) => (canManage && t.state === 'open' ? <button className={btn('ghost')} disabled={act.busy}
                            onClick={() => void act.run(() => onboardingApi.revokeTicket(orgId, t.id), 'Command revoked.').then(() => list.reload())}>Revoke</button> : null) },
                    ]} />
                </>
            )}
        </Loaded>
    );
}

function AssetSync({ s }: { s: Schemas['TenantOnboarding']['asset_sync'] }) {
    return (
        <Card>
            <h2 className="font-bold mb-2">Asset inventory sync</h2>
            {!s ? <p className="text-sm text-foreground-muted">Not available.</p> : (
                <dl className="grid grid-cols-2 gap-3 text-sm" data-testid="asset-sync">
                    <div><dt className="text-[11px] text-foreground-muted">Schedule</dt><dd>{s.interval_minutes ? `Every ${s.interval_minutes} minutes` : 'On demand only'}</dd></div>
                    <div><dt className="text-[11px] text-foreground-muted">Next run</dt><dd>{fmt(s.next_due_at)}</dd></div>
                    <div><dt className="text-[11px] text-foreground-muted">Last run</dt><dd>{fmt(s.last_run_at)}</dd></div>
                    <div><dt className="text-[11px] text-foreground-muted">Outcome</dt><dd>{s.last_outcome ? <StatusPill tone={s.last_outcome === 'completed' ? 'good' : 'warning'} label={s.last_outcome.replace('_', ' ')} /> : '—'}
                        {s.last_detail && <span className="block text-[11px] text-foreground-muted">{s.last_detail}</span>}</dd></div>
                </dl>
            )}
        </Card>
    );
}

function Telemetry({ d }: { d: Schemas['TenantOnboarding'] }) {
    const t = d.telemetry;
    return (
        <Card>
            <h2 className="font-bold mb-3">What has arrived</h2>
            <dl className="grid grid-cols-2 gap-3 text-sm">
                <div><dt className="text-[11px] text-foreground-muted">Security events (24 h)</dt><dd className="text-xl font-bold">{nf.format(t.alerts_24h)}</dd></div>
                <div><dt className="text-[11px] text-foreground-muted">Last event</dt><dd>{fmt(t.last_alert_at)}</dd></div>
                <div><dt className="text-[11px] text-foreground-muted">Assets in the inventory</dt><dd className="text-xl font-bold">{nf.format(t.assets)}</dd></div>
                <div><dt className="text-[11px] text-foreground-muted">Enrolled for vulnerability scanning</dt><dd className="text-xl font-bold">{nf.format(t.vms_enrolled)}</dd></div>
                <div><dt className="text-[11px] text-foreground-muted">Network senders receiving</dt><dd>{d.sources.receiving} of {d.sources.total}</dd></div>
                <div><dt className="text-[11px] text-foreground-muted">Awaiting NovrSOC verification</dt><dd>{d.sources.pending_verification}</dd></div>
            </dl>
            <p className="text-xs mt-3 flex gap-3"><Link href="/app/assets" className="underline">Asset inventory</Link>
                <Link href="/app/vms/policy" className="underline">Scan enrollment</Link><Link href="/app/alerts" className="underline">Alerts</Link></p>
        </Card>
    );
}

const EMPTY = { name: '', ip: '', protocol: 'udp' as 'udp' | 'tcp', port: 514, ref: '' };

function Devices({ d, canManage, sources, reload }: { d: Schemas['TenantOnboarding']; canManage: boolean; sources: Schemas['LogSourceView'][]; reload: () => void }) {
    const { orgId } = useSession();
    const [guide, setGuide] = useState(GUIDES[0].id);
    const [f, setF] = useState(EMPTY);
    const act = useAction();
    const g = GUIDES.find((x) => x.id === guide) ?? GUIDES[0];
    const target = { address: d.syslog.address ?? '(the NovrSIEM collector address from NovrSOC)', port: d.syslog.port };
    async function register(e: FormEvent) {
        e.preventDefault();
        if (await act.run(() => sourcesApi.create(orgId, { name: f.name.trim(), kind: 'syslog', source_ip: f.ip.trim(), host: '', device_type: g.deviceType,
            vendor: g.vendor, protocol: f.protocol, port: f.port, site_id: null, network: null, authorization_reference: f.ref.trim() || 'Onboarding guide',
            notes: `Registered from the ${g.label} guide`, enabled: true }), 'Registered. NovrSOC verifies the sender before its events are accepted.')) {
            setF(EMPTY); reload();
        }
    }
    return (
        <Card>
            <h2 className="font-bold mb-1">Network devices: send syslog to NovrSIEM</h2>
            <p className="text-xs text-foreground-muted mb-3">Collector: <span className="font-mono">{target.address}</span> · port {target.port} · {d.syslog.protocols.join(' or ').toUpperCase()}</p>
            <Field label="Device"><select className={selectCls} value={guide} onChange={(e) => setGuide(e.target.value)} data-testid="guide-select">
                {GUIDES.map((x) => <option key={x.id} value={x.id}>{x.label}</option>)}</select></Field>
            <ol className="list-decimal ml-5 mt-3 space-y-1 text-sm" data-testid="guide-steps">{g.steps(target).map((s) => <li key={s}>{s}</li>)}</ol>
            <p className="text-xs text-foreground-muted mt-2">{g.verify}</p>
            {canManage && (
                <form onSubmit={register} className="mt-4 flex flex-wrap items-end gap-2" data-testid="register-sender">
                    <Field label="Name"><TextInput required minLength={2} value={f.name} placeholder={`${g.label} at head office`} onChange={(e) => setF({ ...f, name: e.target.value })} /></Field>
                    <Field label="Sender address seen by NovrSOC"><TextInput required value={f.ip} placeholder="public or NAT address" onChange={(e) => setF({ ...f, ip: e.target.value })} /></Field>
                    <Field label="Protocol"><select className={selectCls} value={f.protocol} onChange={(e) => setF({ ...f, protocol: e.target.value as 'udp' | 'tcp' })}>
                        <option value="udp">UDP</option><option value="tcp">TCP</option></select></Field>
                    <Field label="Port"><TextInput type="number" min={1} max={65535} value={f.port} onChange={(e) => setF({ ...f, port: Number(e.target.value) })} /></Field>
                    <Field label="Reference (change ticket)"><TextInput value={f.ref} maxLength={200} onChange={(e) => setF({ ...f, ref: e.target.value })} /></Field>
                    <button className={btn('primary')} type="submit" disabled={act.busy}>Register sender</button>
                </form>
            )}
            {act.notice}
            <div className="mt-4">
                <DataTable rows={sources} rowKey={(s) => s.id} empty="No network device registered yet." columns={[
                    { key: 'n', header: 'Sender', render: (s) => <span><strong>{s.name}</strong><span className="block text-[11px] text-foreground-muted font-mono">{s.source_ip ?? s.host}</span></span> },
                    { key: 'v', header: 'Device', render: (s) => <Tag>{s.vendor || s.device_type}</Tag> },
                    { key: 's', header: 'Status', render: (s) => <StatusPill tone={SOURCE_STATUS[s.status].tone} label={SOURCE_STATUS[s.status].label} /> },
                    { key: 'l', header: 'Last event', render: (s) => <span className="text-xs">{fmt(s.last_event_at)} · {nf.format(s.event_count)}</span> },
                ]} />
            </div>
        </Card>
    );
}
