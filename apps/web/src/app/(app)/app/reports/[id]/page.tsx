'use client';

import Link from 'next/link';
import { useCallback, useState } from 'react';
import { useParams } from 'next/navigation';
import { ArrowLeft, Download, FileBarChart } from 'lucide-react';
import { Notice, PageHeader, btn, type Msg } from '@/components/features/vms/kit';
import { Card, SectionTitle, StatusPill } from '@/components/features/vms/ui';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { reportsApi } from '../api';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { REPORT_LABEL, SECTION_STATE, fmtDateTime } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';

/** Saves the file exactly as served (no BOM), so its SHA-256 matches the one shown. */
function saveExact(filename: string, text: string, type: string) {
    const url = URL.createObjectURL(new Blob([text], { type }));
    const a = Object.assign(document.createElement('a'), { href: url, download: filename });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}

/** Renders one section's figures: scalars as rows, objects as nested rows, lists inline. */
function Figures({ data }: { data: Record<string, unknown> }) {
    const entries = Object.entries(data);
    if (!entries.length) return null;
    return (
        <dl className="mt-2 grid grid-cols-[minmax(8rem,12rem)_1fr] gap-y-1.5 text-sm">
            {entries.map(([k, v]) => (
                <div key={k} className="contents">
                    <dt className="text-foreground-muted">{k.replace(/_/g, ' ')}</dt>
                    <dd className="min-w-0 break-words">
                        {v !== null && typeof v === 'object' && !Array.isArray(v)
                            ? Object.keys(v as object).length === 0 ? '—'
                                : <span className="flex flex-wrap gap-x-3 gap-y-0.5">{Object.entries(v as Record<string, unknown>).map(([kk, vv]) => <span key={kk}><span className="text-foreground-muted">{kk.replace(/_/g, ' ')}:</span> <strong className="tabular-nums">{String(vv)}</strong></span>)}</span>
                            : Array.isArray(v) ? (v.length ? v.join(', ') : '—')
                            : <strong className="tabular-nums">{String(v)}</strong>}
                    </dd>
                </div>
            ))}
        </dl>
    );
}

export default function ReportDetailPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId } = useSession();
    const { data: r, error } = useResource(useCallback(() => reportsApi.detail(orgId, id), [orgId, id]));
    const [msg, setMsg] = useState<Msg>(null);

    async function download() {
        setMsg(null);
        try { const f = await reportsApi.download(orgId, id); saveExact(f.filename, f.text, f.type); }
        catch (e) { setMsg({ ok: false, text: (e instanceof ApiError && e.message) || STATE_TEXT[uiState(e)].body }); }
    }

    return (
        <>
            <PageHeader title={r ? (REPORT_LABEL[r.type] ?? r.type.replace(/_/g, ' ').replace(/^./, (c) => c.toUpperCase())) : 'Report'} icon={FileBarChart}
                meta={r && <><span>{new Date(r.period_start).toLocaleDateString('en-GB')} – {new Date(r.period_end).toLocaleDateString('en-GB')}</span><span>Requested {fmtDateTime(r.created_at)}</span></>}
                actions={<>
                    {r?.status === 'ready' && <button className={btn('primary')} onClick={() => void download()} data-testid="report-download"><Download className="w-3.5 h-3.5" aria-hidden /> Download {r.format.toUpperCase()}</button>}
                    {r?.status === 'ready' && <button className={btn('secondary')} onClick={() => window.print()} data-testid="report-print">Print / save as PDF</button>}
                    <Link href="/app/reports" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> All reports</Link>
                </>} />
            <Notice msg={msg} />
            {error ? <div data-testid="report-error"><ApiErrorState error={error} /></div>
                : !r ? <LoadingState label="Loading report" />
                : (
                    <>
                        {r.status === 'failed' && <Card><p className="text-sm font-bold">This report could not be generated</p><p className="text-xs text-foreground-muted mt-1">{r.failure_reason || 'No reason was recorded.'}</p></Card>}
                        <div className="grid gap-4 md:grid-cols-2" data-testid="report-sections">
                            {r.sections.map((s) => {
                                const st = SECTION_STATE[s.state] ?? { label: s.state, tone: 'neutral' as const };
                                return (
                                    <Card key={s.key} aria-label={s.title}>
                                        <div data-section={s.key} data-state={s.state}>
                                            <SectionTitle title={s.title} level={3} action={<StatusPill tone={st.tone} label={st.label} />} />
                                            {s.note && <p className="text-[11px] text-foreground-muted mt-1">{s.note}</p>}
                                            <Figures data={s.data as Record<string, unknown>} />
                                        </div>
                                    </Card>
                                );
                            })}
                        </div>
                        {r.sha256 && <p className="text-[11px] text-foreground-muted break-all">SHA-256 of the stored report: <span className="font-mono">{r.sha256}</span>. The API verifies it on every download.</p>}
                    </>
                )}
        </>
    );
}
