'use client';

// NovrChat: questions answered from the active organization's own records through read-only, permission-checked tools.
// Every answer lists the tools it used (and those your role may not use) and cites the records behind each line. When
// NHAI is configured, an AI-drafted prose answer over the same citations follows, labelled as a draft for review.
import Link from 'next/link';
import { useCallback, useEffect, useRef, useState, type FormEvent } from 'react';
import { MessageSquare, Plus, Send, Trash2 } from 'lucide-react';
import { EmptyState, PageHeader, Tag, btn } from '@/components/features/vms/kit';
import { Card, SectionTitle } from '@/components/features/vms/ui';
import type { Schemas } from '@/foundation/api/client';
import { chatApi } from '@/foundation/api/modules';
import { useSession } from '@/foundation/session/SessionProvider';
import { fmt } from '@/foundation/ui/pilot';
import { StateTag, useAction } from '@/foundation/ui/module';
import { inputCls } from '@/foundation/ui/sources';
import { useResource } from '@/foundation/ui/useResource';
import { NhaiResult } from '../insights/AlertIntelPanel';

type Msg = Schemas['ChatMessageView'];
type Conv = Schemas['ChatConversationView'];
const SUGGESTIONS = ['What critical alerts came in today?', 'Which cases are breaching SLA?', 'What is our security posture?',
    'Which assets have open critical vulnerabilities?', 'Show pending SOAR approvals', 'Generate an executive report'];

function Message({ m }: { m: Msg }) {
    const [nhai, setNhai] = useState(m.nhai ?? null);
    if (m.role === 'user') return <div className="flex justify-end"><p className="max-w-[80%] rounded-2xl bg-purple text-white px-3 py-2 text-sm whitespace-pre-wrap">{m.content}</p></div>;
    return (
        <div className="max-w-[92%] rounded-2xl border border-border bg-card px-3 py-2 text-sm space-y-2" data-testid="chat-answer" data-state={m.state}>
            <p className="whitespace-pre-wrap">{m.content}</p>
            {m.tools.length > 0 && <p className="flex flex-wrap gap-1 text-[11px]">{m.tools.map((t) => <span key={t.tool} title={t.detail}><StateTag state={t.state === 'ok' ? 'ok' : t.state === 'not_permitted' ? 'refused' : 'unknown'} label={`${t.tool.replace('_', ' ')}: ${t.state.replace('_', ' ')}`} /></span>)}</p>}
            {m.citations.length > 0 && (
                <details className="text-xs"><summary className="cursor-pointer text-purple">Sources ({m.citations.length})</summary>
                    <ol className="mt-1 space-y-1">{m.citations.map((c) => <li key={c.citation_id}><Tag>{c.citation_id}</Tag> {c.href ? <Link className="underline" href={c.href}>{c.label}</Link> : c.label}
                        <span className="block text-foreground-muted">{c.excerpt}</span></li>)}</ol></details>
            )}
            {nhai && <div className="border-t border-border pt-2"><p className="text-[11px] font-bold uppercase tracking-wide text-foreground-muted mb-1">NHAI draft over the same sources</p><NhaiResult job={nhai} onChange={setNhai} /></div>}
            <p className="text-[10px] text-foreground-muted">{fmt(m.created_at)}</p>
        </div>
    );
}

export default function ChatPage() {
    const { orgId } = useSession();
    const list = useResource(useCallback(() => chatApi.list(orgId), [orgId]));
    const [conv, setConv] = useState<Conv | null>(null);
    const [q, setQ] = useState('');
    const act = useAction();
    const end = useRef<HTMLDivElement>(null);
    useEffect(() => { end.current?.scrollIntoView({ block: 'end' }); }, [conv?.messages.length]);
    const pending = conv?.messages.some((m) => m.nhai && (m.nhai.status === 'queued' || m.nhai.status === 'running'));
    useEffect(() => {
        if (!pending || !conv) return;
        const t = setInterval(() => { void chatApi.get(orgId, conv.id).then(setConv).catch(() => undefined); }, 6000);
        return () => clearInterval(t);
    }, [pending, conv, orgId]);

    async function ask(text: string, e?: FormEvent) {
        e?.preventDefault();
        if (!text.trim()) return;
        let c = conv;
        if (!c) { c = (await act.run(() => chatApi.start(orgId))) ?? null; if (!c) return; }
        const r = await act.run(() => chatApi.ask(orgId, c!.id, text.trim()));
        if (r) { setQ(''); setConv({ ...c, messages: [...c.messages, r.question, r.answer] }); list.reload(); }
    }

    return (
        <>
            <PageHeader title="NovrChat" icon={MessageSquare}
                description="Ask about your organization's alerts, cases, SLA, assets, vulnerabilities, posture, threat intelligence, SOAR and reports. Answers are read-only, cite their records and say what your role cannot see. NovrChat never acts."
                actions={<button className={btn('secondary')} onClick={() => setConv(null)}><Plus className="w-3.5 h-3.5" aria-hidden /> New conversation</button>} />
            {act.notice}
            <div className="grid grid-cols-1 lg:grid-cols-[16rem_1fr] gap-4">
                <Card>
                    <SectionTitle title="Conversations" />
                    <ul className="mt-2 space-y-1 text-sm">
                        {(list.data?.items ?? []).length === 0 && <li className="text-xs text-foreground-muted">None yet.</li>}
                        {(list.data?.items ?? []).map((c) => (
                            <li key={c.id} className="flex items-center gap-1">
                                <button className={`flex-1 text-left truncate rounded px-2 py-1 ${conv?.id === c.id ? 'bg-purple-tint text-purple' : 'hover:bg-card-muted'}`}
                                    onClick={() => void chatApi.get(orgId, c.id).then(setConv)}>{c.title}</button>
                                <button aria-label="Delete conversation" className={btn('ghost')} onClick={() => void act.run(() => chatApi.remove(orgId, c.id)).then(() => { if (conv?.id === c.id) setConv(null); list.reload(); })}><Trash2 className="w-3 h-3" aria-hidden /></button>
                            </li>
                        ))}
                    </ul>
                    <p className="mt-3 text-[11px] text-foreground-muted">Conversations are private to you. Every question and answer is audited and listed in SOAR AI activity.</p>
                </Card>
                <Card className="flex flex-col min-h-[28rem]">
                    <div className="flex-1 space-y-3 overflow-y-auto max-h-[60vh] pr-1" data-testid="chat-thread">
                        {!conv || conv.messages.length === 0 ? (
                            <EmptyState title="Ask a question" body={<span className="flex flex-wrap gap-2 justify-center mt-2">{SUGGESTIONS.map((s) => (
                                <button key={s} className={btn('secondary')} onClick={() => void ask(s)}>{s}</button>))}</span>} />
                        ) : conv.messages.map((m) => <Message key={m.id} m={m} />)}
                        <div ref={end} />
                    </div>
                    <form onSubmit={(e) => void ask(q, e)} className="mt-3 flex gap-2" data-testid="chat-form">
                        <label className="sr-only" htmlFor="chat-q">Question</label>
                        <input id="chat-q" className={`${inputCls} flex-1`} value={q} maxLength={2000} onChange={(e) => setQ(e.target.value)} placeholder="Ask about alerts, cases, assets, CVEs, posture…" data-testid="chat-input" />
                        <button className={btn('primary', 'md')} disabled={act.busy || !q.trim()} data-testid="chat-send"><Send className="w-3.5 h-3.5" aria-hidden /> Ask</button>
                    </form>
                </Card>
            </div>
        </>
    );
}
