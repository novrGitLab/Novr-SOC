'use client';

// Accepting an invitation to an organization's NovrSOC portal. The token arrives in the link's fragment (#...), which
// browsers never send to a server; it is read here, removed from the address bar, and posted in a request body only.
import Link from 'next/link';
import { useEffect, useState, type FormEvent } from 'react';
import { CheckCircle2, Loader2, UserPlus } from 'lucide-react';
import { AuthField } from '@/components/auth/AuthField';
import { btn } from '@/components/features/vms/kit';
import { Card } from '@/components/features/vms/ui';
import { request, type Schemas } from '@/foundation/api/client';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { BrandMark, brandStyle, usePortal, usePortalTheme } from '@/foundation/portal/portal';

type Preview = Schemas['InvitationPreview'];
const ROLE: Record<string, string> = { soc_manager: 'Organization administrator', analyst: 'Security analyst', executive: 'Executive (read only)',
                                       portal_user: 'Portal user' };
const STATE: Record<string, string> = { accepted: 'This invitation has already been used. Sign in instead.',
                                        revoked: 'This invitation was withdrawn. Ask your administrator for a new one.',
                                        expired: 'This invitation has expired. Ask your administrator for a new one.',
                                        organization_inactive: 'This organization is not active.' };

export default function InvitePage() {
    const portal = usePortal();
    usePortalTheme(portal);
    const info = portal.status === 'ready' ? portal.portal : null;
    const [token, setToken] = useState<string | null>(null);
    const [preview, setPreview] = useState<Preview | null>(null);
    const [error, setError] = useState<string | null>(null);
    const [form, setForm] = useState({ name: '', password: '', confirm: '' });
    const [busy, setBusy] = useState(false);
    const [done, setDone] = useState<Schemas['InvitationAccepted'] | null>(null);

    useEffect(() => {
        const t = window.location.hash.slice(1);
        try { window.history.replaceState(null, '', window.location.pathname); } catch { /* ignore */ }
        void Promise.resolve().then(async () => {
            if (!t) { setError('Open the invitation link you received; it contains your invitation.'); return; }
            setToken(t);
            try {
                setPreview(await request<Preview>('/api/v1/invitations/preview', { method: 'POST', body: { token: t } satisfies Schemas['InvitationToken'] }));
            } catch (e) {
                setError(e instanceof ApiError && e.status === 404 ? 'This invitation is not valid at this address.' : STATE_TEXT[uiState(e)].body);
            }
        });
    }, []);

    async function accept(e: FormEvent) {
        e.preventDefault();
        if (form.password !== form.confirm) { setError('The two passwords differ.'); return; }
        setBusy(true); setError(null);
        try {
            setDone(await request<Schemas['InvitationAccepted']>('/api/v1/invitations/accept', { method: 'POST',
                body: { token: token ?? '', display_name: form.name.trim(), password: form.password } satisfies Schemas['InvitationAccept'] }));
        } catch (err) {
            setError(err instanceof ApiError && err.status === 422 ? 'Use a password of at least 12 characters that differs from your email.'
                : err instanceof ApiError && err.code === 'account_exists' ? 'An account with this email already exists. Ask your administrator.'
                    : err instanceof ApiError && err.status === 404 ? 'This invitation is no longer valid.' : STATE_TEXT[uiState(err)].body);
        } finally { setBusy(false); }
    }

    return (
        <div className="min-h-screen bg-surface flex items-center justify-center p-6" style={brandStyle(info)}>
            <Card className="w-full max-w-sm">
                <div className="flex justify-center mb-6"><BrandMark portal={info} size="lg" /></div>
                {done ? (
                    <div className="space-y-3 text-sm" data-testid="invite-done">
                        <p className="flex items-center gap-2 font-semibold"><CheckCircle2 className="w-4 h-4 text-green" aria-hidden />Your account is ready.</p>
                        <p className="text-foreground-muted">Sign in with {done.email}.</p>
                        <Link href="/login" className={`${btn('primary', 'md')} w-full`}>Sign in</Link>
                    </div>
                ) : preview && preview.state !== 'open' ? (
                    <p className="text-sm" role="alert">{STATE[preview.state]}</p>
                ) : preview ? (
                    <form onSubmit={accept} className="space-y-4" data-testid="invite-form">
                        <h1 className="text-lg font-black">Join {preview.organization}</h1>
                        <p className="text-xs text-foreground-muted">{preview.email} · {ROLE[preview.role ?? ''] ?? preview.role}</p>
                        <AuthField label="Your name" name="name" autoComplete="name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
                        <AuthField label="Password (12 characters or more)" type="password" name="password" autoComplete="new-password" required minLength={12}
                            value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
                        <AuthField label="Repeat the password" type="password" name="confirm" autoComplete="new-password" required minLength={12}
                            value={form.confirm} onChange={(e) => setForm({ ...form, confirm: e.target.value })} />
                        {error && <p role="alert" className="text-xs font-semibold text-red">{error}</p>}
                        <button type="submit" disabled={busy} className={`${btn('primary', 'md')} w-full`}>
                            {busy ? <Loader2 className="w-4 h-4 motion-safe:animate-spin" aria-hidden /> : <UserPlus className="w-4 h-4" aria-hidden />}
                            Create my account</button>
                    </form>
                ) : (
                    <p className="text-sm" role={error ? 'alert' : undefined}>{error ?? 'Checking your invitation…'}</p>
                )}
            </Card>
        </div>
    );
}
