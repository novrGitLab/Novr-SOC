'use client';

import { Suspense, useState, type FormEvent } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Loader2, LogIn } from 'lucide-react';
import { AuthField } from '@/components/auth/AuthField';
import { BrandMark, brandStyle, usePortal, usePortalTheme } from '@/foundation/portal/portal';
import { btn } from '@/components/features/vms/kit';
import { Card } from '@/components/features/vms/ui';
import { api } from '@/foundation/api/client';
import { ApiError, STATE_TEXT, uiState } from '@/foundation/api/errors';
import { safeNext } from '@/foundation/session/redirect';

function LoginForm() {
    const router = useRouter();
    const params = useSearchParams();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [busy, setBusy] = useState(false);
    const [error, setError] = useState<string | null>(null);

    async function submit(e: FormEvent) {
        e.preventDefault();
        setBusy(true); setError(null);
        try {
            await api.login(email, password);
            router.replace(safeNext(params.get('next')));
        } catch (err) {
            setError(err instanceof ApiError && err.code === 'invalid_credentials' ? 'Invalid email or password.'
                : err instanceof ApiError && err.code === 'use_organization_portal'
                    ? "Your organization has its own NovrSOC portal: sign in at your organization's address."
                    : err instanceof ApiError && err.code === 'portal_not_found' ? 'There is no NovrSOC sign-in at this address.'
                        : STATE_TEXT[uiState(err)].body);
            setBusy(false);
        }
    }

    return (
        <form onSubmit={submit} className="space-y-4" aria-describedby={error ? 'login-error' : undefined}>
            <AuthField label="Email" type="email" name="email" autoComplete="username" required value={email}
                onChange={(e) => setEmail(e.target.value)} error={!!error} data-testid="login-email" />
            <AuthField label="Password" type="password" name="password" autoComplete="current-password" required value={password}
                onChange={(e) => setPassword(e.target.value)} error={!!error} data-testid="login-password" />
            {error && <p id="login-error" role="alert" className="text-xs font-semibold text-red" data-testid="login-error">{error}</p>}
            <button type="submit" disabled={busy} className={`${btn('primary', 'md')} w-full`} data-testid="login-submit">
                {busy ? <Loader2 className="w-4 h-4 motion-safe:animate-spin" aria-hidden /> : <LogIn className="w-4 h-4" aria-hidden />}
                Sign in
            </button>
        </form>
    );
}

export default function LoginPage() {
    const portal = usePortal();
    usePortalTheme(portal);
    const info = portal.status === 'ready' ? portal.portal : null;
    const tenant = info?.kind === 'tenant' ? info : null;
    return (
        <div className="min-h-screen bg-surface flex items-center justify-center p-6" style={brandStyle(info)} data-portal={info?.kind ?? portal.status}>
            <Card className="w-full max-w-sm">
                <div className="flex justify-center mb-6"><BrandMark portal={info} size="lg" /></div>
                <h1 className="text-lg font-black text-foreground mb-1">Sign in</h1>
                <p className="text-xs text-foreground-muted mb-5">
                    {tenant ? `${tenant.branding?.display_name ?? tenant.organization?.name} security portal, operated by NovrSOC.`
                        : portal.status === 'unknown' ? 'There is no NovrSOC sign-in at this address.'
                            : 'NovrSOC staff and client accounts. Sessions are stored in a secure cookie.'}</p>
                {portal.status !== 'unknown' && <Suspense fallback={null}><LoginForm /></Suspense>}
            </Card>
        </div>
    );
}
