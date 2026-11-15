'use client';

import type { ReactNode } from 'react';
import { SessionProvider } from '@/foundation/session/SessionProvider';
import { AppShell } from '@/foundation/shell/AppShell';
import { ApiErrorState, FullPage, LoadingState } from '@/foundation/ui/states';

export default function AuthenticatedLayout({ children }: { children: ReactNode }) {
    return (
        <SessionProvider
            loading={<FullPage><LoadingState label="Checking your session" /></FullPage>}
            failed={(state, retry) => <FullPage><ApiErrorState state={state} onRetry={retry} /></FullPage>}>
            <AppShell>{children}</AppShell>
        </SessionProvider>
    );
}
