'use client';

// Shared loading / error / empty states for V2 pages, built on the extracted VMS design kit.
import { Loader2, ShieldAlert, WifiOff } from 'lucide-react';
import { EmptyState, ErrorState, btn } from '@/components/features/vms/kit';
import { Card, Skeleton } from '@/components/features/vms/ui';
import { STATE_TEXT, uiState, type UiState } from '@/foundation/api/errors';

export function LoadingState({ label = 'Loading' }: { label?: string }) {
    return (
        <Card aria-busy aria-label={label}>
            <div className="flex items-center gap-2 text-xs text-foreground-muted mb-4" role="status">
                <Loader2 className="w-4 h-4 motion-safe:animate-spin" aria-hidden /> {label}…
            </div>
            <Skeleton className="h-4 w-2/3 mb-2" />
            <Skeleton className="h-4 w-1/2 mb-2" />
            <Skeleton className="h-4 w-3/5" />
        </Card>
    );
}

const STATUS: Partial<Record<UiState, number>> = { forbidden: 403, not_ready: 503 };

export function ApiErrorState({ error, state, onRetry }: { error?: unknown; state?: UiState; onRetry?: () => void }) {
    const s = state ?? uiState(error);
    const text = STATE_TEXT[s];
    if (s === 'backend_unreachable') {
        return (
            <Card>
                <EmptyState icon={WifiOff} title={text.title} body={text.body}
                    action={onRetry && <button className={btn('secondary')} onClick={onRetry}>Retry</button>} />
            </Card>
        );
    }
    if (s === 'not_found') return <Card><EmptyState icon={ShieldAlert} title={text.title} body={text.body} /></Card>;
    return <ErrorState error={text.body} status={STATUS[s]} onRetry={onRetry} />;
}

export function FullPage({ children }: { children: React.ReactNode }) {
    return <div className="min-h-screen bg-surface flex items-center justify-center p-6"><div className="w-full max-w-lg">{children}</div></div>;
}
