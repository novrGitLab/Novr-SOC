'use client';

// CNII endpoints answer 403 without an explicit designation covering the active organization. That is the expected,
// designed state for most users: it is explained, not shown as an error.
import type { ReactNode } from 'react';
import { Lock } from 'lucide-react';
import { EmptyState } from '@/components/features/vms/kit';
import { Card } from '@/components/features/vms/ui';
import { ApiError } from '@/foundation/api/errors';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';

export function CniiGate<T>({ data, error, reload, children }: { data: T | undefined; error: unknown; reload: () => void; children: (d: T) => ReactNode }) {
    if (error instanceof ApiError && error.status === 403) {
        return (
            <Card><EmptyState icon={Lock} title="CNII monitoring needs a designation"
                body="Your role's permission is not enough: a platform administrator must grant you an explicit, expiring CNII designation covering this organization and its sectors. Every access attempt is audited." /></Card>
        );
    }
    if (error) return <ApiErrorState error={error} onRetry={reload} />;
    if (data === undefined) return <LoadingState label="Loading CNII monitoring" />;
    return <>{children(data)}</>;
}
