'use client';

import Link from 'next/link';
import { useCallback } from 'react';
import { useParams } from 'next/navigation';
import { ArrowLeft, MapPin } from 'lucide-react';
import { PageHeader, btn } from '@/components/features/vms/kit';
import { Card } from '@/components/features/vms/ui';
import { api } from '@/foundation/api/client';
import { useSession } from '@/foundation/session/SessionProvider';
import { ApiErrorState, LoadingState } from '@/foundation/ui/states';
import { useResource } from '@/foundation/ui/useResource';

export default function SiteDetailPage() {
    const { id } = useParams<{ id: string }>();
    const { orgId } = useSession();
    const { data: site, error } = useResource(useCallback(() => api.getSite(orgId, id), [orgId, id]));

    return (
        <>
            <PageHeader title={site?.name ?? 'Site'} icon={MapPin} actions={<Link href="/app/sites" className={btn('secondary')}><ArrowLeft className="w-3.5 h-3.5" aria-hidden /> All sites</Link>} />
            {error ? <div data-testid="site-error"><ApiErrorState error={error} /></div>
                : !site ? <LoadingState label="Loading site" />
                : (
                    <Card>
                        <dl className="grid grid-cols-[10rem_1fr] gap-y-2 text-sm" data-testid="site-detail">
                            <dt className="text-foreground-muted">Name</dt><dd className="font-semibold">{site.name}</dd>
                            <dt className="text-foreground-muted">Networks</dt><dd>{site.network_cidrs.join(', ') || '—'}</dd>
                            <dt className="text-foreground-muted">Site id</dt><dd className="font-mono text-xs">{site.id}</dd>
                            <dt className="text-foreground-muted">Created</dt><dd>{new Date(site.created_at).toLocaleString('en-GB')}</dd>
                        </dl>
                    </Card>
                )}
        </>
    );
}
